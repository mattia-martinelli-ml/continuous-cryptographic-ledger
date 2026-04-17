#!/usr/bin/env node
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { Command } from 'commander';
import { DatabaseClient } from './db.js';
import { KeyManager, verifySignature } from './signer.js';
import { verifyMerkleProof, hashLeaf } from './merkle.js';
import { startServer } from './server.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const program = new Command();
program.name('merkle-proof').description('Merkle Proof CLI per compliance data integrity');

const resolvePath = (filePath) => path.resolve(process.cwd(), filePath);
const hourStartFromIso = (value) => {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    throw new Error('Formato ISO 8601 non valido per hour-start');
  }
  date.setUTCMinutes(0, 0, 0);
  return date;
};

program
  .command('init-db')
  .requiredOption('--dsn <dsn>', 'PostgreSQL DSN')
  .option('--key-dir <dir>', 'Cartella per chiavi ed25519', 'keys')
  .action(async (options) => {
    const keyDir = resolvePath(options.keyDir);
    fs.mkdirSync(keyDir, { recursive: true });
    const keyManager = new KeyManager(path.join(keyDir, 'private_key.pem'), path.join(keyDir, 'public_key.pem'));
    const client = new DatabaseClient(options.dsn, keyManager);
    const setupPath = path.resolve(__dirname, '..', 'migrations', 'setup.sql');
    const setupSql = fs.readFileSync(setupPath, 'utf8');
    await client.initializeSchema(setupSql);
    console.log(`Database inizializzato. Chiave pubblica: ${keyManager.publicKeyFingerprint()}`);
  });

program
  .command('ingest-events-batch')
  .requiredOption('--dsn <dsn>', 'PostgreSQL DSN')
  .requiredOption('--payload-file <file>', 'JSON file containing array of events (each with payload and optional occurredAt)')
  .option('--key-dir <dir>', 'Cartella per chiavi', 'keys')
  .action(async (options) => {
    const keyManager = new KeyManager(path.join(resolvePath(options.keyDir), 'private_key.pem'), path.join(resolvePath(options.keyDir), 'public_key.pem'));
    const client = new DatabaseClient(options.dsn, keyManager);
    const filePath = resolvePath(options.payloadFile);
    const fileContent = JSON.parse(fs.readFileSync(filePath, 'utf8'));
    
    if (!Array.isArray(fileContent)) {
      throw new Error('Il file deve contenere un array di eventi');
    }
    
    const events = fileContent.map(item => ({
      payload: item.payload,
      occurredAt: item.occurredAt ? new Date(item.occurredAt) : new Date()
    }));
    
    const eventIds = await client.insertEventsBatch(events);
    console.log(`Inseriti ${eventIds.length} eventi. IDs: ${eventIds.join(', ')}`);
  });

program
  .command('ingest-event')
  .requiredOption('--dsn <dsn>', 'PostgreSQL DSN')
  .requiredOption('--payload <payload>', 'JSON payload dell\'evento')
  .option('--occurred-at <ts>', 'Timestamp ISO 8601 dell\'evento')
  .option('--key-dir <dir>', 'Cartella per chiavi', 'keys')
  .action(async (options) => {
    const keyManager = new KeyManager(path.join(resolvePath(options.keyDir), 'private_key.pem'), path.join(resolvePath(options.keyDir), 'public_key.pem'));
    const client = new DatabaseClient(options.dsn, keyManager);
    const payload = JSON.parse(options.payload);
    const eventTime = options.occurredAt ? new Date(options.occurredAt) : new Date();
    if (Number.isNaN(eventTime.getTime())) {
      throw new Error('Timestamp non valido');
    }
    const eventId = await client.insertEvent(payload, eventTime);
    console.log(`Evento inserito con event_id=${eventId} alle ${eventTime.toISOString()}`);
  });

program
  .command('finalize-hour')
  .requiredOption('--dsn <dsn>', 'PostgreSQL DSN')
  .requiredOption('--hour-start <hour>', 'Ora di inizio blocco ISO 8601 (UTC) a 0 minuti')
  .option('--key-dir <dir>', 'Cartella per chiavi', 'keys')
  .action(async (options) => {
    const keyManager = new KeyManager(path.join(resolvePath(options.keyDir), 'private_key.pem'), path.join(resolvePath(options.keyDir), 'public_key.pem'));
    const client = new DatabaseClient(options.dsn, keyManager);
    const hour = hourStartFromIso(options.hourStart);
    const root = await client.computeAndStoreRoot(hour);
    console.log(`Root orario salvato per ${hour.toISOString()}`);
    console.log(`root_hash=${root.toString('hex')}`);
  });

program
  .command('prove-event')
  .requiredOption('--dsn <dsn>', 'PostgreSQL DSN')
  .requiredOption('--event-id <id>', 'ID dell\'evento')
  .requiredOption('--hour-start <hour>', 'Ora di inizio blocco ISO 8601 (UTC)')
  .option('--key-dir <dir>', 'Cartella per chiavi', 'keys')
  .action(async (options) => {
    const keyManager = new KeyManager(path.join(resolvePath(options.keyDir), 'private_key.pem'), path.join(resolvePath(options.keyDir), 'public_key.pem'));
    const client = new DatabaseClient(options.dsn, keyManager);
    const proof = await client.generateInclusionProof(Number(options.eventId), hourStartFromIso(options.hourStart));
    console.log(JSON.stringify(proof, null, 2));
  });

program
  .command('serve')
  .requiredOption('--dsn <dsn>', 'PostgreSQL DSN')
  .option('--port <port>', 'Porta per il server API', '3000')
  .option('--key-dir <dir>', 'Cartella per chiavi', 'keys')
  .action(async (options) => {
    const keyManager = new KeyManager(path.join(resolvePath(options.keyDir), 'private_key.pem'), path.join(resolvePath(options.keyDir), 'public_key.pem'));
    const client = new DatabaseClient(options.dsn, keyManager);
    startServer(client, Number(options.port));
  });

program
  .command('verify-chain')
  .requiredOption('--dsn <dsn>', 'PostgreSQL DSN')
  .option('--start <date>', 'Start date for verification (ISO 8601)')
  .option('--end <date>', 'End date for verification (ISO 8601)')
  .option('--key-dir <dir>', 'Cartella per chiavi', 'keys')
  .action(async (options) => {
    const keyManager = new KeyManager(path.join(resolvePath(options.keyDir), 'private_key.pem'), path.join(resolvePath(options.keyDir), 'public_key.pem'));
    const client = new DatabaseClient(options.dsn, keyManager);
    const startTime = options.start ? new Date(options.start) : null;
    const endTime = options.end ? new Date(options.end) : null;
    const result = await client.verifyChainIntegrity(startTime, endTime);
    console.log(`Chain valida: ${result.valid}`);
    console.log(`Ore verificate: ${result.checkedHours}`);
    if (result.errors.length > 0) {
      console.log('Errori:');
      result.errors.forEach(err => console.log(`  - ${err}`));
    }
    if (result.cumulativeHash) {
      console.log(`Hash cumulativo: ${result.cumulativeHash}`);
    }
  });

program
  .command('chain-stats')
  .requiredOption('--dsn <dsn>', 'PostgreSQL DSN')
  .action(async (options) => {
    const keyManager = new KeyManager(path.join(resolvePath(options.keyDir || 'keys'), 'private_key.pem'), path.join(resolvePath(options.keyDir || 'keys'), 'public_key.pem'));
    const client = new DatabaseClient(options.dsn, keyManager);
    const stats = await client.getChainStats();
    console.log(`Ore totali: ${stats.totalHours}`);
    console.log(`Eventi totali: ${stats.totalEvents}`);
    if (stats.firstHour) {
      console.log(`Prima ora: ${stats.firstHour.toISOString()}`);
    }
    if (stats.lastHour) {
      console.log(`Ultima ora: ${stats.lastHour.toISOString()}`);
    }
  });

program
  .command('verify-event')
  .requiredOption('--dsn <dsn>', 'PostgreSQL DSN')
  .requiredOption('--event-id <id>', 'ID dell\'evento da verificare')
  .action(async (options) => {
    const keyManager = new KeyManager(path.join(resolvePath(options.keyDir || 'keys'), 'private_key.pem'), path.join(resolvePath(options.keyDir || 'keys'), 'public_key.pem'));
    const client = new DatabaseClient(options.dsn, keyManager);
    const result = await client.verifyEventIntegrity(Number(options.eventId));
    console.log(`Evento valido: ${result.valid}`);
    if (result.errors.length > 0) {
      console.log('Errori:');
      result.errors.forEach(err => console.log(`  - ${err}`));
    }
  });

program
  .command('verify-proof')
  .requiredOption('--event-hash <hash>', 'Hash dell\'evento in esadecimale')
  .requiredOption('--proof-file <file>', 'File JSON con la prova di inclusione')
  .option('--public-key <file>', 'Chiave pubblica per verificare la firma', 'keys/public_key.pem')
  .action(async (options) => {
    const proofPath = resolvePath(options.proofFile);
    if (!fs.existsSync(proofPath)) {
      throw new Error('File di prova non trovato');
    }
    const payload = JSON.parse(fs.readFileSync(proofPath, 'utf8'));
    const eventBytes = Buffer.from(options.eventHash, 'hex');
    const proof = payload.proof.map((item) => ({ sibling: Buffer.from(item.sibling, 'hex'), position: item.position }));
    const root = Buffer.from(payload.root_hash, 'hex');
    const signature = Buffer.from(payload.signature, 'hex');
    // event_hash is already a leaf hash (hashed with 0x00 prefix), don't hash again
    const proofOk = verifyMerkleProof(eventBytes, proof, root);
    const signatureOk = verifySignature(resolvePath(options.publicKey), root, signature, payload.hour_start);
    console.log(`Merkle proof valida: ${proofOk}`);
    console.log(`Firma del root valida: ${signatureOk}`);
  });

program.parseAsync(process.argv).catch((error) => {
  console.error(error.message || error);
  process.exit(1);
});
