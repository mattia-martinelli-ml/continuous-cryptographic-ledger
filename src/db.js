import { Pool } from 'pg';
import { buildMerkleRoot, stableSerialize, sha256Hash, hashLeaf, generateInclusionProof as computeInclusionProof } from './merkle.js';
import { TSAClient } from './tsa.js';

const normalizeHourStart = (hourStart) => {
  const date = new Date(hourStart);
  if (Number.isNaN(date.getTime())) {
    throw new Error('Formato di data non valido');
  }
  const normalized = new Date(date.toISOString());
  normalized.setUTCMinutes(0, 0, 0);
  return normalized;
};

export class DatabaseClient {
  constructor(dsn, signer) {
    this.pool = new Pool({ connectionString: dsn });
    this.signer = signer;
    this.tsa = new TSAClient();
  }

  async initializeSchema(setupSql) {
    await this.pool.query(setupSql);
  }

  async insertEvent(payload, occurredAt) {
    const serialized = stableSerialize(payload);
    const eventHash = hashLeaf(serialized);
    const result = await this.pool.query(
      'INSERT INTO compliance_event (occurred_at, payload, event_hash) VALUES ($1, $2, $3) RETURNING event_id',
      [occurredAt.toISOString(), payload, eventHash]
    );
    return result.rows[0].event_id;
  }

  async getEventsForHour(hourStart) {
    const start = normalizeHourStart(hourStart);
    const end = new Date(start.getTime() + 60 * 60 * 1000);
    const result = await this.pool.query(
      'SELECT event_id, occurred_at, payload, event_hash FROM compliance_event WHERE occurred_at >= $1 AND occurred_at < $2 ORDER BY occurred_at',
      [start.toISOString(), end.toISOString()]
    );
    return result.rows.map((row) => ({
      event_id: row.event_id,
      occurred_at: new Date(row.occurred_at),
      payload: row.payload,
      event_hash: row.event_hash,
    }));
  }

  async computeAndStoreRoot(hourStart) {
    const start = normalizeHourStart(hourStart);
    const events = await this.getEventsForHour(start);
    const leafHashes = events.map((event) => event.event_hash);
    const root = buildMerkleRoot(leafHashes);
    const signature = this.signer.sign(root, start.toISOString());

    // REQ-3.1: External Anchoring with TSA
    const tsaProof = await this.tsa.timestamp(root);

    await this.pool.query(
      'INSERT INTO hourly_root (hour_start, root_hash, signature, tsa_proof) VALUES ($1, $2, $3, $4)',
      [start.toISOString(), root, signature, tsa_proof]
    );
    return root;
  }

  async getHourlyRoot(hourStart) {
    const start = normalizeHourStart(hourStart);
    const result = await this.pool.query(
      'SELECT hour_start, root_hash, signature, signed_at FROM hourly_root WHERE hour_start = $1',
      [start.toISOString()]
    );
    return result.rows[0] || null;
  }

  async generateInclusionProof(eventId, hourStart) {
    const start = normalizeHourStart(hourStart);
    const events = await this.getEventsForHour(start);
    const index = events.findIndex((event) => String(event.event_id) === String(eventId));
    if (index === -1) {
      throw new Error(`Event ${eventId} non trovato nell'ora ${start.toISOString()}`);
    }
    const leaves = events.map((event) => event.event_hash);
    const proof = computeInclusionProof(index, leaves);
    const rootRecord = await this.getHourlyRoot(start);
    if (!rootRecord) {
      throw new Error(`Root orario non trovato per ${start.toISOString()}`);
    }
    return {
      event_id: eventId,
      hour_start: start.toISOString(),
      event_hash: leaves[index].toString('hex'),
      root_hash: rootRecord.root_hash.toString('hex'),
      signature: rootRecord.signature.toString('hex'),
      proof: proof.map(({ sibling, position }) => ({ sibling: sibling.toString('hex'), position })),
    };
  }

}
