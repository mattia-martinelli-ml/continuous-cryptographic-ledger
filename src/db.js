import { Pool } from 'pg';
import { buildMerkleRoot, stableSerialize, sha256Hash } from './merkle.js';

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
  }

  async initializeSchema(setupSql) {
    await this.pool.query(setupSql);
  }

  async insertEvent(payload, occurredAt) {
    const serialized = stableSerialize(payload);
    const eventHash = sha256Hash(serialized);
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
    const signature = this.signer.sign(root);
    await this.pool.query(
      'INSERT INTO hourly_root (hour_start, root_hash, signature) VALUES ($1, $2, $3) ON CONFLICT (hour_start) DO UPDATE SET root_hash = EXCLUDED.root_hash, signature = EXCLUDED.signature, signed_at = now()',
      [start.toISOString(), root, signature]
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
    const index = events.findIndex((event) => event.event_id === eventId);
    if (index === -1) {
      throw new Error(`Event ${eventId} non trovato nell'ora ${start.toISOString()}`);
    }
    const leaves = events.map((event) => event.event_hash);
    const proof = DatabaseClient.buildInclusionProof(index, leaves);
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

  static buildInclusionProof(index, leaves) {
    if (leaves.length === 0) {
      throw new Error('Nessuna foglia disponibile per l\'ora richiesta');
    }
    const normalizedLeaves = leaves.map((leaf) => (Buffer.isBuffer(leaf) ? leaf : Buffer.from(leaf)));
    const proof = [];
    let layer = normalizedLeaves;
    let idx = index;

    while (layer.length > 1) {
      const nextLayer = [];
      for (let i = 0; i < layer.length; i += 2) {
        const left = layer[i];
        const right = i + 1 < layer.length ? layer[i + 1] : layer[i];
        if (i === idx || i + 1 === idx) {
          if (i === idx) {
            proof.push({ sibling: right, position: 'right' });
          } else {
            proof.push({ sibling: left, position: 'left' });
          }
          idx = nextLayer.length;
        }
        nextLayer.push(sha256Hash(Buffer.concat([left, right])));
      }
      layer = nextLayer;
    }

    return proof;
  }
}
