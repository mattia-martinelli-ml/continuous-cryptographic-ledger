import { Pool } from 'pg';
import { buildMerkleRoot, stableSerialize, sha256Hash, hashLeaf, generateInclusionProof as computeInclusionProof, verifyMerkleProof } from './merkle.js';
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

// Input validation helpers
const validateEventPayload = (payload) => {
  if (payload === null || payload === undefined) {
    throw new Error('Il payload dell\'evento non può essere null o undefined');
  }
  if (typeof payload !== 'object') {
    throw new Error('Il payload deve essere un oggetto');
  }
};

const validateTimestamp = (date) => {
  if (!(date instanceof Date) || Number.isNaN(date.getTime())) {
    throw new Error('Timestamp non valido');
  }
};

export class DatabaseClient {
  constructor(dsn, signer) {
    if (!dsn || typeof dsn !== 'string') {
      throw new Error('DSN non valido: deve essere una stringa non vuota');
    }
    if (!signer) {
      throw new Error('Signer non fornito');
    }
    this.pool = new Pool({ connectionString: dsn });
    this.signer = signer;
    this.tsa = new TSAClient();
  }

  async initializeSchema(setupSql) {
    if (!setupSql || typeof setupSql !== 'string') {
      throw new Error('SQL di setup non valido');
    }
    await this.pool.query(setupSql);
  }

  async insertEvent(payload, occurredAt) {
    validateEventPayload(payload);
    validateTimestamp(occurredAt);
    
    const serialized = stableSerialize(payload);
    const eventHash = hashLeaf(serialized);
    const result = await this.pool.query(
      'INSERT INTO compliance_event (occurred_at, payload, event_hash) VALUES ($1, $2, $3) RETURNING event_id',
      [occurredAt.toISOString(), payload, eventHash]
    );
    return result.rows[0].event_id;
  }

  /**
   * Batch insert multiple events efficiently.
   * @param {Array<{payload: object, occurredAt: Date}>} events - Array of events to insert
   * @returns {Promise<Array<number>>} Array of inserted event IDs
   */
  async insertEventsBatch(events) {
    if (!events || !Array.isArray(events)) {
      throw new Error('Events deve essere un array non vuoto');
    }
    
    if (events.length === 0) {
      return [];
    }
    
    // Validate each event
    for (let i = 0; i < events.length; i++) {
      const event = events[i];
      if (!event.payload) {
        throw new Error(`Evento all'indice ${i} manca del payload`);
      }
      validateEventPayload(event.payload);
      if (!event.occurredAt) {
        events[i].occurredAt = new Date();
      } else {
        validateTimestamp(event.occurredAt);
      }
    }
    
    // Prepare values for batch insert
    const values = [];
    const params = [];
    let paramIndex = 1;
    
    for (const event of events) {
      const serialized = stableSerialize(event.payload);
      const eventHash = hashLeaf(serialized);
      values.push(`($${paramIndex}, $${paramIndex + 1}, $${paramIndex + 2})`);
      params.push(event.occurredAt.toISOString(), event.payload, eventHash);
      paramIndex += 3;
    }
    
    const query = `
      INSERT INTO compliance_event (occurred_at, payload, event_hash) 
      VALUES ${values.join(', ')} 
      RETURNING event_id, occurred_at
    `;
    
    const result = await this.pool.query(query, params);
    
    // Sort results by occurred_at to maintain order
    const sortedResults = result.rows.sort((a, b) => 
      new Date(a.occurred_at).getTime() - new Date(b.occurred_at).getTime()
    );
    
    return sortedResults.map(row => row.event_id);
  }

  async getEventsForHour(hourStart) {
    if (!hourStart) {
      throw new Error('hourStart è richiesto');
    }
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

  /**
   * Query events with filtering and pagination.
   * @param {Object} options - Query options
   * @param {Date} options.startTime - Start time filter
   * @param {Date} options.endTime - End time filter
   * @param {number} options.limit - Maximum number of results
   * @param {number} options.offset - Offset for pagination
   * @param {string} options.orderBy - Order by field (occurred_at, event_id)
   * @param {string} options.order - Order direction (asc, desc)
   * @returns {Promise<{events: Array, total: number}>}
   */
  async queryEvents({ startTime = null, endTime = null, limit = 100, offset = 0, orderBy = 'occurred_at', order = 'asc' }) {
    // Validate pagination params
    if (typeof limit !== 'number' || limit < 1) {
      limit = 100;
    }
    if (typeof offset !== 'number' || offset < 0) {
      offset = 0;
    }
    
    // Validate order by field
    const validOrderBy = ['occurred_at', 'event_id', 'event_hash'];
    if (!validOrderBy.includes(orderBy)) {
      orderBy = 'occurred_at';
    }
    
    // Validate order direction
    if (!['asc', 'desc'].includes(order.toLowerCase())) {
      order = 'asc';
    }
    
    const conditions = [];
    const params = [];
    let paramIndex = 1;
    
    if (startTime) {
      validateTimestamp(startTime);
      conditions.push(`occurred_at >= $${paramIndex}`);
      params.push(startTime.toISOString());
      paramIndex++;
    }
    
    if (endTime) {
      validateTimestamp(endTime);
      conditions.push(`occurred_at <= $${paramIndex}`);
      params.push(endTime.toISOString());
      paramIndex++;
    }
    
    const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';
    const orderClause = `ORDER BY ${orderBy} ${order.toUpperCase()}`;
    
    // Get total count
    const countQuery = `SELECT COUNT(*) as total FROM compliance_event ${whereClause}`;
    const countResult = await this.pool.query(countQuery, params);
    const total = parseInt(countResult.rows[0].total);
    
    // Get paginated results
    const dataQuery = `SELECT event_id, occurred_at, payload, event_hash FROM compliance_event ${whereClause} ${orderClause} LIMIT $${paramIndex} OFFSET $${paramIndex + 1}`;
    params.push(limit, offset);
    
    const dataResult = await this.pool.query(dataQuery, params);
    
    const events = dataResult.rows.map((row) => ({
      event_id: row.event_id,
      occurred_at: new Date(row.occurred_at),
      payload: row.payload,
      event_hash: row.event_hash,
    }));
    
    return { events, total };
  }

  async computeAndStoreRoot(hourStart) {
    if (!hourStart) {
      throw new Error('hourStart è richiesto');
    }
    const start = normalizeHourStart(hourStart);
    const events = await this.getEventsForHour(start);
    const leafHashes = events.map((event) => event.event_hash);
    const root = buildMerkleRoot(leafHashes);
    const signature = this.signer.sign(root, start.toISOString());

    // REQ-3.1: External Anchoring with TSA
    const tsaProof = await this.tsa.timestamp(root);

    await this.pool.query(
      'INSERT INTO hourly_root (hour_start, root_hash, signature, tsa_proof) VALUES ($1, $2, $3, $4)',
      [start.toISOString(), root, signature, tsaProof]
    );
    return root;
  }

  async getHourlyRoot(hourStart) {
    if (!hourStart) {
      throw new Error('hourStart è richiesto');
    }
    const start = normalizeHourStart(hourStart);
    const result = await this.pool.query(
      'SELECT hour_start, root_hash, signature, signed_at FROM hourly_root WHERE hour_start = $1',
      [start.toISOString()]
    );
    return result.rows[0] || null;
  }

  /**
   * Verify the integrity of the chain of hourly roots.
   * This ensures all hourly roots are properly anchored and no gaps exist.
   * @param {Date} startTime - Start of verification range (optional)
   * @param {Date} endTime - End of verification range (optional)
   * @returns {Promise<{valid: boolean, errors: Array<string>, checkedHours: number}>}
   */
  async verifyChainIntegrity(startTime = null, endTime = null) {
    let query = 'SELECT hour_start, root_hash, signature FROM hourly_root';
    const params = [];
    
    if (startTime || endTime) {
      const conditions = [];
      if (startTime) {
        conditions.push('hour_start >= $1');
        params.push(startTime.toISOString());
      }
      if (endTime) {
        conditions.push('hour_start <= $' + (params.length + 1));
        params.push(endTime.toISOString());
      }
      query += ' WHERE ' + conditions.join(' AND ');
    }
    
    query += ' ORDER BY hour_start ASC';
    
    const result = await this.pool.query(query, params);
    const roots = result.rows;
    
    const errors = [];
    let cumulativeHash = null;
    
    for (let i = 0; i < roots.length; i++) {
      const root = roots[i];
      const hourStart = new Date(root.hour_start);
      
      // Check for gaps in the chain (first entry should have no previous)
      if (i > 0) {
        const prevHourStart = new Date(roots[i - 1].hour_start);
        const expectedGap = 60 * 60 * 1000; // 1 hour in ms
        const actualGap = hourStart.getTime() - prevHourStart.getTime();
        
        if (actualGap !== expectedGap) {
          errors.push(`Gap rilevato tra ${prevHourStart.toISOString()} e ${hourStart.toISOString()}: ${actualGap / (1000 * 60)} minuti`);
        }
      }
      
      // Verify signature for this root
      const signatureValid = this.signer.verify(
        root.root_hash,
        root.signature,
        hourStart.toISOString()
      );
      
      if (!signatureValid) {
        errors.push(`Firma non valida per ${hourStart.toISOString()}`);
      }
      
      // Update cumulative hash for chain integrity
      // Each root includes the previous cumulative hash for forward chaining
      const rootBuf = root.root_hash;
      cumulativeHash = sha256Hash(Buffer.concat([
        cumulativeHash || Buffer.alloc(32),
        rootBuf
      ]));
    }
    
    return {
      valid: errors.length === 0,
      errors,
      checkedHours: roots.length,
      cumulativeHash: cumulativeHash ? cumulativeHash.toString('hex') : null
    };
  }

  /**
   * Get chain statistics.
   * @returns {Promise<{totalHours: number, firstHour: Date, lastHour: Date, totalEvents: number}>}
   */
  async getChainStats() {
    const rootResult = await this.pool.query(
      'SELECT COUNT(*) as count, MIN(hour_start) as first_hour, MAX(hour_start) as last_hour FROM hourly_root'
    );
    
    const eventResult = await this.pool.query(
      'SELECT COUNT(*) as count FROM compliance_event'
    );
    
    return {
      totalHours: parseInt(rootResult.rows[0].count),
      firstHour: rootResult.rows[0].first_hour ? new Date(rootResult.rows[0].first_hour) : null,
      lastHour: rootResult.rows[0].last_hour ? new Date(rootResult.rows[0].last_hour) : null,
      totalEvents: parseInt(eventResult.rows[0].count)
    };
  }

  async generateInclusionProof(eventId, hourStart) {
    const start = normalizeHourStart(hourStart);
    const events = await this.getEventsForHour(start);
    const index = events.findIndex((event) => event.event_id === eventId);
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
  
  /**
   * Verify the integrity of a specific event by checking its hash matches the stored hash.
   * @param {number} eventId - The ID of the event to verify
   * @returns {Promise<{valid: boolean, event: object|null, errors: Array<string>}>}
   */
  async verifyEventIntegrity(eventId) {
    const errors = [];
    
    // Get the event from the database
    const result = await this.pool.query(
      'SELECT event_id, occurred_at, payload, event_hash FROM compliance_event WHERE event_id = $1',
      [eventId]
    );
    
    if (result.rows.length === 0) {
      return { valid: false, event: null, errors: [`Evento ${eventId} non trovato`] };
    }
    
    const storedEvent = result.rows[0];
    const storedHash = storedEvent.event_hash;
    
    // Recompute the hash from the payload
    const serialized = stableSerialize(storedEvent.payload);
    const computedHash = hashLeaf(serialized);
    
    // Compare hashes
    if (!computedHash.equals(storedHash)) {
      errors.push(`Hash non corrispondente per evento ${eventId}: il payload potrebbe essere stato alterato`);
    }
    
    // Check if event is included in a finalized hourly root
    const hourStart = new Date(storedEvent.occurred_at);
    hourStart.setUTCMinutes(0, 0, 0);
    const hourEnd = new Date(hourStart.getTime() + 60 * 60 * 1000);
    
    const rootResult = await this.pool.query(
      'SELECT root_hash FROM hourly_root WHERE hour_start = $1',
      [hourStart.toISOString()]
    );
    
    if (rootResult.rows.length === 0) {
      errors.push(`Evento ${eventId} non è ancora incluso in un root orario finalizzato`);
    } else {
      // Verify the event is in the correct position
      const events = await this.getEventsForHour(hourStart);
      const eventIndex = events.findIndex(e => e.event_id === eventId);
      
      if (eventIndex === -1) {
        errors.push(`Evento ${eventId} non trovato nella lista degli eventi per l'ora`);
      } else {
        // Verify inclusion proof
        const leaves = events.map(e => e.event_hash);
        const proof = computeInclusionProof(eventIndex, leaves);
        const proofValid = verifyMerkleProof(leaves[eventIndex], proof, rootResult.rows[0].root_hash);
        
        if (!proofValid) {
          errors.push(`Prova di inclusione non valida per evento ${eventId}`);
        }
      }
    }
    
    return {
      valid: errors.length === 0,
      event: storedEvent,
      errors
    };
  }

}
