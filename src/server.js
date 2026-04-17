import express from 'express';

/**
 * Avvia il server REST API per le inclusion proofs.
 * @param {DatabaseClient} dbClient
 * @param {number} port
 */
export function startServer(dbClient, port = 3000) {
  const app = express();
  
  // Health check endpoint
  app.get('/health', async (req, res) => {
    try {
      // Check database connectivity
      const result = await dbClient.pool.query('SELECT 1 as health');
      res.json({ 
        status: 'healthy', 
        timestamp: new Date().toISOString(),
        database: result.rows[0] ? 'connected' : 'disconnected'
      });
    } catch (error) {
      res.status(503).json({ 
        status: 'unhealthy', 
        timestamp: new Date().toISOString(),
        error: error.message 
      });
    }
  });
  
  // Chain statistics endpoint
  app.get('/api/v1/chain/stats', async (req, res) => {
    try {
      const stats = await dbClient.getChainStats();
      res.json(stats);
    } catch (error) {
      console.error('API Error:', error);
      const isProduction = process.env.NODE_ENV === 'production';
      res.status(500).json({ error: isProduction ? 'Errore interno del server' : error.message });
    }
  });
  
  // Chain integrity verification endpoint
  app.get('/api/v1/chain/verify', async (req, res) => {
    try {
      const startTime = req.query.start ? new Date(req.query.start) : null;
      const endTime = req.query.end ? new Date(req.query.end) : null;
      const result = await dbClient.verifyChainIntegrity(startTime, endTime);
      res.json(result);
    } catch (error) {
      console.error('API Error:', error);
      const isProduction = process.env.NODE_ENV === 'production';
      res.status(500).json({ error: isProduction ? 'Errore interno del server' : error.message });
    }
  });
  
  // Events query endpoint with filtering and pagination
  app.get('/api/v1/events', async (req, res) => {
    try {
      const startTime = req.query.start_time ? new Date(req.query.start_time) : null;
      const endTime = req.query.end_time ? new Date(req.query.end_time) : null;
      const limit = Math.min(parseInt(req.query.limit) || 100, 1000);
      const offset = parseInt(req.query.offset) || 0;
      const orderBy = req.query.order_by || 'occurred_at';
      const order = req.query.order || 'asc';
      
      const result = await dbClient.queryEvents({ 
        startTime, 
        endTime, 
        limit, 
        offset, 
        orderBy, 
        order 
      });
      
      res.json({
        events: result.events,
        total: result.total,
        limit,
        offset
      });
    } catch (error) {
      console.error('API Error:', error);
      const isProduction = process.env.NODE_ENV === 'production';
      res.status(500).json({ error: isProduction ? 'Errore interno del server' : error.message });
    }
  });

  // REQ-3.2: Inclusion Proof API
  app.get('/api/v1/proof/:log_id', async (req, res) => {
    try {
      const eventId = req.params.log_id;
      const hourStart = req.query.hour_start;

      if (!hourStart) {
        return res.status(400).json({ error: 'Il parametro query hour_start è richiesto (formato ISO 8601)' });
      }

      const proof = await dbClient.generateInclusionProof(Number(eventId), hourStart);

      // Recupera anche il payload in chiaro come richiesto da REQ-3.2
      const result = await dbClient.pool.query(
        'SELECT payload FROM compliance_event WHERE event_id = $1',
        [eventId]
      );

      if (result.rows.length === 0) {
        return res.status(404).json({ error: 'Evento non trovato' });
      }

      res.json({
        ...proof,
        payload: result.rows[0].payload
      });
    } catch (error) {
      console.error('API Error:', error);
      // In production, only return generic error messages to avoid leaking internal details
      const isProduction = process.env.NODE_ENV === 'production';
      res.status(500).json({ error: isProduction ? 'Errore interno del server' : error.message });
    }
  });
  
  // Event integrity verification endpoint
  app.get('/api/v1/events/:eventId/verify', async (req, res) => {
    try {
      const eventId = Number(req.params.eventId);
      const result = await dbClient.verifyEventIntegrity(eventId);
      res.json(result);
    } catch (error) {
      console.error('API Error:', error);
      const isProduction = process.env.NODE_ENV === 'production';
      res.status(500).json({ error: isProduction ? 'Errore interno del server' : error.message });
    }
  });

  return app.listen(port, () => {
    console.log(`Inclusion Proof API server in ascolto sulla porta ${port}`);
  });
}
