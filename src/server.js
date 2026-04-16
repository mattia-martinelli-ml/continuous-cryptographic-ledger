import express from 'express';

/**
 * Avvia il server REST API per le inclusion proofs.
 * @param {DatabaseClient} dbClient
 * @param {number} port
 */
export function startServer(dbClient, port = 3000) {
  const app = express();

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

  return app.listen(port, () => {
    console.log(`Inclusion Proof API server in ascolto sulla porta ${port}`);
  });
}
