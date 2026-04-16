import crypto from 'crypto';

/**
 * Simula un'autorità di marcatura temporale (TSA) conforme a RFC 3161.
 * In un ambiente reale, questo interagirebbe con un server TSA esterno.
 */
export class TSAClient {
  /**
   * Genera una prova di marcatura temporale per un hash di dati.
   * @param {Buffer} rootHash Il Merkle Root Hash da ancorare.
   * @returns {Promise<Buffer>} Il token TSA (simulato).
   */
  async timestamp(rootHash) {
    // Simula un ritardo di rete
    await new Promise(resolve => setTimeout(resolve, 50));

    const now = new Date().toISOString();
    // La "prova" è un hash del rootHash + timestamp, firmato virtualmente
    const tokenData = Buffer.concat([
      rootHash,
      Buffer.from(now)
    ]);

    return crypto.createHash('sha256').update(tokenData).digest();
  }

  /**
   * Verifica un token TSA simulato.
   * @param {Buffer} rootHash
   * @param {Buffer} token
   * @returns {boolean}
   */
  verify(rootHash, token) {
    // In questa simulazione non possiamo verificare senza il timestamp originale,
    // ma in un sistema reale il token conterrebbe il timestamp e la firma del TSA.
    // Per simulazione, accettiamo solo token di 32 byte che non sono vuoti.
    return token && token.length === 32 && !token.equals(Buffer.alloc(32));
  }
}
