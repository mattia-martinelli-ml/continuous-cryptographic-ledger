import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'fs';
import { join } from 'path';
import { tmpdir } from 'os';
import { KeyManager, verifySignature } from '../src/signer.js';
import { sha256Hash } from '../src/merkle.js';

test('signer creates keypair and verifies signature', () => {
  const tempDir = mkdtempSync(join(tmpdir(), 'keytest-'));
  const privatePath = join(tempDir, 'private_key.pem');
  const publicPath = join(tempDir, 'public_key.pem');

  const signer = new KeyManager(privatePath, publicPath);
  const payload = sha256Hash('compliance-event');
  const context = '2025-04-15T14:00:00Z';
  const signature = signer.sign(payload, context);

  assert.strictEqual(verifySignature(publicPath, payload, signature, context), true);
  assert.strictEqual(verifySignature(publicPath, payload, signature, 'wrong-context'), false);
  assert.ok(signer.publicKeyFingerprint());

  rmSync(tempDir, { recursive: true, force: true });
});
