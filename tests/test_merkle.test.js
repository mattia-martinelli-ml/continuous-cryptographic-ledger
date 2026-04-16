import { test } from 'node:test';
import assert from 'node:assert/strict';
import { buildMerkleRoot, generateInclusionProof, verifyMerkleProof, sha256Hash } from '../src/merkle.js';

test('sha256 hash is stable', () => {
  assert.strictEqual(
    sha256Hash('hello').toString('hex'),
    '2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824'
  );
});

test('build merkle root for single leaf', () => {
  const leaf = sha256Hash('event');
  assert.deepStrictEqual(buildMerkleRoot([leaf]), leaf);
});

test('build merkle root for multiple leaves', () => {
  const leaves = [sha256Hash('a'), sha256Hash('b')];
  const root = buildMerkleRoot(leaves);
  assert.strictEqual(root.length, 32);
});

test('inclusion proof verifies correctly', () => {
  const leaves = [sha256Hash('a'), sha256Hash('b'), sha256Hash('c')];
  const proof = generateInclusionProof(1, leaves);
  const root = buildMerkleRoot(leaves);
  assert.strictEqual(verifyMerkleProof(leaves[1], proof, root), true);
});
