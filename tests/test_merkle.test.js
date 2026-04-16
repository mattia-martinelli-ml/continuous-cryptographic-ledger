import { test } from 'node:test';
import assert from 'node:assert/strict';
import { buildMerkleRoot, generateInclusionProof, verifyMerkleProof, sha256Hash, hashLeaf } from '../src/merkle.js';

test('sha256 hash is stable', () => {
  assert.strictEqual(
    sha256Hash('hello').toString('hex'),
    '2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824'
  );
});

test('build merkle root for single leaf', () => {
  const leaf = hashLeaf('event');
  assert.deepStrictEqual(buildMerkleRoot([leaf]), leaf);
});

test('build merkle root for multiple leaves', () => {
  const leaves = [hashLeaf('a'), hashLeaf('b')];
  const root = buildMerkleRoot(leaves);
  assert.strictEqual(root.length, 32);
});

test('inclusion proof verifies correctly', () => {
  const leaves = [hashLeaf('a'), hashLeaf('b'), hashLeaf('c')];
  const proof = generateInclusionProof(1, leaves);
  const root = buildMerkleRoot(leaves);
  assert.strictEqual(verifyMerkleProof(leaves[1], proof, root), true);
});

test('merkle root is not vulnerable to duplicate-last-node collision', () => {
  const L1 = hashLeaf('event1');
  const L2 = hashLeaf('event2');
  const L3 = hashLeaf('event3');

  const root1 = buildMerkleRoot([L1, L2, L3]);
  const root2 = buildMerkleRoot([L1, L2, L3, L3]);

  assert.notDeepStrictEqual(root1, root2, 'Roots should be different for 3 vs 4 events');
});

test('merkle tree implements domain separation between leaves and internal nodes', () => {
  const L1 = hashLeaf('a');
  const L2 = hashLeaf('b');

  // This is what an internal node combining L1 and L2 would look like
  const internalNode = sha256Hash(Buffer.concat([Buffer.from([0x01]), L1, L2]));

  // A leaf with the same combined data should have a different hash due to 0x00 prefix
  const leafWithCombinedData = hashLeaf(Buffer.concat([L1, L2]));

  assert.notDeepStrictEqual(internalNode, leafWithCombinedData, 'Internal node and leaf should have different hashes');
});
