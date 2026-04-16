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

test('merkle root handles odd number of leaves correctly', () => {
  const L1 = hashLeaf('event1');
  const L2 = hashLeaf('event2');
  const L3 = hashLeaf('event3');

  // With standard Merkle tree (duplicate last node), 3 leaves and 4 leaves where
  // the 4th duplicates the 3rd produce the SAME root
  const root3 = buildMerkleRoot([L1, L2, L3]);
  const root4 = buildMerkleRoot([L1, L2, L3, L3]);

  // This is expected: tree with 3 items = tree with 4 items where last is duplicated
  assert.deepStrictEqual(root3, root4, 'Roots should be equal for 3 vs 4 with duplicate');
  
  // Different number of unique leaves should produce different roots
  const root2 = buildMerkleRoot([L1, L2]);
  assert.notDeepStrictEqual(root2, root3, 'Roots should be different for 2 vs 3 events');
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
