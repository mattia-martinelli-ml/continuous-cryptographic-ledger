import crypto from 'crypto';

const stableStringify = (value) => {
  if (value === null || typeof value !== 'object') {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map(stableStringify).join(',')}]`;
  }
  const keys = Object.keys(value).sort();
  return `{${keys.map((key) => `${JSON.stringify(key)}:${stableStringify(value[key])}`).join(',')}}`;
};

export const sha256Hash = (data) => {
  const hash = crypto.createHash('sha256');
  if (typeof data === 'string') {
    hash.update(data, 'utf8');
  } else {
    hash.update(data);
  }
  return hash.digest();
};

export const hashLeaf = (data) => {
  const buf = typeof data === 'string' ? Buffer.from(data, 'utf8') : data;
  return sha256Hash(Buffer.concat([Buffer.from([0x00]), buf]));
};

export const hashInternal = (left, right) => {
  return sha256Hash(Buffer.concat([Buffer.from([0x01]), left, right]));
};

export const buildMerkleRoot = (leaves) => {
  let layer = leaves.map((leaf) => (Buffer.isBuffer(leaf) ? leaf : Buffer.from(leaf)));
  if (layer.length === 0) {
    return sha256Hash(Buffer.alloc(0));
  }
  while (layer.length > 1) {
    const nextLayer = [];
    for (let i = 0; i < layer.length; i += 2) {
      if (i + 1 < layer.length) {
        nextLayer.push(hashInternal(layer[i], layer[i + 1]));
      } else {
        // Standard Merkle tree: duplicate the last node and hash with itself
        nextLayer.push(hashInternal(layer[i], layer[i]));
      }
    }
    layer = nextLayer;
  }
  return layer[0];
};

export const generateInclusionProof = (index, leaves) => {
  if (index < 0 || index >= leaves.length) {
    throw new Error('Indice della foglia fuori range');
  }
  let layer = leaves.map((leaf) => (Buffer.isBuffer(leaf) ? leaf : Buffer.from(leaf)));
  const proof = [];
  let idx = index;
  while (layer.length > 1) {
    const nextLayer = [];
    for (let i = 0; i < layer.length; i += 2) {
      if (i + 1 < layer.length) {
        // Normal pair
        if (i === idx) {
          proof.push({ sibling: layer[i + 1], position: 'right' });
        } else if (i + 1 === idx) {
          proof.push({ sibling: layer[i], position: 'left' });
        }
        nextLayer.push(hashInternal(layer[i], layer[i + 1]));
      } else {
        // Standard Merkle tree: duplicate last node and hash with itself
        // Only add proof entry if the index being proven IS the odd node
        if (i === idx) {
          proof.push({ sibling: layer[i], position: 'right' });
        }
        nextLayer.push(hashInternal(layer[i], layer[i]));
      }
      if (i === idx || i + 1 === idx) {
        idx = nextLayer.length - 1;
      }
    }
    layer = nextLayer;
  }
  return proof;
};

export const verifyMerkleProof = (leaf, proof, root) => {
  let computed = Buffer.isBuffer(leaf) ? leaf : Buffer.from(leaf);
  for (const { sibling, position } of proof) {
    const siblingBuf = Buffer.isBuffer(sibling) ? sibling : Buffer.from(sibling);
    if (position === 'left') {
      computed = hashInternal(siblingBuf, computed);
    } else {
      computed = hashInternal(computed, siblingBuf);
    }
  }
  return computed.equals(root);
};

export const stableSerialize = (payload) => stableStringify(payload);
