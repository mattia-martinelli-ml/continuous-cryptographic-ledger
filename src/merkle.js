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

export const buildMerkleRoot = (leaves) => {
  let layer = leaves.map((leaf) => (Buffer.isBuffer(leaf) ? leaf : Buffer.from(leaf)));
  if (layer.length === 0) {
    return sha256Hash(Buffer.alloc(0));
  }
  while (layer.length > 1) {
    const nextLayer = [];
    for (let i = 0; i < layer.length; i += 2) {
      const left = layer[i];
      const right = i + 1 < layer.length ? layer[i + 1] : layer[i];
      nextLayer.push(sha256Hash(Buffer.concat([left, right])));
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
};

export const verifyMerkleProof = (leaf, proof, root) => {
  let computed = Buffer.isBuffer(leaf) ? leaf : Buffer.from(leaf);
  for (const { sibling, position } of proof) {
    const siblingBuf = Buffer.isBuffer(sibling) ? sibling : Buffer.from(sibling);
    if (position === 'left') {
      computed = sha256Hash(Buffer.concat([siblingBuf, computed]));
    } else {
      computed = sha256Hash(Buffer.concat([computed, siblingBuf]));
    }
  }
  return computed.equals(root);
};

export const stableSerialize = (payload) => stableStringify(payload);
