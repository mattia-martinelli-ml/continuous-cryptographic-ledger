import fs from 'fs';
import crypto from 'crypto';
import path from 'path';

export class KeyManager {
  constructor(privateKeyPath, publicKeyPath) {
    this.privateKeyPath = path.resolve(privateKeyPath);
    this.publicKeyPath = path.resolve(publicKeyPath);
    this._loadKeys();
  }

  _loadKeys() {
    if (fs.existsSync(this.privateKeyPath) && fs.existsSync(this.publicKeyPath)) {
      this.privateKey = crypto.createPrivateKey({
        key: fs.readFileSync(this.privateKeyPath, 'utf8'),
        format: 'pem',
      });
      this.publicKey = crypto.createPublicKey({
        key: fs.readFileSync(this.publicKeyPath, 'utf8'),
        format: 'pem',
      });
    } else {
      this._generateKeys();
    }
  }

  _generateKeys() {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
    this.privateKey = privateKey;
    this.publicKey = publicKey;
    fs.mkdirSync(path.dirname(this.privateKeyPath), { recursive: true });
    fs.writeFileSync(
      this.privateKeyPath,
      privateKey.export({ format: 'pem', type: 'pkcs8' }),
      { encoding: 'utf8', mode: 0o600 }
    );
    fs.writeFileSync(
      this.publicKeyPath,
      publicKey.export({ format: 'pem', type: 'spki' }),
      'utf8'
    );
  }

  sign(data, context = '') {
    const msg = context ? Buffer.concat([Buffer.from(context), data]) : data;
    return crypto.sign(null, msg, this.privateKey);
  }

  verify(data, signature, context = '') {
    const msg = context ? Buffer.concat([Buffer.from(context), data]) : data;
    try {
      return crypto.verify(null, msg, this.publicKey, signature);
    } catch {
      return false;
    }
  }

  publicKeyFingerprint() {
    const raw = this.publicKey.export({ format: 'der', type: 'spki' });
    return Buffer.from(raw).toString('base64');
  }
}

export const verifySignature = (publicKeyPath, data, signature, context = '') => {
  const publicKeyPem = fs.readFileSync(path.resolve(publicKeyPath), 'utf8');
  const publicKey = crypto.createPublicKey({ key: publicKeyPem, format: 'pem' });
  const msg = context ? Buffer.concat([Buffer.from(context), data]) : data;
  try {
    return crypto.verify(null, msg, publicKey, signature);
  } catch {
    return false;
  }
};
