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
    const keyDir = path.dirname(this.privateKeyPath);
    const lockFile = path.join(keyDir, '.keygen.lock');
    
    // Use a lock file to prevent race conditions during key generation
    let fd;
    try {
      // Try to create lock file exclusively
      fd = fs.openSync(lockFile, 'wx');
    } catch (err) {
      if (err.code === 'EEXIST') {
        // Another process is generating keys, wait and retry loading
        // Wait for the other process to complete
        const maxWait = 5000;
        const start = Date.now();
        while (fs.existsSync(lockFile) && Date.now() - start < maxWait) {
          // Wait a bit
          const fs2 = require('fs');
          fs2.readFileSync('/dev/null');
        }
        // Retry loading keys
        if (fs.existsSync(this.privateKeyPath) && fs.existsSync(this.publicKeyPath)) {
          this._loadKeys();
          return;
        }
      }
      throw err;
    }
    
    try {
      // Check again if keys were created while we were waiting for lock
      if (fs.existsSync(this.privateKeyPath) && fs.existsSync(this.publicKeyPath)) {
        this._loadKeys();
        return;
      }
      
      const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
      this.privateKey = privateKey;
      this.publicKey = publicKey;
      fs.mkdirSync(keyDir, { recursive: true });
      
      // Write keys atomically using temporary files + rename
      const privateTmp = this.privateKeyPath + '.tmp';
      const publicTmp = this.publicKeyPath + '.tmp';
      
      fs.writeFileSync(
        privateTmp,
        privateKey.export({ format: 'pem', type: 'pkcs8' }),
        { encoding: 'utf8', mode: 0o600 }
      );
      fs.writeFileSync(
        publicTmp,
        publicKey.export({ format: 'pem', type: 'spki' }),
        'utf8'
      );
      
      // Atomic rename
      fs.renameSync(privateTmp, this.privateKeyPath);
      fs.renameSync(publicTmp, this.publicKeyPath);
    } finally {
      if (fd !== undefined) {
        fs.closeSync(fd);
        fs.unlinkSync(lockFile);
      }
    }
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
