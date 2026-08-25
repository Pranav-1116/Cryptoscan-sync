import { createCipheriv, createHash } from 'crypto';

export function encrypt(key: Buffer, iv: Buffer, data: Buffer): Buffer {
  return createCipheriv('aes-256-gcm', key, iv).update(data);
}

export function digest(data: Buffer): Buffer {
  return createHash('sha256').update(data).digest();
}
