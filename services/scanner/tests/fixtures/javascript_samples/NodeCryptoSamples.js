const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const CryptoJS = require('crypto-js');

function encrypt(key, iv, data) {
  return crypto.createCipheriv('aes-256-gcm', key, iv).update(data);
}

function weakHash(data) {
  return crypto.createHash('md5').update(data).digest('hex');
}

function sign(payload, secret) {
  return jwt.sign(payload, secret, { algorithm: 'HS256' });
}

async function password(pw) {
  return bcrypt.hash(pw, 10);
}

function cryptoJs(data) {
  return CryptoJS.AES.encrypt(data, 'pass').toString();
}

const secret = 'highEntropySecretValue!!';
