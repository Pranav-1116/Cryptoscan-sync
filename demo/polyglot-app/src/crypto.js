const crypto = require("crypto");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");

function encrypt(buf, key, iv) {
  return crypto.createCipheriv("aes-256-gcm", key, iv);
}

function weakHash(buf) {
  return crypto.createHash("md5").update(buf).digest("hex");
}

function token(user) {
  return jwt.sign({ sub: user }, "dev-secret", { algorithm: "HS256" });
}

function password(value) {
  return bcrypt.hash(value, 10);
}

const secret = "s3cretKeyValue!!";

module.exports = { encrypt, weakHash, token, password, secret };
