// SAMA Open Banking (KSA OBF) – JWS detached signature for payment initiation, PS256 with the OB signing cert
const jose = require("jose");
const fs = require("fs");

async function signPayload(payload, kid) {
  const pem = fs.readFileSync(process.env.OB_SIGNING_KEY, "utf8");
  const key = await jose.importPKCS8(pem, "PS256");
  return new jose.CompactSign(Buffer.from(JSON.stringify(payload)))
    .setProtectedHeader({ alg: "PS256", kid, b64: false, crit: ["b64"], "http://openbanking.org.uk/tan": "openbanking.sa" })
    .sign(key);
}

async function verifyConsent(jwt, jwks) {
  const { payload } = await jose.jwtVerify(jwt, jose.createRemoteJWKSet(new URL(jwks)), { algorithms: ["PS256", "ES256"] });
  return payload;
}
module.exports = { signPayload, verifyConsent };
