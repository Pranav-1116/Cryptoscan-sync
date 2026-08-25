use md5::Md5;
use sha2::Sha256;
use aes_gcm::Aes256Gcm;
use rsa::RsaPrivateKey;
use rustls::ServerConfig;

fn main() {
    let _d = Md5::digest(b"x");
    let _s = Sha256::digest(b"y");
    let _a = Aes256Gcm::new(&key);
    let _r = RsaPrivateKey::new(&mut rng, 2048);
    let _t = ServerConfig::builder();
}
