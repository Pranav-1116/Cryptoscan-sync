use md5::Md5;
use aes_gcm::Aes256Gcm;

fn legacy(key: &[u8]) {
    let _ = Md5::digest(b"password");
    let _ = Aes256Gcm::new_from_slice(key);
}
