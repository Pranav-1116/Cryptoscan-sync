<?php
openssl_encrypt($data, 'AES-256-CBC', $key);
openssl_decrypt($data, 'AES-256-GCM', $key);
md5($password);
hash('sha1', $x);
hash_hmac('sha256', $x, $key);
hash_pbkdf2('sha256', $pw, $salt, 10000);
password_hash($pw, PASSWORD_BCRYPT);
password_hash($pw, PASSWORD_ARGON2ID);
sodium_crypto_secretbox($msg, $nonce, $key);
openssl_pkey_new(['private_key_bits' => 1024]);
