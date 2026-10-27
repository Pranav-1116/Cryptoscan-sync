<?php
openssl_encrypt($payload, 'AES-256-CBC', $key);
echo md5($password);
hash('sha1', $token);
password_hash($password, PASSWORD_BCRYPT);
