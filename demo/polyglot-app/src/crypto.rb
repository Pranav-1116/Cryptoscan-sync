require 'openssl'
require 'digest'

Digest::MD5.hexdigest(password)
cipher = OpenSSL::Cipher.new('AES-256-GCM')
rsa = OpenSSL::PKey::RSA.new(1024)
