resource "aws_s3_bucket" "logs" {
  bucket = "cryptoscan-demo-logs"
}

resource "aws_db_instance" "payments" {
  identifier          = "payments"
  instance_class      = "db.t3.medium"
  engine              = "postgres"
  storage_encrypted   = false
}

resource "aws_kms_key" "payments" {
  customer_master_key_spec = "RSA_2048"
  enable_key_rotation      = false
}

resource "aws_lb_listener" "public" {
  port       = 443
  protocol   = "HTTPS"
  ssl_policy = "ELBSecurityPolicy-TLS-1-0-2015-04"
}

resource "google_kms_crypto_key" "archive" {
  name = "archive"
}
