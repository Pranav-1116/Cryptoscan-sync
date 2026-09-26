#!/bin/bash
certbot certonly --nginx -d example.com --key-type ecdsa --elliptic-curve secp384r1 --agree-tos -m ops@example.com -n
