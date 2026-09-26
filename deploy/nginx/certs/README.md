# TLS certificates (not committed)

Place the edge certificate + key here before enabling `docker-compose.tls.yml`:

    fullchain.pem   # full chain, leaf first (Let's Encrypt name works as-is)
    privkey.pem     # private key, chmod 600

Everything in this directory is mounted read-only into the nginx edge
container at `/etc/nginx/certs`. **Never commit real certificates or keys** —
this README is the only file that should live here in git.

## Issue / renew with Let's Encrypt (HTTP-01)

```bash
sudo certbot certonly --standalone -d cryptoscan.example.com
cp /etc/letsencrypt/live/cryptoscan.example.com/{fullchain,privkey}.pem deploy/nginx/certs/
sudo cp /etc/letsencrypt/renewal-hooks/deploy/reload-cryptoscan /etc/letsencrypt/renewal-hooks/deploy/
```

Renewal hook (`/etc/letsencrypt/renewal-hooks/deploy/reload-cryptoscan`):

```bash
#!/usr/bin/env bash
cd /opt/cryptoscan   # repo checkout on the production host
docker compose -f docker-compose.yml -f docker-compose.prod.yml -f docker-compose.tls.yml \
  exec nginx nginx -s reload
```

Verify after (re)deploy:

    curl -sSI https://cryptoscan.example.com | head -1          # HTTP/2 200
    curl -sSI http://cryptoscan.example.com  | head -1          # 301 -> https
    openssl s_client -connect cryptoscan.example.com:443 -tls1_3 </dev/null | head -2
