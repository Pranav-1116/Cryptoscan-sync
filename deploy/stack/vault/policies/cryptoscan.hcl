# Vault policy for the platform's runtime identity (the SECRETS layer).
# Values live in the KV store; this file grants paths only — no secret is
# ever committed to the repository.
path "secret/data/cryptoscan/*" {
  capabilities = ["read", "list"]
}

path "secret/data/cryptoscan/checkpoint-signing" {
  capabilities = ["read"]
}

path "secret/metadata/cryptoscan/*" {
  capabilities = ["list"]
}
