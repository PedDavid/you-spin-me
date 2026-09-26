# Policy for you-spin-me: write-only access to the paths its ApiKeys target.
# No read, list or metadata access, so the app can never read keys back.
#
#   bao policy write you-spin-me deploy/examples/openbao-policy.hcl
#
# Grant only the paths meant for this app: anyone who can merge an ApiKey can
# point it at any path allowed here, and it would overwrite the key there.
path "secret/data/ci/*" {
  capabilities = ["create", "patch"]
}

path "secret/data/home/*" {
  capabilities = ["create", "patch"]
}
