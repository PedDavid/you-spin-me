# you-spin-me

A self-hosted, Kubernetes-native inventory of external API keys. For each key it
tracks how the key is set up, when it expires, where to renew it and where it has
to be updated, and it exports Prometheus metrics so expiry alerts arrive in one place.

It never stores keys. On rotation it writes the new key once to the configured
Kubernetes Secrets or OpenBao paths and forgets it.

Status: planning. See [docs/PLAN.md](docs/PLAN.md).
