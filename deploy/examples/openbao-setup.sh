#!/bin/sh
# One-time OpenBao setup for you-spin-me (Kubernetes auth method).
# Run with a privileged token, e.g. `BAO_ADDR=... BAO_TOKEN=... ./openbao-setup.sh`.
set -eu

NAMESPACE=${NAMESPACE:-you-spin-me}
SERVICE_ACCOUNT=${SERVICE_ACCOUNT:-you-spin-me}

# Enable the Kubernetes auth method if it is not already enabled. When OpenBao
# runs in the same cluster, it can use its own ServiceAccount to review tokens.
bao auth list -format=json | grep -q '"kubernetes/"' || bao auth enable kubernetes
bao write auth/kubernetes/config kubernetes_host="https://kubernetes.default.svc"

bao policy write you-spin-me "$(dirname "$0")/openbao-policy.hcl"

# The chart mounts a projected token with audience "openbao".
bao write auth/kubernetes/role/you-spin-me \
  bound_service_account_names="$SERVICE_ACCOUNT" \
  bound_service_account_namespaces="$NAMESPACE" \
  audience=openbao \
  token_policies=you-spin-me \
  token_ttl=15m \
  token_max_ttl=1h
