#!/bin/bash
# 개발용 self-signed TLS 인증서 생성
# 프로덕션에서는 cert-manager 사용 권장
set -euo pipefail

NAMESPACE="${NAMESPACE:-patrol-system}"
SERVICE="${SERVICE:-patrol-webhook}"
SECRET="${SECRET:-patrol-webhook-certs}"
TMPDIR=$(mktemp -d)

echo "=== Generating self-signed TLS certificate for ${SERVICE}.${NAMESPACE} ==="

# 네임스페이스가 없으면 생성
kubectl get namespace "${NAMESPACE}" &>/dev/null || kubectl create namespace "${NAMESPACE}"

# CA
openssl genrsa -out "${TMPDIR}/ca.key" 2048
openssl req -x509 -new -nodes -key "${TMPDIR}/ca.key" \
  -subj "/CN=patrol-webhook-ca" \
  -days 3650 -out "${TMPDIR}/ca.crt"

# Server key + CSR
openssl genrsa -out "${TMPDIR}/tls.key" 2048
cat > "${TMPDIR}/csr.conf" <<EOF
[req]
req_extensions = v3_req
distinguished_name = dn
prompt = no

[dn]
CN = ${SERVICE}.${NAMESPACE}.svc

[v3_req]
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = ${SERVICE}
DNS.2 = ${SERVICE}.${NAMESPACE}
DNS.3 = ${SERVICE}.${NAMESPACE}.svc
DNS.4 = ${SERVICE}.${NAMESPACE}.svc.cluster.local
EOF

openssl req -new -key "${TMPDIR}/tls.key" \
  -out "${TMPDIR}/server.csr" \
  -config "${TMPDIR}/csr.conf"

# Sign
openssl x509 -req -in "${TMPDIR}/server.csr" \
  -CA "${TMPDIR}/ca.crt" -CAkey "${TMPDIR}/ca.key" \
  -CAcreateserial -out "${TMPDIR}/tls.crt" \
  -days 365 -extensions v3_req -extfile "${TMPDIR}/csr.conf"

# Create secret
kubectl -n "${NAMESPACE}" create secret tls "${SECRET}" \
  --cert="${TMPDIR}/tls.crt" \
  --key="${TMPDIR}/tls.key" \
  --dry-run=client -o yaml | kubectl apply -f -

# Patch webhook with CA bundle
CA_BUNDLE=$(base64 < "${TMPDIR}/ca.crt" | tr -d '\n')
kubectl patch validatingwebhookconfiguration patrol-pod-validator \
  --type='json' \
  -p="[{\"op\":\"add\",\"path\":\"/webhooks/0/clientConfig/caBundle\",\"value\":\"${CA_BUNDLE}\"}]"

echo "=== Done. CA bundle injected into ValidatingWebhookConfiguration ==="
rm -rf "${TMPDIR}"
