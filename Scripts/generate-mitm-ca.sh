#!/usr/bin/env bash

set -euo pipefail
umask 077

project_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
output_dir="${1:-$project_root/MITM/private}"
template="$project_root/MITM/config.template.json"

mkdir -p "$output_dir"

password="${MITM_P12_PASSWORD:-$(openssl rand -hex 16)}"
password_file="$output_dir/mitm-ca.password.txt"
key_file="$output_dir/mitm-ca.key.pem"
cert_file="$output_dir/mitm-ca.crt.pem"
cert_der_file="$output_dir/mitm-ca.cer"
p12_file="$output_dir/mitm-ca.p12"
config_file="$output_dir/config.json"

printf '%s\n' "$password" > "$password_file"

openssl req -x509 -newkey rsa:2048 -sha256 -nodes -days 3650 \
    -subj "/CN=sing-box MITM Root CA/O=Local sing-box MITM" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign,digitalSignature" \
    -addext "subjectKeyIdentifier=hash" \
    -keyout "$key_file" \
    -out "$cert_file"

openssl x509 -in "$cert_file" -outform DER -out "$cert_der_file"
openssl pkcs12 -export \
    -inkey "$key_file" \
    -in "$cert_file" \
    -name "sing-box MITM Root CA" \
    -passout "file:$password_file" \
    -out "$p12_file"

p12_base64="$(base64 < "$p12_file" | tr -d '\n')"
jq \
    --arg p12 "$p12_base64" \
    --arg password "$password" \
    '.certificate.tls_decryption.key_pair_p12 = $p12
     | .certificate.tls_decryption.key_pair_p12_password = $password' \
    "$template" > "$config_file"

openssl pkcs12 -in "$p12_file" -passin "file:$password_file" -noout
jq empty "$config_file"

echo "MITM CA:     $cert_der_file"
echo "MITM config: $config_file"
echo "P12 password is stored in: $password_file"
