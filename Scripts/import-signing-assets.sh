#!/usr/bin/env bash

set -euo pipefail
umask 077

if [[ $# -ne 1 ]]; then
    echo "Usage: SIGNING_P12_PASSWORD=... $0 /path/to/signing.zip" >&2
    exit 1
fi
if [[ -z "${SIGNING_P12_PASSWORD:-}" ]]; then
    echo "SIGNING_P12_PASSWORD is required." >&2
    exit 1
fi

project_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
output_dir="$project_root/.signing"
mkdir -p "$output_dir"
unzip -oq "$1" -d "$output_dir"

p12_file="$(find "$output_dir" -maxdepth 1 -type f -name '*.p12' -print -quit)"
profile_file="$(find "$output_dir" -maxdepth 1 -type f -name '*.mobileprovision' -print -quit)"
if [[ -z "$p12_file" || -z "$profile_file" ]]; then
    echo "The archive must contain one .p12 and one .mobileprovision file." >&2
    exit 1
fi

openssl pkcs12 -in "$p12_file" -passin "pass:$SIGNING_P12_PASSWORD" -clcerts -nokeys -legacy -out "$output_dir/signing-cert.pem"
security cms -D -i "$profile_file" > "$output_dir/profile.plist"

team_id="$(plutil -extract TeamIdentifier.0 raw -o - "$output_dir/profile.plist")"
app_id="$(plutil -extract Entitlements.application-identifier raw -o - "$output_dir/profile.plist")"
profile_name="$(plutil -extract Name raw -o - "$output_dir/profile.plist")"

echo "Signing assets imported to $output_dir"
echo "Team ID: $team_id"
echo "Application identifier: $app_id"
echo "Provisioning profile: $profile_name"
