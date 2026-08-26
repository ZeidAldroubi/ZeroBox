#!/usr/bin/env sh
set -eu

BASE=${BASE:-http://localhost:8080}
MINIO_ENDPOINT=${MINIO_ENDPOINT:-http://localhost:9000}
MINIO_DOCKER_ENDPOINT=${MINIO_DOCKER_ENDPOINT:-http://minio:9000}
MINIO_USER=${MINIO_USER:-zerobox}
MINIO_PASSWORD=${MINIO_PASSWORD:-zeroboxsecret}
COOKIE_JAR=${TMPDIR:-/tmp}/zerobox-attack-cookies.$$
BODY_FILE=${TMPDIR:-/tmp}/zerobox-attack-body.$$
BIG_FILE=${TMPDIR:-/tmp}/zerobox-attack-big.$$
trap 'rm -f "$COOKIE_JAR" "$BODY_FILE" "$BIG_FILE"' EXIT

pass() { printf 'PASS %s\n' "$1"; }
fail() { printf 'FAIL %s: %s\n' "$1" "${2:-unexpected response}" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || fail prerequisites "$1 is required"; }
need curl
need jq

health=$(curl -fsS "$BASE/health") || fail health "server is not reachable"
[ "$(printf '%s' "$health" | jq -r '.status')" = ok ] || fail health
pass health

username="attack_$(date +%s)_$$"
password='correct horse battery staple'
sql_payload=$(printf '{"username":"%s","password":"wrongpass"}' "' OR '1'='1' --")
sql_response=$(curl -sS -w '\n%{http_code}' -X POST "$BASE/login" -H 'Content-Type: application/json' -d "$sql_payload")
sql_code=$(printf '%s' "$sql_response" | tail -n 1)
sql_body=$(printf '%s' "$sql_response" | sed '$d')
[ "$sql_code" = 401 ] && ! printf '%s' "$sql_body" | grep -Eiq 'sql|syntax|postgres|database' || fail sql-injection
pass sql-injection

traversal_code=$(curl --path-as-is -sS -o /dev/null -w '%{http_code}' -H 'Authorization: Bearer malformed' "$BASE/files/..%2F..%2Fetc%2Fpasswd")
[ "$traversal_code" = 400 ] || [ "$traversal_code" = 401 ] || [ "$traversal_code" = 404 ] || fail path-traversal "$traversal_code"
pass path-traversal

register_code=$(curl -sS -o /dev/null -w '%{http_code}' -X POST "$BASE/register" -H 'Content-Type: application/json' -d "$(printf '{"username":"%s","password":"%s"}' "$username" "$password")")
[ "$register_code" = 201 ] || fail registration "$register_code"
login_headers=$(curl -sS -D - -o "$BODY_FILE" -c "$COOKIE_JAR" -X POST "$BASE/login" -H 'Content-Type: application/json' -d "$(printf '{"username":"%s","password":"%s"}' "$username" "$password")")
login_code=$(printf '%s' "$login_headers" | awk 'toupper($1) ~ /^HTTP\// { code=$2 } END { print code }')
[ "$login_code" = 200 ] || fail login "$login_code"
token=$(jq -r '.access_token' "$BODY_FILE")
[ -n "$token" ] && [ "$token" != null ] || fail login "missing access token"
pass login

for i in $(seq 1 20); do
  code=$(curl -sS -o /dev/null -w '%{http_code}' -X POST "$BASE/login" -H 'Content-Type: application/json' -d '{"username":"unknown-attack-user","password":"wrongpass"}')
  [ "$code" = 429 ] && break
done
[ "$code" = 429 ] || fail rate-limit "$code"
pass rate-limit

invalid_code=$(curl -sS -o /dev/null -w '%{http_code}' -H 'Authorization: Bearer malformed' "$BASE/files")
[ "$invalid_code" = 401 ] || fail invalid-token "$invalid_code"
pass invalid-token

nonce='000102030405060708090a0b'
tag='000102030405060708090a0b0c0d0e0f'
ciphertext=$(printf 'zerobox attack fixture' | od -An -tx1 | tr -d ' \n')
filename=$(printf 'fixture.txt' | od -An -tx1 | tr -d ' \n')
filename_nonce='101112131415161718191a1b'
payload=$(printf '{"ciphertext":"%s","auth_tag":"%s","nonce":"%s","encrypted_filename":"%s","filename_nonce":"%s"}' "$ciphertext" "$tag" "$nonce" "$filename$tag" "$filename_nonce")
upload_response=$(curl -sS -w '\n%{http_code}' -b "$COOKIE_JAR" -H "Authorization: Bearer $token" -H 'Content-Type: application/json' -X POST "$BASE/files" -d "$payload")
upload_code=$(printf '%s' "$upload_response" | tail -n 1)
upload_body=$(printf '%s' "$upload_response" | sed '$d')
[ "$upload_code" = 201 ] || fail upload "$upload_code $upload_body"
file_id=$(printf '%s' "$upload_body" | jq -r '.id')
pass upload

replay_code=$(curl -sS -o /dev/null -w '%{http_code}' -b "$COOKIE_JAR" -H "Authorization: Bearer $token" -H 'Content-Type: application/json' -X POST "$BASE/files" -d "$payload")
[ "$replay_code" = 409 ] || fail replay "$replay_code"
pass replay

printf '{"ciphertext":"' > "$BIG_FILE"
dd if=/dev/zero bs=1048576 count=101 2>/dev/null | od -An -tx1 | tr -d ' \n' >> "$BIG_FILE"
printf '"}' >> "$BIG_FILE"
large_code=$(curl -sS -o /dev/null -w '%{http_code}' -b "$COOKIE_JAR" -H "Authorization: Bearer $token" -H 'Content-Type: application/json' -X POST "$BASE/files" --data-binary "@$BIG_FILE")
[ "$large_code" = 400 ] || fail oversized-upload "$large_code"
pass oversized-upload

origin_code=$(curl -sS -o /dev/null -w '%{http_code}' -X OPTIONS "$BASE/health" -H 'Origin: http://evil.example' -H 'Access-Control-Request-Method: GET')
[ "$origin_code" = 403 ] || fail cors "$origin_code"
pass cors

download_response=$(curl -sS -b "$COOKIE_JAR" -H "Authorization: Bearer $token" "$BASE/files/$file_id")
printf '%s' "$download_response" | jq -e '.ciphertext and .auth_tag and .nonce' >/dev/null || fail tamper "download fixture unavailable"
storage_key=$(docker compose exec -T postgres psql -U zerobox -d zerobox -Atc "SELECT storage_key FROM files WHERE id='$file_id';" 2>/dev/null | tr -d '\r')
[ -n "$storage_key" ] || fail tamper "could not locate storage key"
docker run --rm --network zerobox_default minio/mc:latest sh -c "mc alias set local $MINIO_DOCKER_ENDPOINT $MINIO_USER $MINIO_PASSWORD >/dev/null && mc cp local/zerobox/$storage_key /tmp/blob && printf X | dd of=/tmp/blob bs=1 seek=0 conv=notrunc 2>/dev/null && mc cp /tmp/blob local/zerobox/$storage_key >/dev/null" >/dev/null 2>&1 || fail tamper "MinIO mutation failed"
tamper_response=$(curl -sS -o /dev/null -w '%{http_code}' -b "$COOKIE_JAR" -H "Authorization: Bearer $token" "$BASE/files/$file_id")
[ "$tamper_response" = 409 ] || fail tamper "$tamper_response"
pass tamper

printf 'PASS all required black-box checks\n'
