#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'HELP'
Usage: ./start.sh --domain support.example.com [options]

  --domain NAME          Public DNS name (automatic Let's Encrypt by default)
  --bind ADDRESS         Host IPv4/IPv6 address to bind (default: 0.0.0.0)
  --port PORT            Host HTTPS port (default: 8443)
  --origin HTTPS_ORIGIN  Exact public origin, if different from domain:port
  --email ADDRESS        Optional ACME account email
  --acme-directory URL   Use another HTTPS ACME directory
  --http-port PORT       Host HTTP challenge port (default: 80; 0 disables it)
  --certbot-dir DIRECTORY Default certificate search tree (default: /etc/letsencrypt)
  --cert-dir DIRECTORY   Mount a certificate tree read-only; defaults to
                         fullchain.pem and privkey.pem inside this directory
  --tls-cert FILE        PEM certificate chain (relative to --cert-dir if set)
  --tls-key FILE         PEM private key (relative to --cert-dir if set)
  --no-build             Reuse the existing Docker image
  --help                 Show these instructions

Existing Certbot and application-cache certificates are checked before issuance.
Manual certificates require --domain or --origin; no ACME port is published.
Certificate files must be readable by container UID/GID 65532. Mount the whole
certificate tree with --cert-dir when renewal uses symlinks across folders.

Builds and checks configuration before stopping the previous server. Prepares
first-time passkey setup if needed, then starts it. Existing data and passkeys
are retained. No .env file is read or written. Rerunning ends active sessions.
HELP
}
die() { printf 'Error: %s\n' "$*" >&2; exit 1; }
domain='' bind='0.0.0.0' port='8443' origin='' email='' directory='' http_port='80'
cert_dir='' cert='' key='' no_build=false http_explicit=false certbot_dir='/etc/letsencrypt' cached=false discovered=false
while (($#)); do
  case "$1" in
    --help|-h) usage; exit 0 ;;
    --no-build) no_build=true; shift ;;
    --domain|--bind|--port|--origin|--email|--acme-directory|--http-port|--cert-dir|--certbot-dir|--tls-cert|--tls-key)
      (($# >= 2)) && [[ -n "$2" && "$2" != --* ]] || die "Missing value for $1"
      [[ "$2" != *[$'\001'-$'\037']* ]] || die 'Arguments cannot contain control characters.'
      case "$1" in
        --domain) domain="${2,,}" ;; --bind) bind="$2" ;;
        --port) port="$2" ;; --origin) origin="$2" ;; --email) email="$2" ;;
        --acme-directory) directory="$2" ;; --http-port) http_port="$2"; http_explicit=true ;;
        --cert-dir) cert_dir="$2" ;; --certbot-dir) certbot_dir="$2" ;; --tls-cert) cert="$2" ;; --tls-key) key="$2" ;;
      esac
      shift 2 ;;
    *) die "Unknown argument: $1 (use --help)" ;;
  esac
done
port_number() {
  [[ "$2" =~ ^[0-9]{1,5}$ ]] || die "$1 must be a numeric port."
  local number=$((10#$2))
  ((number >= $3 && number <= 65535)) || die "$1 must be $3–65535."
  printf '%s' "$number"
}
port=$(port_number --port "$port" 1)
http_port=$(port_number --http-port "$http_port" 0)
[[ "$bind" =~ ^[0-9a-fA-F:.]+$ ]] || die '--bind must be an IPv4 or IPv6 address.'
[[ -n "$domain" || -n "$origin" ]] || die 'Supply --domain, or --origin with manual certificates.'
if [[ -n "$domain" ]]; then
  [[ ${#domain} -le 253 && "$domain" == *.* && "$domain" != *. && "$domain" =~ ^[a-z0-9.-]+$ ]] || die '--domain must be a DNS name without a scheme or port.'
  IFS='.' read -r -a labels <<< "$domain"
  for label in "${labels[@]}"; do
    [[ ${#label} -ge 1 && ${#label} -le 63 && "$label" != -* && "$label" != *- ]] || die 'Invalid domain label.'
  done
fi
if [[ -z "$origin" ]]; then
  origin="https://$domain"
  if [[ "$port" != 443 ]]; then origin+=":$port"; fi
fi
[[ "$origin" == https://* ]] || die '--origin must be an HTTPS origin.'
# Prefer an existing standard Certbot deployment before enabling built-in ACME.
# Explicit certificate/issuer/challenge options override automatic discovery.
requested_email="$email"
if [[ -n "$domain" && -z "$cert_dir$cert$key$directory" && "$http_explicit" == false && -d "$certbot_dir/live/$domain" ]]; then
  [[ -f "$certbot_dir/live/$domain/fullchain.pem" && -f "$certbot_dir/live/$domain/privkey.pem" ]] || die 'Found a Certbot directory but its certificate/key are missing or inaccessible. Check permissions or choose explicit certificate/ACME settings.'
  cert_dir="$certbot_dir"; cert="live/$domain/fullchain.pem"; key="live/$domain/privkey.pem"; discovered=true; email=''
fi
manual=false
if [[ -n "$cert_dir" || -n "$cert" || -n "$key" ]]; then
  manual=true
  [[ -z "$email" && -z "$directory" && "$http_explicit" == false ]] || die 'Do not combine supplied certificates with ACME options.'
  if [[ -n "$cert_dir" ]]; then
    cert_dir=$(cd -- "$cert_dir" && pwd -P) || die 'Certificate directory does not exist.'
    [[ "$cert_dir" != / ]] || die 'Use a dedicated certificate directory, not the filesystem root.'
    cert=${cert:-fullchain.pem}; key=${key:-privkey.pem}
    [[ "$cert" != /* && "$key" != /* && "/$cert/" != *'/../'* && "/$key/" != *'/../'* ]] || die 'With --cert-dir, certificate/key paths must stay relative to that directory.'
    [[ -f "$cert_dir/$cert" && -f "$cert_dir/$key" ]] || die 'Certificate or key file is missing.'
    container_cert="/certs/tree/$cert"; container_key="/certs/tree/$key"
  else
    [[ -n "$cert" && -n "$key" && -f "$cert" && -f "$key" ]] || die 'Supply both existing --tls-cert and --tls-key files.'
    cert_parent=$(cd -- "$(dirname -- "$cert")" && pwd -P)
    key_parent=$(cd -- "$(dirname -- "$key")" && pwd -P)
    [[ "$cert_parent" != / && "$key_parent" != / ]] || die 'Keep certificate files in a dedicated directory.'
    container_cert="/certs/certificate/$(basename -- "$cert")"
    container_key="/certs/key/$(basename -- "$key")"
  fi
else
  [[ -n "$domain" ]] || die 'Automatic certificates require --domain.'
  ((http_port == 0 || http_port != port)) || die 'HTTPS and HTTP challenge ports must differ.'
fi
command -v docker >/dev/null || die 'Install Docker with Docker Compose first.'
docker compose version >/dev/null || die 'Docker Compose is required.'
project_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
configuration=$(mktemp "${TMPDIR:-/tmp}/rmm-start.XXXXXXXX.json")
trap 'rm -f -- "$configuration"' EXIT
# Compose interpolates dollar signs even in JSON string values. Escape those as
# well as JSON quoting, so paths containing spaces, quotes or $ remain literal.
quote() {
  local value="$1"
  value=${value//\\/\\\\}; value=${value//\"/\\\"}; value=${value//\$/\$\$}
  printf '"%s"' "$value"
}
array() {
  local separator='' item
  printf '['
  for item in "$@"; do printf '%s' "$separator"; quote "$item"; separator=','; done
  printf ']'
}
mount() {
  printf '{"type":"bind","source":'; quote "$1"
  printf ',"target":'; quote "$2"
  printf ',"read_only":true,"bind":{"create_host_path":false}}'
}
settings=(--origin "$origin")
if [[ -n "$domain" ]]; then settings+=(--domain "$domain"); fi
if $manual; then
  settings+=(--tls-cert "$container_cert" --tls-key "$container_key")
else
  settings+=(--acme-email "$email" --acme-directory "$directory")
fi
challenge_listen=''
if ! $manual && ((http_port != 0)); then challenge_listen=':8080'; fi
write_configuration() {
  printf '{"services":{"rmm":{"command":'
  array serve "${settings[@]}" --data-dir /data --listen :8443 --acme-listen "$challenge_listen" --agent-exe /app/agent.exe
  printf ',"ports":[{"target":8443,"published":"%s","host_ip":' "$port"; quote "$bind"; printf '}'
  if ! $manual && ((http_port != 0)); then
    printf ',{"target":8080,"published":"%s","host_ip":' "$http_port"; quote "$bind"; printf '}'
  fi
  printf ']'
  if $manual; then
    printf ',"volumes":['
    if [[ -n "$cert_dir" ]]; then mount "$cert_dir" /certs/tree
    else mount "$cert_parent" /certs/certificate; printf ','; mount "$key_parent" /certs/key; fi
    printf ']'
  fi
  printf '}}}\n'
}
write_configuration > "$configuration"
compose=(docker compose --env-file /dev/null --project-directory "$project_dir" -f "$project_dir/compose.base.yaml" -f "$configuration")
"${compose[@]}" config --quiet
if ! $no_build; then "${compose[@]}" build; fi
check_listen="$bind:$port"
if [[ "$bind" == *:* ]]; then check_listen="[$bind]:$port"; fi
# Runs as the same unprivileged user with the same mounts. This catches invalid
# binds, origins, certificates and key permissions before stopping the live app.
if ! check_output=$("${compose[@]}" run --rm --no-deps rmm check "${settings[@]}" --listen "$check_listen" --data-dir /tmp/rmm-check 2>&1); then
  printf '%s\n' "$check_output" >&2
  if ! $discovered; then die 'Configuration check failed; the existing server was not stopped.'; fi
  if [[ "$check_output" == *'open /certs/tree/'* && "$check_output" == *'permission denied'* ]]; then
    die 'The existing Certbot certificate is unreadable by container UID 65532. Give that user read access to the certificate/key, or copy them to a protected directory and use --cert-dir. The existing server was not stopped.'
  fi
  printf 'The discovered certificate is not usable; checking built-in ACME configuration instead.\n'
  manual=false; discovered=false; email="$requested_email"
  settings=(--origin "$origin" --domain "$domain" --acme-email "$email" --acme-directory "$directory")
  ((http_port == 0 || http_port != port)) || die 'HTTPS and HTTP challenge ports must differ.'
  challenge_listen=':8080'
  write_configuration > "$configuration"
  "${compose[@]}" config --quiet
  "${compose[@]}" run --rm --no-deps rmm check "${settings[@]}" --listen "$check_listen" --data-dir /tmp/rmm-check
fi
if ! $manual && ! $http_explicit; then
  if "${compose[@]}" run --rm --no-deps rmm check "${settings[@]}" --listen "$check_listen" --data-dir /data --cached-only >/dev/null 2>&1; then
    cached=true; http_port=0; challenge_listen=''
    write_configuration > "$configuration"
    "${compose[@]}" config --quiet
  fi
fi
"${compose[@]}" stop rmm
setup_output=$("${compose[@]}" run --rm --no-deps rmm bootstrap --data-dir /data --if-needed --show-token)
launch_time=$(date -u +%Y-%m-%dT%H:%M:%S.%NZ)
"${compose[@]}" up -d --no-build
container=$("${compose[@]}" ps -q rmm)
[[ -n "$container" ]] || die 'Docker Compose did not return a running container. Check docker compose ps and logs.'
ready=false
for ((attempt=0; attempt<60; attempt++)); do
  if ! recent_logs=$(docker logs --since "$launch_time" "$container" 2>&1); then
    printf '%s\n' "$recent_logs" >&2
    die 'Unable to read the server startup logs.'
  fi
  if [[ "$recent_logs" == *'operator console listening'* ]]; then ready=true; break; fi
  if [[ "$recent_logs" == *'ERROR server stopped'* ]]; then
    printf '%s\n' "$recent_logs" >&2
    die 'The server stopped during startup. Fix the logged error, then rerun start.sh.'
  fi
  status=$(docker inspect -f '{{.State.Status}}' "$container")
  if [[ "$status" != running && "$status" != restarting ]]; then
    printf '%s\n' "$recent_logs" >&2
    die "The server container is $status. Check its logs and rerun start.sh."
  fi
  sleep 2
done
if ! $ready; then
  printf '%s\n' "$recent_logs" >&2
  die 'The server did not become ready within two minutes. Check certificate challenge routing and container logs.'
fi
printf '\n%s\n\nAdmin console: %s/admin\nFamily help page: %s/\n' "$setup_output" "$origin" "$origin"
printf 'Container: %s\nView logs: docker logs --tail=50 %s\n' "$container" "$container"
if $discovered; then printf 'Using the existing certificate from %s/live/%s/.\n' "$certbot_dir" "$domain"; fi
if $cached; then printf 'Valid cached certificate found: no HTTP challenge port is published. HTTP-01 renewal needs a rerun with --http-port 80 (or forwarded challenge port); TLS-ALPN renewal needs public 443.\n'; fi
if $manual; then printf 'Using supplied certificates; renewed files reload on new TLS handshakes.\n'
else printf 'Automatic certificate provisioning continues at startup. Check the container logs if HTTPS is not ready yet.\n'; fi
printf 'Settings persist in the container; server data stays in the Docker volume.\n'
