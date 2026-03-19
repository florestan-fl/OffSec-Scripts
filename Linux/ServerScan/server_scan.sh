#!/bin/sh
# http_scan.sh — Basic HTTP server scanner
# Uses only: curl, grep, awk, sed, printf, echo (no external installs needed)

# ─── CONFIG ────────────────────────────────────────────────────────────────────
TARGET="${1:-http://localhost}"           # First argument or default
WORDLIST="${2:-}"                         # Optional second arg: path to endpoint wordlist
TIMEOUT=5                                 # Seconds per request
COMMON_METHODS="GET POST PUT DELETE PATCH OPTIONS HEAD"

# Strip trailing slash
TARGET="${TARGET%/}"

# ─── COLOURS (disabled if not a terminal) ──────────────────────────────────────
if [ -t 1 ]; then
  RED='\033[0;31m'; GRN='\033[0;32m'; YLW='\033[0;33m'
  BLU='\033[0;34m'; CYN='\033[0;36m'; RST='\033[0m'
else
  RED=''; GRN=''; YLW=''; BLU=''; CYN=''; RST=''
fi

# ─── HELPERS ───────────────────────────────────────────────────────────────────
color_status() {
  code="$1"
  case "$code" in
    2*) printf "${GRN}%s${RST}" "$code" ;;
    3*) printf "${CYN}%s${RST}" "$code" ;;
    4*) printf "${YLW}%s${RST}" "$code" ;;
    5*) printf "${RED}%s${RST}" "$code" ;;
    *)  printf "%s" "$code" ;;
  esac
}

separator() { printf '%0.s─' $(seq 1 60); printf '\n'; }

probe() {
  method="$1"; url="$2"
  # -s silent, -o /dev/null discard body, -w write status + size + content-type
  result=$(curl -s -o /dev/null \
    -m "$TIMEOUT" \
    -X "$method" \
    -w "%{http_code} %{size_download} %{content_type} %{redirect_url}" \
    -H "User-Agent: http_scan/1.0" \
    "$url" 2>/dev/null)
  echo "$result"
}

# ─── BANNER ────────────────────────────────────────────────────────────────────
printf "\n${BLU}══════════════════════════════════════════════════════════${RST}\n"
printf "${BLU}  HTTP Scanner${RST}\n"
printf "${BLU}  Target : ${RST}%s\n" "$TARGET"
printf "${BLU}  Date   : ${RST}%s\n" "$(date)"
printf "${BLU}══════════════════════════════════════════════════════════${RST}\n\n"

# ─── 1. SERVER INFO (HEAD on root) ─────────────────────────────────────────────
printf "${CYN}[1/4] Server headers${RST}\n"
separator
curl -s -I -m "$TIMEOUT" \
  -H "User-Agent: http_scan/1.0" \
  "$TARGET/" 2>/dev/null | grep -iE "^(HTTP|Server|X-Powered-By|Content-Type|Allow|Access-Control|X-Frame|Strict-Transport|Set-Cookie|Location):" \
  | while IFS= read -r line; do
      key=$(echo "$line" | cut -d: -f1)
      val=$(echo "$line" | cut -d: -f2-)
      printf "  ${YLW}%-30s${RST}:%s\n" "$key" "$val"
    done
printf "\n"

# ─── 2. HTTP METHOD TEST on root ───────────────────────────────────────────────
printf "${CYN}[2/4] HTTP method probe on /  ${RST}\n"
separator
printf "  %-10s %-6s %-10s %s\n" "METHOD" "CODE" "SIZE(B)" "Content-Type"
printf "  %-10s %-6s %-10s %s\n" "──────" "────" "───────" "────────────"
for method in $COMMON_METHODS; do
  res=$(probe "$method" "$TARGET/")
  code=$(echo "$res" | awk '{print $1}')
  size=$(echo "$res" | awk '{print $2}')
  ctype=$(echo "$res" | awk '{print $3}')
  [ "$code" = "000" ] && code="ERR"
  printf "  %-10s " "$method"
  color_status "$code"
  printf " %-10s %s\n" "$size" "$ctype"
done
printf "\n"

# ─── 3. COMMON ENDPOINT SCAN ───────────────────────────────────────────────────
printf "${CYN}[3/4] Common endpoint scan (GET)${RST}\n"
separator
printf "  %-35s %-6s %-10s\n" "ENDPOINT" "CODE" "SIZE(B)"
printf "  %-35s %-6s %-10s\n" "────────" "────" "───────"

# Built-in wordlist — extend as needed
BUILTIN_PATHS="
/
/api
/api/v1
/api/v2
/api/v3
/health
/healthz
/ping
/status
/metrics
/ready
/live
/version
/info
/docs
/swagger
/swagger.json
/swagger.yaml
/openapi.json
/openapi.yaml
/redoc
/graphql
/graphiql
/admin
/login
/logout
/auth
/oauth
/oauth/token
/token
/users
/user
/me
/profile
/register
/signup
/config
/settings
/env
/robots.txt
/sitemap.xml
/.well-known/openid-configuration
/.well-known/jwks.json
/actuator
/actuator/health
/actuator/info
/actuator/env
/debug
/console
/dashboard
/api/swagger.json
/api/docs
"

# If a custom wordlist file was provided, use it instead
if [ -n "$WORDLIST" ] && [ -f "$WORDLIST" ]; then
  PATHS=$(cat "$WORDLIST")
  printf "  ${YLW}(using custom wordlist: %s)${RST}\n\n" "$WORDLIST"
else
  PATHS="$BUILTIN_PATHS"
fi

echo "$PATHS" | while IFS= read -r path; do
  # skip blank lines
  [ -z "$path" ] && continue
  url="${TARGET}${path}"
  res=$(probe "GET" "$url")
  code=$(echo "$res" | awk '{print $1}')
  size=$(echo "$res" | awk '{print $2}')
  redirect=$(echo "$res" | awk '{print $4}')
  [ "$code" = "000" ] && continue   # skip connection errors silently
  # Only print interesting codes (not 404)
  case "$code" in
    404) continue ;;
  esac
  printf "  %-35s " "$path"
  color_status "$code"
  printf " %-10s" "$size"
  [ -n "$redirect" ] && printf " → %s" "$redirect"
  printf "\n"
done
printf "\n"

# ─── 4. SECURITY HEADER CHECK ──────────────────────────────────────────────────
printf "${CYN}[4/4] Security header check${RST}\n"
separator
HEADERS=$(curl -s -I -m "$TIMEOUT" -H "User-Agent: http_scan/1.0" "$TARGET/" 2>/dev/null)

check_header() {
  label="$1"; pattern="$2"
  if echo "$HEADERS" | grep -qi "$pattern"; then
    printf "  ${GRN}[✔]${RST} %s\n" "$label"
  else
    printf "  ${RED}[✘]${RST} %s — MISSING\n" "$label"
  fi
}

check_header "Strict-Transport-Security (HSTS)"  "Strict-Transport-Security"
check_header "Content-Security-Policy"            "Content-Security-Policy"
check_header "X-Frame-Options"                    "X-Frame-Options"
check_header "X-Content-Type-Options"             "X-Content-Type-Options"
check_header "Referrer-Policy"                    "Referrer-Policy"
check_header "Permissions-Policy"                 "Permissions-Policy"
check_header "Access-Control-Allow-Origin (CORS)" "Access-Control-Allow-Origin"

printf "\n${BLU}══════════════════════════════════════════════════════════${RST}\n"
printf "${BLU}  Scan complete.${RST}\n"
printf "${BLU}══════════════════════════════════════════════════════════${RST}\n\n"
