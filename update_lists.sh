#!/bin/bash

DIR="rules"
BLOCK_OUT="./$DIR/blocklists.txt"
ALLOW_OUT="./$DIR/allowlists.txt"
PRIVATE_TLDS_OUT="./$DIR/private_tlds.txt"
REDIRECT_RULES_OUT="./$DIR/redirect_rules.txt"
MULLVAD_UPSTREAM_OUT="./$DIR/mullvad_upstream.txt"

BLOCK_TMP="/tmp/blocklists.tmp"
ALLOW_TMP="/tmp/allowlists.tmp"
PRIVATE_TLDS_TMP="/tmp/private_tlds.tmp"
REDIRECT_RULES_TMP="/tmp/redirect_rules.tmp"
MULLVAD_UPSTREAM_TMP="/tmp/mullvad_upstream.tmp"

mkdir -p "./$DIR"

trap "rm -f $BLOCK_TMP $ALLOW_TMP $PRIVATE_TLDS_TMP $REDIRECT_RULES_TMP $MULLVAD_UPSTREAM_TMP; exit 1" INT TERM

extract_domains() {
  awk '{
    if (/^[[:space:]]*$/ || /^[!#]/) next
    line = tolower($0)
    sub(/^@@\|\|?/, "", line)
    sub(/^\|\|?/, "", line)
    sub(/\^.*/, "", line)
    sub(/[#!].*/, "", line)
    sub(/\/.*/, "", line)
    sub(/:.*/, "", line)
    sub(/^[0-9.]+[[:space:]]+/, "", line)
    gsub(/^[[:space:]]+|[[:space:]]+$/, "", line)
    if (line ~ /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$/ && !seen[line]++) print line
  }'
}

extract_redirect_rules() {
  awk '{
    if (/^[[:space:]]*$/ || /^[!#]/) next
    line = tolower($0)
    gsub(/^[[:space:]]+|[[:space:]]+$/, "", line)
    n = split(line, parts, /[[:space:]]+/)
    if (n == 2) {
      if (parts[1] ~ /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$/ &&
          parts[2] ~ /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$/) {
        print parts[1] " " parts[2]
      }
    }
  }'
}

echo "================================"
echo "🔄 DNS Lists Update Script"
echo "================================"
echo ""

echo "📥 Downloading and processing blocklists..."
if ! curl -fsSL --max-time 60 \
https://raw.githubusercontent.com/bibicadotnet/blocklist_minimal/main/blocklists.txt \
| extract_domains > "$BLOCK_TMP"; then
  echo "❌ ERROR: Failed to download blocklists"
  exit 1
fi

if [ ! -s "$BLOCK_TMP" ]; then
  echo "❌ ERROR: Blocklist is empty or invalid"
  exit 1
fi

echo "📥 Downloading and processing allowlists..."
ALLOW_DOWNLOADED=false

if curl -fsSL --max-time 60 \
https://raw.githubusercontent.com/anudeepND/whitelist/master/domains/whitelist.txt \
| extract_domains >> "$ALLOW_TMP" 2>/dev/null; then
  echo "  ✓ anudeepND whitelist downloaded"
  ALLOW_DOWNLOADED=true
fi

if curl -fsSL --max-time 60 \
https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/SpywareFilter/sections/tracking_servers.txt \
| extract_domains >> "$ALLOW_TMP" 2>/dev/null; then
  echo "  ✓ AdGuard tracking servers downloaded"
  ALLOW_DOWNLOADED=true
fi

if [ "$ALLOW_DOWNLOADED" = false ] || [ ! -s "$ALLOW_TMP" ]; then
  echo "⚠️ WARNING: Could not download allowlists, using minimal defaults"
  cat > "$ALLOW_TMP" << 'EOF'
google.com
youtube.com
github.com
stackoverflow.com
cloudflare.com
microsoft.com
apple.com
amazon.com
EOF
fi

sort -u "$ALLOW_TMP" -o "$ALLOW_TMP"

echo "📥 Downloading and processing private TLDs..."
if ! curl -fsSL --max-time 60 \
https://data.iana.org/TLD/tlds-alpha-by-domain.txt \
| extract_domains > "$PRIVATE_TLDS_TMP" 2>/dev/null; then
  echo "⚠️ WARNING: Failed to download IANA TLD list, using defaults"
  cat > "$PRIVATE_TLDS_TMP" << 'EOF'
local
localhost
internal
intranet
test
invalid
example
lan
home
localdomain
EOF
fi

cat >> "$PRIVATE_TLDS_TMP" << 'EOF'
.local
.internal
.test
.lan
.home
.intranet
.localnetwork
.local.arpa
.corp
.internal.corp
router
gateway
nas
server
media
EOF

extract_domains < "$PRIVATE_TLDS_TMP" | sort -u > "$PRIVATE_TLDS_TMP.sorted"
mv "$PRIVATE_TLDS_TMP.sorted" "$PRIVATE_TLDS_TMP"

echo "📥 Downloading and processing DNS redirect rules..."
cat > "$REDIRECT_RULES_TMP" << 'EOF'
# DNS Redirect Rules - Format: source-domain target-domain
# Example: www.example.com www.example.com.edge.cloudfront.net
# Uncomment and modify as needed for your needs

# Bilibili optimization
# www.bilibili.com www.bilibili.com.w.cdngslb.com

# Add your custom redirects below:
EOF

if curl -fsSL --max-time 30 \
https://raw.githubusercontent.com/basingwaebasing-hash/dns-redirect-rules/main/redirect_rules.txt \
>> "$REDIRECT_RULES_TMP" 2>/dev/null; then
  echo "✓ Custom redirect rules downloaded"
else
  echo "ℹ️ No custom redirect rules found (optional)"
fi

extract_redirect_rules < "$REDIRECT_RULES_TMP" > "$REDIRECT_RULES_TMP.clean"
mv "$REDIRECT_RULES_TMP.clean" "$REDIRECT_RULES_TMP"

echo "📥 Downloading and processing Mullvad upstream domains..."
cat > "$MULLVAD_UPSTREAM_TMP" << 'EOF'
# Domains that should use Mullvad DNS for geo-bypass
# These are domains commonly geo-blocked or requiring privacy-first resolution

# Streaming services often geo-block
bbc.co.uk
netflix.com
disneyplus.com

# News sites
bbc.com
cnn.com
aljazeera.com

# Social media (privacy-first)
twitter.com
facebook.com
instagram.com

# Torrenting & P2P
thepiratebay.org

# Add your custom Mullvad domains below:
EOF

if curl -fsSL --max-time 30 \
https://raw.githubusercontent.com/basingwaebasing-hash/mullvad-domains/main/mullvad_upstream.txt \
>> "$MULLVAD_UPSTREAM_TMP" 2>/dev/null; then
  echo "✓ Custom Mullvad domains downloaded"
else
  echo "ℹ️ Using default Mullvad domains"
fi

extract_domains < "$MULLVAD_UPSTREAM_TMP" | sort -u > "$MULLVAD_UPSTREAM_TMP.clean"
mv "$MULLVAD_UPSTREAM_TMP.clean" "$MULLVAD_UPSTREAM_TMP"

echo ""
echo "💾 Finalizing files..."
mv "$BLOCK_TMP" "$BLOCK_OUT"
mv "$ALLOW_TMP" "$ALLOW_OUT"
mv "$PRIVATE_TLDS_TMP" "$PRIVATE_TLDS_OUT"
mv "$REDIRECT_RULES_TMP" "$REDIRECT_RULES_OUT"
mv "$MULLVAD_UPSTREAM_TMP" "$MULLVAD_UPSTREAM_OUT"

echo ""
echo "================================"
echo "✅ All Lists Downloaded & Processed"
echo "================================"

BLOCK_SIZE=$(wc -l < "$BLOCK_OUT")
ALLOW_SIZE=$(wc -l < "$ALLOW_OUT")
PRIVATE_TLDS_SIZE=$(wc -l < "$PRIVATE_TLDS_OUT")
REDIRECT_RULES_SIZE=$(grep -v "^#" "$REDIRECT_RULES_OUT" | grep -v "^$" | wc -l)
MULLVAD_UPSTREAM_SIZE=$(wc -l < "$MULLVAD_UPSTREAM_OUT")

echo ""
echo "📊 Statistics:"
echo "  🚫 Blocklist:        $BLOCK_SIZE domains"
echo "  ✅ Allowlist:        $ALLOW_SIZE domains"
echo "  🔐 Private TLDs:     $PRIVATE_TLDS_SIZE domains"
echo "  🔄 Redirect Rules:   $REDIRECT_RULES_SIZE rules"
echo "  🕵️ Mullvad Domains:  $MULLVAD_UPSTREAM_SIZE domains"
echo ""

ERRORS=0

if [ "$BLOCK_SIZE" -lt 1000 ]; then
  echo "⚠️ WARNING: Blocklist only has $BLOCK_SIZE domains (expected >1000)"
  ((ERRORS++))
fi

if [ "$ALLOW_SIZE" -lt 10 ]; then
  echo "⚠️ WARNING: Allowlist only has $ALLOW_SIZE domains (expected >10)"
  ((ERRORS++))
fi

if [ "$PRIVATE_TLDS_SIZE" -lt 10 ]; then
  echo "⚠️ WARNING: Private TLDs only has $PRIVATE_TLDS_SIZE entries (expected >10)"
  ((ERRORS++))
fi

if [ "$REDIRECT_RULES_SIZE" -eq 0 ]; then
  echo "ℹ️ INFO: No redirect rules configured (optional)"
fi

if [ "$MULLVAD_UPSTREAM_SIZE" -eq 0 ]; then
  echo "ℹ️ INFO: No Mullvad upstream domains configured (optional)"
fi

echo ""
echo "📁 Files saved to:"
echo "  ✓ $BLOCK_OUT"
echo "  ✓ $ALLOW_OUT"
echo "  ✓ $PRIVATE_TLDS_OUT"
echo "  ✓ $REDIRECT_RULES_OUT"
echo "  ✓ $MULLVAD_UPSTREAM_OUT"
echo ""
echo "⏰ Updated: $(date -u +'%Y-%m-%d %H:%M:%S UTC')"
echo ""

rm -f $BLOCK_TMP $ALLOW_TMP $PRIVATE_TLDS_TMP $REDIRECT_RULES_TMP $MULLVAD_UPSTREAM_TMP

if [ $ERRORS -gt 0 ]; then
  echo "⚠️ Script completed with $ERRORS warning(s)"
  exit 1
else
  echo "✅ All checks passed! Script completed successfully."
  exit 0
fi
