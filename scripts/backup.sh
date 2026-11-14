#!/usr/bin/env bash
set -euo pipefail

PROJECT=osv-honeypot
REPO_DIR=$(cd "$(dirname "$0")/.." && pwd)
BACKUP_DIR=/var/backups/osv-honeypot
KEEP_DAYS=7
VOLUMES="grafana-data crowdsec-db crowdsec-config cowrie-log webtrap-log"
STAMP=$(date +%Y-%m-%d_%H%M)
ARCHIVE="$BACKUP_DIR/backup_${STAMP}.tar"
COMPOSE="docker compose -f $REPO_DIR/docker-compose.yml"

TOKEN=$(grep '^TELEGRAM_BOT_TOKEN=' "$REPO_DIR/.env" | cut -d= -f2-)
CHAT=$(grep '^TELEGRAM_CHAT_ID=' "$REPO_DIR/.env" | cut -d= -f2-)

notify() {
  curl -s -o /dev/null "https://api.telegram.org/bot${TOKEN}/sendMessage" \
    -d chat_id="$CHAT" --data-urlencode text="$1" || true
}

TMP=$(mktemp -d)
cleanup() {
  $COMPOSE start grafana crowdsec >/dev/null 2>&1 || true
  rm -rf "$TMP"
}
trap cleanup EXIT
trap 'notify "Záloha zlyhala ($(hostname), $STAMP)"' ERR

mkdir -p "$BACKUP_DIR"
$COMPOSE stop grafana crowdsec

for v in $VOLUMES; do
  docker run --rm -v "${PROJECT}_${v}:/data:ro" -v "$TMP:/backup" alpine \
    tar czf "/backup/${v}.tar.gz" -C /data .
done

$COMPOSE start grafana crowdsec
cp "$REPO_DIR/.env" "$TMP/env.backup"
tar cf "$ARCHIVE" -C "$TMP" .
chmod 600 "$ARCHIVE"
find "$BACKUP_DIR" -name 'backup_*.tar' -mtime +"$KEEP_DAYS" -delete

SIZE=$(du -h "$ARCHIVE" | cut -f1)
COUNT=$(find "$BACKUP_DIR" -name 'backup_*.tar' | wc -l)
echo "Backup OK: $ARCHIVE ($SIZE)"
notify "Záloha OK: $SIZE, uložených záloh: $COUNT"
