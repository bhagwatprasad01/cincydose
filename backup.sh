#!/bin/sh
# Back up the CincyDose account database. Run nightly from cron on the host, e.g.:
#   0 2 * * * cd /opt/cincydose && ./backup.sh /opt/cincydose-backups
set -e
DEST=${1:-./backups}; mkdir -p "$DEST"
STAMP=$(date +%Y%m%d-%H%M)
docker compose exec -T app node --no-warnings -e "const {DatabaseSync}=require('node:sqlite');new DatabaseSync('/data/cincydose.db').exec(\"VACUUM INTO '/data/backup.db'\")"
docker compose cp app:/data/backup.db "$DEST/cincydose-$STAMP.db"
docker compose exec -T app rm -f /data/backup.db
find "$DEST" -name 'cincydose-*.db' -mtime +30 -delete
echo "Saved $DEST/cincydose-$STAMP.db"
