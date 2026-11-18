#!/usr/bin/env bash
# Copia de seguridad de PostgreSQL. La ejecuta cada noche mini-siem-backup.timer.
#
# Restaurar (con la app parada para que no escriba mientras tanto):
#   docker compose stop app
#   gunzip -c /var/backups/mini-siem/siem-<fecha>.sql.gz | docker compose exec -T postgres psql -U siem -d siem
#   docker compose start app
#
# Las copias quedan en el mismo VPS: protegen de un error (un DELETE de más, una
# migración rota), no de perder el servidor. Para eso, cópialas fuera (rclone, scp) o
# activa los snapshots del proveedor.
set -euo pipefail

BACKUP_DIR=${BACKUP_DIR:-/var/backups/mini-siem}
KEEP_DAYS=${KEEP_DAYS:-14}

cd "$(dirname "$0")"
umask 077 # los volcados tienen todos los eventos: solo los lee el dueño
mkdir -p "$BACKUP_DIR"

FILE="$BACKUP_DIR/siem-$(date -u +%Y%m%dT%H%M%SZ).sql.gz"
# --clean --if-exists: el volcado borra las tablas antes de crearlas, así que se puede
# restaurar sobre una base que ya tiene datos.
docker compose exec -T postgres pg_dump -U siem -d siem --clean --if-exists --no-owner | gzip >"$FILE.tmp"
# Se escribe en .tmp y se renombra al final: un volcado a medias nunca parece válido.
mv "$FILE.tmp" "$FILE"
echo "copia creada: $FILE ($(du -h "$FILE" | cut -f1))"

find "$BACKUP_DIR" -name 'siem-*.sql.gz' -mtime +"$KEEP_DAYS" -print -delete
