#!/bin/sh
# Nightly logical backups of the Flare and PowerDNS databases.
# Dumps are written to /backups and pruned after BACKUP_RETENTION_DAYS.
set -eu
: "${BACKUP_INTERVAL_SECONDS:=86400}"
: "${BACKUP_RETENTION_DAYS:=14}"
export PGHOST=postgres PGUSER="$POSTGRES_USER" PGPASSWORD="$POSTGRES_PASSWORD"

until pg_isready -q; do sleep 2; done
while true; do
	ts=$(date -u +%Y%m%dT%H%M%SZ)
	for db in "$POSTGRES_DB" "$PDNS_DB_NAME"; do
		out="/backups/${db}-${ts}.dump"
		if pg_dump --format=custom --no-owner --dbname="$db" --file="${out}.partial"; then
			mv "${out}.partial" "$out"
			echo "backup ok: $out"
		else
			rm -f "${out}.partial"
			echo "backup FAILED: $db" >&2
		fi
	done
	find /backups -name '*.dump' -mtime +"$BACKUP_RETENTION_DAYS" -delete
	sleep "$BACKUP_INTERVAL_SECONDS"
done
