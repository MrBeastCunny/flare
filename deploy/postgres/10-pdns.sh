#!/bin/sh
# Creates the PowerDNS database and role, then loads the gpgsql schema.
# Runs once, on first initialization of the Postgres data directory.
set -eu

: "${PDNS_DB_NAME:=pdns}"
: "${PDNS_DB_USER:=pdns}"
: "${PDNS_DB_PASSWORD:?PDNS_DB_PASSWORD must be set}"

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<-SQL
	CREATE ROLE "${PDNS_DB_USER}" LOGIN PASSWORD '${PDNS_DB_PASSWORD}';
	CREATE DATABASE "${PDNS_DB_NAME}" OWNER "${PDNS_DB_USER}";
SQL

PGPASSWORD="$PDNS_DB_PASSWORD" psql -v ON_ERROR_STOP=1 --username "$PDNS_DB_USER" --dbname "$PDNS_DB_NAME" \
	-f /docker-entrypoint-initdb.d/pdns-schema.sql.inc
