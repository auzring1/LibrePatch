#!/bin/sh
# Wraps the official PostgreSQL entrypoint (decision D109). On the very first start it creates the database passwords, so
# nobody has to run a script beforehand; on every start it makes sure the connection strings the server and the
# maintenance service read match those passwords. It never replaces a password the database already uses.
#
#   pg/    postgres_admin_password, postgres_owner_password, postgres_app_password   (this container only)
#   app/   database_url                    (server and maintenance: runtime role, data only)
#   owner/ migrate_database_url            (maintenance only: schema owner)
#
# The master key is not made here: the database container never gets to see it.
set -eu

pgdir=${LIBREPATCH_PG_SECRETS:-/run/librepatch/pg}
appdir=${LIBREPATCH_APP_SECRETS:-/run/librepatch/app}
ownerdir=${LIBREPATCH_OWNER_SECRETS:-/run/librepatch/owner}
data=${PGDATA:-/var/lib/postgresql/data}
db=${POSTGRES_DB:-librepatch}
host=${LIBREPATCH_DB_HOST:-postgres}

rand() { head -c "$1" /dev/urandom | od -An -tx1 | tr -d ' \n'; }

missing=""
for n in admin owner app; do
  [ -s "$pgdir/postgres_${n}_password" ] || missing="$missing $n"
done

if [ -n "$missing" ]; then
  if [ -s "$data/PG_VERSION" ]; then
    echo "ERROR: the database already exists, but its saved passwords (volume 'secrets_pg':$missing) are missing." >&2
    echo "A new password would not open the existing database. Restore the secrets volumes from a backup, or" >&2
    echo "remove the database volume as well to start over with an empty database (this deletes all data)." >&2
    exit 1
  fi
  umask 077
  mkdir -p "$pgdir"
  for n in $missing; do
    rand 24 > "$pgdir/postgres_${n}_password"
  done
  echo "Created the database passwords (first start)."
fi

umask 077
mkdir -p "$appdir" "$ownerdir"
printf 'postgres://librepatch_app:%s@%s:5432/%s?sslmode=disable' "$(cat "$pgdir/postgres_app_password")" "$host" "$db" > "$appdir/database_url"
printf 'postgres://librepatch_owner:%s@%s:5432/%s?sslmode=disable' "$(cat "$pgdir/postgres_owner_password")" "$host" "$db" > "$ownerdir/migrate_database_url"

# The server and the maintenance service run as an unprivileged user and must be able to read their connection string;
# the passwords themselves belong to PostgreSQL's own user, which reads them in the init script.
chmod 755 "$appdir" "$ownerdir" "$pgdir"
chmod 644 "$appdir/database_url" "$ownerdir/migrate_database_url"
if [ "$(id -u)" = 0 ] && id postgres >/dev/null 2>&1; then
  chown postgres "$pgdir"/postgres_*_password 2>/dev/null || true
fi
chmod 600 "$pgdir"/postgres_*_password

exec docker-entrypoint.sh "$@"
