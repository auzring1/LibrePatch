# LibrePatch database: PostgreSQL with the role setup and the first-start password wrapper built in, so an install
# needs no files next to the compose file (decision D110). Published as ghcr.io/<owner>/librepatch-postgres.
# The base image is pinned by digest; Dependabot proposes the updates.
FROM postgres:16-alpine@sha256:f2f98726820d0342055351c6e9d36e705f5bfffb3dd53ff556325114b08afb6d
LABEL org.opencontainers.image.source="https://github.com/auzring1/LibrePatch" \
      org.opencontainers.image.description="LibrePatch database (PostgreSQL) that creates its own passwords on the first start" \
      org.opencontainers.image.licenses="AGPL-3.0-or-later"
COPY init/ /docker-entrypoint-initdb.d/
COPY entrypoint.sh /librepatch/pg-entrypoint.sh
# The wrapper creates the passwords on the very first start (decision D109) and then runs the official entrypoint.
ENTRYPOINT ["sh", "/librepatch/pg-entrypoint.sh"]
CMD ["postgres"]
