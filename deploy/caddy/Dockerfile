# LibrePatch web proxy: Caddy with both Caddyfiles built in, so an install needs no files next to the compose file
# (decision D110). Published as ghcr.io/<owner>/librepatch-caddy. The base image is pinned by digest; Dependabot
# proposes the updates.
FROM caddy:2-alpine@sha256:78bd35025c7ba85961dd149ae670315129954e77abe2383ac47c89106b35ade9
LABEL org.opencontainers.image.source="https://github.com/auzring1/LibrePatch" \
      org.opencontainers.image.description="LibrePatch web proxy (Caddy) for the console and REST API" \
      org.opencontainers.image.licenses="AGPL-3.0-or-later"
COPY Caddyfile Caddyfile.behind-proxy /etc/caddy/
COPY start.sh /usr/local/bin/librepatch-caddy
# LIBREPATCH_BEHIND_PROXY=true selects Caddyfile.behind-proxy (plain HTTP, for your own reverse proxy).
CMD ["sh", "/usr/local/bin/librepatch-caddy"]
