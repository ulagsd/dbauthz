# syntax=docker/dockerfile:1

# The console as its own container.
#
# The assets are the same files the server embeds with go:embed — one source of
# truth, two delivery mechanisms. The single binary stays the answer for a
# plain deployment; this exists for stacks that want the front end scaled,
# cached or released separately.
FROM nginxinc/nginx-unprivileged:1.27-alpine

# Runs as uid 101 (nginx) with no root in the image.
COPY deploy/compose/console/nginx.conf /etc/nginx/conf.d/default.conf
COPY internal/server/web/              /usr/share/nginx/html/

EXPOSE 8080

HEALTHCHECK --interval=10s --timeout=3s --start-period=3s --retries=3 \
  CMD wget -q -O /dev/null http://127.0.0.1:8080/nginx-health || exit 1
