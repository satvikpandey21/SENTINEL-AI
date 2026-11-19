# syntax=docker/dockerfile:1
ARG NODE_IMAGE=node:24-alpine@sha256:116b800c3754b440ee0aa3ed2f20f5bf3d99a554bfd9adeea09ea8017f6e85f5
ARG CADDY_IMAGE=caddy:2.11.9-alpine@sha256:003a97808e781aa9f7e75cc2f43d34d461099031faf5e20faefb9f61126836f0
FROM ${NODE_IMAGE} AS frontend
WORKDIR /build
COPY apps/dashboard/package.json apps/dashboard/package-lock.json ./
RUN npm ci
COPY apps/dashboard/ ./
RUN npm run build
FROM ${CADDY_IMAGE} AS runtime
RUN addgroup -g 10001 sentinel && adduser -D -u 10001 -G sentinel sentinel \
    && mkdir -p /srv /data /config && chown -R 10001:10001 /srv /data /config
COPY --from=frontend /build/dist /srv
COPY infra/deploy/Caddyfile infra/deploy/Caddyfile.tunnel infra/deploy/common.caddy /etc/caddy/
USER 10001:10001
CMD ["caddy", "run", "--config", "/etc/caddy/Caddyfile", "--adapter", "caddyfile"]
