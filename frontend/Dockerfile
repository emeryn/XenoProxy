FROM node:22.21.0-alpine3.22 AS builder

ENV NPM_CONFIG_FUND=false \
    NPM_CONFIG_AUDIT=false \
    CI=true

WORKDIR /build
COPY package.json package-lock.json* ./

# Install scripts are disabled: a dependency must not run code at install time.
RUN npm config set ignore-scripts true \
 && if [ -f package-lock.json ]; then npm ci; else npm install; fi \
 && npm audit --audit-level=high

COPY tsconfig.json vite.config.ts tailwind.config.js postcss.config.js index.html ./
COPY public ./public
COPY src ./src

RUN npm run build


FROM nginxinc/nginx-unprivileged:1.31-alpine-slim AS runtime

USER root
RUN rm -rf /usr/share/nginx/html/* \
 && mkdir -p /tmp/nginx \
 && chown -R 101:101 /tmp/nginx
COPY --from=builder --chown=101:101 /build/dist /usr/share/nginx/html
COPY --chown=101:101 nginx-site.conf /etc/nginx/conf.d/default.conf

USER 101:101

EXPOSE 8081

HEALTHCHECK --interval=15s --timeout=4s --start-period=10s --retries=4 \
  CMD ["/bin/sh", "-c", "wget -q -O /dev/null http://127.0.0.1:8081/healthz || exit 1"]

CMD ["nginx", "-g", "daemon off;"]
