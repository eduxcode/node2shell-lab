ARG NODE_IMAGE=node:24.22.0-bookworm-slim
FROM ${NODE_IMAGE}

LABEL org.opencontainers.image.title="CVE-2026-111497 Node2Shell lab target"
LABEL org.opencontainers.image.description="Express 5 + body-parser Brotli body inflation target"

WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev
COPY server.js ./

EXPOSE 3000
USER node
CMD ["node", "/app/server.js"]
