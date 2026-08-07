# Dockerfile — Node 20 + curl. Same shape as listen-bizapp-club.
#
# Trap from the playbook (GHL_MEDIA_UPLOAD.md): node:20-slim doesn't ship
# curl OR /etc/mime.types. We need curl for GHL uploads (Node FormData
# fails on GHL's multipart parser) and we always pass `;type=...` on the
# form field so curl never falls back to application/octet-stream.

FROM node:20-slim

# unzip is needed at build time only (for the PDF.js prebuilt) — we strip it
# again in the same RUN so it doesn't bloat the runtime image.
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl ca-certificates unzip ffmpeg \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY package.json package-lock.json* ./
RUN npm install --omit=dev --no-audit --no-fund

# App code
COPY server.js ./
COPY lib ./lib

# Static assets we serve ourselves (currently the vendored SortableJS used by
# the chat-scroll editor). Copied before the PDF.js step below, which mkdir -p's
# into the same /app/public tree.
COPY public ./public

# Pull the prebuilt PDF.js viewer (Mozilla's zip release) and unpack into
# /app/public/pdfjs. The npm package `pdfjs-dist` only ships the library
# bundle (pdf_viewer.mjs) — the standalone `web/viewer.html` we need to
# iframe lives only in the GitHub release zip.
ARG PDFJS_VERSION=4.7.76
RUN mkdir -p /app/public/pdfjs \
    && curl -sL "https://github.com/mozilla/pdf.js/releases/download/v${PDFJS_VERSION}/pdfjs-${PDFJS_VERSION}-dist.zip" -o /tmp/pdfjs.zip \
    && unzip -q /tmp/pdfjs.zip -d /app/public/pdfjs \
    && rm /tmp/pdfjs.zip \
    && apt-get purge -y unzip && apt-get autoremove -y

# Persistent volume for SQLite — mounted by Coolify
RUN mkdir -p /app/data
VOLUME ["/app/data"]
ENV DATA_DIR=/app/data

ENV NODE_ENV=production
ENV PORT=3000
EXPOSE 3000

CMD ["node", "server.js"]
