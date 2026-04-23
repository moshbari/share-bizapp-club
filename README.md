# share.bizapp.club

Upload any file (image, video, audio, PDF, text/code/markdown), share a link
that previews the file with a tailored viewer.

Companion to `listen.bizapp.club`. Same shape (Express + SQLite + GHL CDN +
Coolify), different focus.

## What it does

- Owner logs in with a single shared password.
- Owner drops a file. Server classifies it, enforces a per-type size cap,
  uploads to the GoHighLevel media library, writes a row to SQLite.
- Owner gets a `/f/<slug>` share link.
- Recipient opens the link. The viewer is picked by file kind:
  - **Image** — full preview, click to open full-size.
  - **Video** — `<video controls>` player.
  - **Audio** — `<audio controls>` player.
  - **PDF** — embedded PDF.js (page nav, zoom, search, thumbnails, text
    selection).
  - **Text / Markdown / Code** — markdown renders to formatted text with a
    "View source" toggle, plain text renders in a `<pre>`. Copy button on
    every text view.
- The owner picks per-file whether downloads are allowed. When off, no
  download button shows.

## Per-type size limits (matches GHL)

| Kind   | Limit |
| ------ | ----- |
| Image  | 100 MB |
| Audio  | 100 MB |
| Video  | 4 GB |
| PDF    | 100 MB |
| Text   | 100 MB |

Code and markup files (`.md`, `.js`, `.py`, …) get coerced to a `.txt`
display name when uploaded to GHL — GHL rejects most code MIME types as
`INVALID_FILE_TYPE`. The viewer reads the original filename's extension to
pick the right rendering.

## Env vars

| Var                 | Purpose                                  |
| ------------------- | ---------------------------------------- |
| `UPLOAD_PASSWORD`   | shared owner password (required)         |
| `SESSION_SECRET`    | cookie-parser secret (auto-gen if unset) |
| `SITE_NAME`         | header brand                             |
| `PUBLIC_ORIGIN`     | scheme+host for share-link composition   |
| `GHL_API_KEY`       | PIT token (`pit-…`)                      |
| `GHL_LOCATION_ID`   | sub-account location id                  |
| `GHL_FOLDER_ID`     | folder id under the sub-account          |
| `DATA_DIR`          | SQLite dir (defaults to `/app/data`)     |
| `PORT`              | listen port (defaults to 3000)           |

## Run

```sh
docker build -t share .
docker run --rm -p 3000:3000 \
  -e UPLOAD_PASSWORD=… \
  -e GHL_API_KEY=pit-… \
  -e GHL_LOCATION_ID=… \
  -e GHL_FOLDER_ID=… \
  -e PUBLIC_ORIGIN=https://share.bizapp.club \
  -v "$PWD/data:/app/data" \
  share
```
