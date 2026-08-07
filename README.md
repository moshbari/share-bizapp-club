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

## Chat scrolls

A long conversation doesn't fit in one screenshot, so people take a run of
them. Five separate share links are useless — the reader has to open each one
and guess the order. A **chat scroll** stacks them edge-to-edge on one page at
`/c/<slug>`, so scrolling the page is scrolling the conversation.

- `/chats/new` — pick the screenshots (drag-and-drop, or the phone's photo
  picker; multi-select). They're ordered by **capture time** by default, which
  is nearly always the order the reader wants, falling back to a natural
  filename sort when the timestamps are useless.
- Each one gets a serial number, a thumbnail, and a drag handle. Reorder by
  dragging, or with the ↑/↓ buttons (which also cover the case where the drag
  library fails to load). Number 1 is the top of the scroll.
- Ordering happens **in the browser, before anything uploads** — thumbnails are
  local object URLs, so rearranging costs no round-trips. The upload then runs
  strictly sequentially, because position is assigned server-side in arrival
  order.
- `/chats/<slug>/edit` — reorder, remove, append more, rename, toggle
  downloads, delete. Reorders save automatically.
- The viewer reserves each screenshot's exact box (width/height are captured in
  the browser at pick time), so lazy-loading never yanks the page out from under
  the reader. Tap any screenshot to zoom without losing your place.

A chat's images are **not** rows in `files` — they have no share link of their
own and don't appear in the recent-shares list. Trial accounts get one scroll
of up to 10 screenshots; regular accounts get unlimited scrolls of up to 60.
A scroll stays a hidden `draft` until every image has uploaded; abandoned
drafts are swept (DB + GHL) after 24h.

## Per-type size limits (matches GHL's **API** caps)

| Kind   | Limit |
| ------ | ----- |
| Image  | 25 MB |
| Audio  | 25 MB |
| Video  | 500 MB |
| PDF    | 25 MB |
| Text   | 25 MB |

Note: GHL's dashboard UI accepts larger files (100 MB / 4 GB), but the
`/medias/upload-file` API endpoint we use rejects anything over 25 MB
for non-video and 500 MB for video. We match the API caps so uploads
never pass client validation then fail server-side.

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
