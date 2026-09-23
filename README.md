# securefile

An encrypted, registration-free file-transfer service. A single Go binary with
an embedded SQLite database and plain-JavaScript front end: deployment is a file
copy and a `systemctl restart`.

**Live service:** [up.paps.jp](https://up.paps.jp) — "セキュファイル便", run by
[特定非営利活動法人ぱっぷす (PAPS)](https://paps.jp) as a free, safe alternative to
password-protected ZIP (PPAP).

## Design

**The server cannot read your files.** Each share gets a random data-encryption
key (DEK) that encrypts the file bodies; that DEK is then wrapped with a key
derived from the share password via Argon2id. The password itself is stored
nowhere. Someone who walks off with both the database and the blob directory
still cannot recover a file without its password. **File names are encrypted
with the same DEK**, so even the names give nothing away.

The flip side: a file whose password is lost is unrecoverable by anyone. That is
by design.

**Transfers resume.** Files are sent in 8 MiB parts. Each part retries
independently, and the server can report how much it has already received, so an
interrupted upload continues from where it stopped rather than starting over —
even a multi-gigabyte upload on a flaky mobile link.

```
browser
  │  PATCH /api/uploads/{sid}/files/{fid}   (Upload-Offset header, 8 MiB parts)
  ▼
securefile (Go, :8080)
  ├── internal/cryptobox   AES-256-GCM STREAM construction, Argon2id key wrap
  ├── internal/store       SQLite (modernc.org/sqlite, pure Go — no CGO)
  ├── internal/service     resumable upload, download sessions, expiry sweep
  ├── internal/httpd       routing, rate limiting, Range support
  └── web/                 templates and static files (embedded in the binary)
```

### Encryption format

File bodies use the STREAM construction (Hoang et al.): the plaintext is split
into fixed 1 MiB chunks, each sealed independently with AES-256-GCM. The nonce is
a per-file random 7-byte prefix + a 4-byte chunk index + a 1-byte final flag.

Fixed-size chunks buy two things:

1. **Range requests.** The position of chunk *N* is a calculation, so returning
   the tail of a large file does not require decrypting the whole thing.
   Download resume and seeking fall out of this.
2. **Upload resume.** An interrupted upload reads its nonce prefix and resume
   offset back from the partial file's header and continues sealing.

The final flag detects truncation: a stream cut short fails authentication
rather than decrypting as a shorter file.

### Download counting

One password entry (a session) consumes **one** download, no matter how many
files the share holds. Peeking, unlocking, ticket issuance, and `HEAD` requests
never consume one.

### No secrets in download URLs

Because a browser navigates for each download — leaving the authorizing token in
the address bar, history, and access log — the server never puts a session token
there. It issues a **single-file, ten-minute ticket** per download and puts that
in the URL instead, so a leaked URL exposes far less than a session would.

### No third-party code on secret pages

The default Content-Security-Policy is `default-src 'none'`: pages load nothing
from another origin. Optional ads/analytics can be enabled, but only on
non-secret pages, never on a page whose URL or fragment can carry a share key.

## Build & run

Requires Go 1.26+.

```bash
go test ./...
go run ./cmd/securefile -addr 127.0.0.1:8099 \
  -data-dir ./data -base-url http://127.0.0.1:8099
```

Cross-compile a static Linux binary (CGO off, thanks to the pure-Go SQLite
driver, so it runs on any glibc or musl image):

```bash
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o securefile ./cmd/securefile
```

## Configuration

Settings are available as flags and as `SECUREFILE_*` environment variables; see
[`deploy/securefile.env.example`](deploy/securefile.env.example). The ones that
matter most:

- `SECUREFILE_BASE_URL` — share links are built from this; it must match the URL
  the recipient's browser actually sees, scheme included.
- `SECUREFILE_TRUSTED_PROXIES` — only `X-Forwarded-For` (or the real-IP header)
  from these hops is believed. Empty treats every connection as direct, which
  behind a reverse proxy would share one rate-limit bucket across all users.
- `SECUREFILE_DISK_QUOTA_BYTES` — new uploads are refused past this, rather than
  letting the disk fill and take the service down.

### Reverse proxy

An example is in [`deploy/nginx-securefile.conf`](deploy/nginx-securefile.conf).
Two settings matter:

- `client_max_body_size 0` — nginx's default 1 MiB would reject the 8 MiB parts.
- `proxy_request_buffering off` — buffering parts to disk before forwarding
  doubles write volume and adds latency.

## License

MIT. See [LICENSE](LICENSE).

Originally built by [特定非営利活動法人ぱっぷす (PAPS)](https://paps.jp) to replace
its own file-transfer service.
