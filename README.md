# Zerobox

> Private file storage where encryption happens before your files leave the browser.

Zerobox is a zero-knowledge file storage web application. It provides a Dropbox-style browser experience for registering, signing in, uploading, listing, downloading, and deleting files, while keeping file encryption keys and plaintext content on the client side.

Before an upload is sent to the server, the browser derives an encryption key from the user's password and encrypts both the file contents and filename with AES-256-GCM. The Go backend stores only encrypted bytes and metadata. PostgreSQL stores account and file metadata, while MinIO stores the encrypted blobs. The server never receives the user's file-encryption key or plaintext file contents.

This project also includes a Security Console that demonstrates the architecture and runs live security checks against the actual database and object storage.
<img width="1890" height="856" alt="Screenshot 2026-08-25 232358" src="https://github.com/user-attachments/assets/2f32a2d9-f2f5-444e-85d4-a899140a5f90" />
<img width="1892" height="857" alt="Screenshot 2026-08-25 232420" src="https://github.com/user-attachments/assets/54dcd010-85b2-4051-9da7-2b227160998d" />
<img width="1880" height="852" alt="Screenshot 2026-08-25 232511" src="https://github.com/user-attachments/assets/142bb8d8-2667-4f8b-8849-8435645a40b7" />

## Contents

- [What It Does](#what-it-does)
- [How It Works](#how-it-works)
- [Security Model](#security-model)
- [Technology](#technology)
- [Quick Start](#quick-start)
- [Using the Web App](#using-the-web-app)
- [Security Console](#security-console)
- [Testing](#testing)
- [Project Structure](#project-structure)
- [Design Decisions](#design-decisions)
- [Limitations](#limitations)

## What It Does

### Web application

- User registration and login
- Browser-side Argon2id key derivation
- Browser-native AES-256-GCM encryption and decryption
- Encrypted filenames as well as encrypted file contents
- Drag-and-drop upload and traditional file selection
- Upload progress reporting
- File listing with client-side filename decryption
- Browser downloads after successful client-side decryption
- Delete operations with owner checks
- In-memory access token handling
- HttpOnly refresh-cookie rotation
- Automatic access-token refresh and one retry after a 401 response
- Responsive desktop and mobile layout

### Security Console

The optional `/console` view is a password-gated demonstration area for logged-in users. It includes:

- A comparison of client-visible information and raw server-visible information
- PostgreSQL metadata inspection for a selected file
- A 256-byte MinIO ciphertext hex dump
- Live SQL injection, path traversal, replay, tampering, brute-force, and session-hijacking simulations
- Structured `BLOCKED` or `VULNERABLE` results with request and response details
- Downloads for the attack test script and a standalone architecture explainer

The console password is separate from every user password. Local Docker development defaults to `admin`; deployments should override it with `ADMIN_CONSOLE_PASSWORD`.

## How It Works

```text
┌──────────────────────┐       HTTPS / ciphertext       ┌────────────────────┐
│ React + TypeScript   │ ────────────────────────────► │ Go chi API         │
│ browser client       │ ◄──────────────────────────── │                    │
│                      │                               └─────────┬──────────┘
│ Argon2id            │                                         │
│ WebCrypto AES-GCM   │                               ┌─────────┴──────────┐
│ key held in memory  │                               │                    │
└──────────────────────┘                         PostgreSQL             MinIO
                                                 metadata                blobs
```

### Upload flow

1. The user selects or drops a file into the browser.
2. The browser derives a 256-bit AES key with Argon2id using the user's password and the account's client KDF salt.
3. The browser generates a fresh random 12-byte nonce.
4. WebCrypto encrypts the file with AES-256-GCM.
5. The browser encrypts the filename separately with another random nonce.
6. The browser sends the encrypted file as an `application/octet-stream` body. Crypto metadata is sent in `X-Zerobox-*` headers.
7. The server generates the storage key from the authenticated user ID and a new server-side UUID.
8. PostgreSQL stores encrypted metadata, nonce values, the authentication tag, and a SHA-256 checksum.
9. MinIO stores the ciphertext blob.

The browser uses raw binary upload transport instead of hexadecimal JSON for the web app. This avoids unnecessary file-size expansion and supports files up to the configured 100 MiB request limit.

### Download flow

1. The browser requests the selected file using its UUID.
2. The server verifies ownership and checks the ciphertext checksum.
3. The server returns encrypted bytes and encryption metadata.
4. The browser combines the ciphertext and GCM authentication tag.
5. WebCrypto decrypts the file using the in-memory key.
6. If authentication fails, the browser refuses to save the result and displays an integrity-check error.
7. On success, the browser creates a temporary Blob download.

## Security Model

| Threat | Defense | Where to inspect it |
|---|---|---|
| Session hijacking | 15-minute JWT access tokens, hashed refresh tokens, one-use refresh rotation, HttpOnly SameSite refresh cookie | `cmd/server/main.go`, web auth flow |
| Denial of service | Custom token-bucket rate limiter, per-IP auth limits, per-user limits, `Retry-After`, 100 MiB body limit | `cmd/server/main.go` |
| SQL injection | Every PostgreSQL query uses pgx placeholders such as `$1`; user input is never concatenated into SQL | `cmd/server/main.go`, `cmd/server/admin.go` |
| Path traversal | Strict UUID parsing for file IDs, server-generated storage keys, owner checks, filename validation | file handlers in `cmd/server/main.go` |
| Server-side data breach | File and filename keys are derived and used only in the browser; MinIO receives ciphertext | `web/src/App.tsx` |
| Replay attacks | Client nonces are recorded in `used_nonces` and duplicate nonces are rejected | upload handler and `schema.sql` |
| Data tampering | AES-GCM authentication tags plus server-side SHA-256 ciphertext checksums | upload/download flow |
| Unauthorized console access | Separate environment password and console JWT with `role=console`; user JWTs receive 403 | `cmd/server/admin.go` |
| Unauthorized browser origins | Configurable CORS allowlist with credentials support and no wildcard origin | CORS middleware |

### Password separation

There are two separate password-related operations:

- The backend uses Argon2id to hash the account password for login verification. That value is stored in PostgreSQL.
- The browser uses Argon2id with a separate KDF salt to derive the file-encryption key. The derived key is held in memory and is never sent to the backend.

The raw password is used only during the login request and local browser key derivation. It is not stored in the database, local storage, session storage, or frontend source code.

## Technology

### Backend

- Go 1.21+
- `github.com/go-chi/chi/v5` for HTTP routing
- `github.com/jackc/pgx/v5` for PostgreSQL access
- PostgreSQL 15+
- `github.com/minio/minio-go/v7` for S3-compatible object storage
- MinIO for local blob storage
- `golang.org/x/crypto/argon2` for server-side password verification hashing
- `github.com/golang-jwt/jwt/v5` for access and console JWTs
- Go standard library `crypto/tls` for optional TLS
- Custom Go token-bucket middleware

### Frontend

- React 18
- TypeScript
- Vite
- Tailwind CSS utilities
- Native Fetch API
- Native WebCrypto API for AES-256-GCM
- `argon2-browser` for client-side Argon2id WebAssembly
- `XMLHttpRequest` for upload progress events

## Quick Start

### Prerequisites

Install:

- Go 1.21 or later
- Node.js 18 or later
- Docker Desktop with Docker Compose

### Start the backend

From the repository root:

```powershell
cd "C:\path\to\Zerobox"
docker compose up --build
```

This starts:

- Go API: `http://localhost:8080`
- PostgreSQL: `localhost:5432`
- MinIO API: `http://localhost:9000`
- MinIO console: `http://localhost:9001`

The database schema is mounted into PostgreSQL and is applied automatically when the database volume is initialized.

Check the API from another terminal:

```powershell
Invoke-RestMethod http://localhost:8080/health
```

Expected response:

```json
{"status":"ok"}
```

### Configure the console password

The local demo password is `admin`. To choose another password:

```powershell
Copy-Item .env.example .env
notepad .env
```

Set:

```env
ADMIN_CONSOLE_PASSWORD=your-private-console-password
```

Then recreate the server:

```powershell
docker compose up -d --build server
```

`.env` is ignored by Git. Never commit it or share its contents.

### Start the frontend

In a second terminal:

```powershell
cd "C:\path\to\Zerobox\web"
npm.cmd install
npm.cmd run dev
```

Open:

```text
http://localhost:5173
```

`npm.cmd` is useful on Windows systems where PowerShell script execution blocks `npm.ps1`.

## Using the Web App

1. Open `http://localhost:5173`.
2. Choose **Create an account**.
3. Register with a username of at least 3 characters and a password of at least 8 characters.
4. Sign in with that account.
5. Drop a file into the upload area or choose one with the file picker.
6. Wait for browser encryption and upload to finish.
7. Use the download control to decrypt the file in the browser and save it locally.
8. Use the delete control to remove it from PostgreSQL and MinIO.

The application accepts any file type supported by the browser's file picker, including videos, images, archives, documents, and binary files. The current server limit is 100 MiB per request.

### MinIO inspection

Open `http://localhost:9001` and sign in with the local development credentials:

```text
Username: zerobox
Password: zeroboxsecret
```

Stored objects should appear as unreadable ciphertext. Filenames are stored in PostgreSQL as encrypted bytes represented by hex text, not as plaintext names.

## Security Console

The Security Console is an additive demonstration feature. It does not manage users and does not replace normal authentication.

1. Log into the main web app.
2. Click **Security Console** in the header.
3. Enter the configured console password, `admin` by default.
4. Inspect a file under **What the server sees**.
5. Run the attack simulations.
6. Expand each result to inspect the request and response.
7. Download the attack suite or the standalone console explainer.

The tamper simulation flips a byte in a real MinIO object, verifies that the modified data is rejected, and restores the original object before returning.

## Testing

### Go tests and compilation

```powershell
go test ./...
```

### Frontend production build

```powershell
cd web
npm.cmd run build
```

### Compose validation

```powershell
docker compose config
```

### Black-box attack suite

The expanded script requires `curl`, `jq`, Docker, and Docker Compose. It creates a disposable user and reports individual `PASS` or `FAIL` results for:

- Health endpoint
- SQL injection
- Path traversal
- Authentication
- Rate limiting
- Invalid JWTs
- Encrypted upload
- Replay detection
- Oversized upload rejection
- CORS origin enforcement
- MinIO ciphertext tampering and checksum detection

From Git Bash or WSL:

```bash
cd "/c/path/to/Zerobox"
bash attack_tests.sh
```

On Debian-based WSL distributions, install `jq` if necessary:

```bash
sudo apt-get update
sudo apt-get install jq
```

The script uses the local MinIO Compose network for its tampering check. Override these values when needed:

```bash
MINIO_USER=zerobox \
MINIO_PASSWORD=zeroboxsecret \
MINIO_DOCKER_ENDPOINT=http://minio:9000 \
bash attack_tests.sh
```

### Stop the stack

```powershell
docker compose down
```

Remove database and object-storage volumes as well:

```powershell
docker compose down -v
```

## Project Structure

```text
Zerobox/
├── cmd/
│   ├── client/              Legacy Go CLI client
│   └── server/
│       ├── main.go          API, auth, uploads, downloads, CORS, rate limits
│       └── admin.go         Security Console API and attack simulations
├── web/
│   ├── src/
│   │   ├── App.tsx          React app, encryption, vault, console UI
│   │   └── styles.css       Application styling
│   ├── package.json         Frontend dependencies and scripts
│   └── vite.config.ts       Vite and API proxy configuration
├── schema.sql               PostgreSQL schema
├── docker-compose.yml       PostgreSQL, MinIO, and API services
├── Dockerfile               Multi-stage Go server image
├── attack_tests.sh          Black-box security test suite
├── console-readme.md        Standalone console explainer
├── .env.example             Safe environment-variable template
└── README.md                Project documentation
```

## Design Decisions

### Argon2id

Argon2id is memory-hard and designed to make large-scale password cracking more expensive. It is used for server-side login verification and separately in the browser for file-key derivation. The two operations use different salts and have different purposes.

### AES-256-GCM

AES-GCM provides authenticated encryption: it protects confidentiality and detects modification. CBC mode alone does not authenticate ciphertext and requires a separate integrity mechanism. If the ciphertext or authentication tag changes, WebCrypto decryption fails and Zerobox refuses to save the result.

### Browser-side encryption

Encrypting before upload means the storage service does not need the user's file-encryption key. A database or object-storage compromise exposes encrypted material, not the original file contents. The tradeoff is that losing the password means losing the ability to decrypt files; there is no server-side recovery key.

### In-memory access tokens

The short-lived JWT is kept in React state rather than localStorage to reduce persistence and token-theft risk from a later XSS incident. The refresh token is stored in an HttpOnly, SameSite cookie so frontend JavaScript cannot read it directly. Refresh-token rotation means an old token is invalid after it has been used.

### Server-generated storage keys

The server never uses a user-provided filename as a filesystem or object-storage path. Each object is stored under a key based on the authenticated user UUID and a server-generated file UUID. This makes path traversal irrelevant to storage addressing and provides an additional ownership boundary.

## Limitations

- The current upload limit is 100 MiB per request. Chunked uploads are not implemented yet.
- Local Docker development uses HTTP. Production should use HTTPS with `TLS_CERT_FILE`, `TLS_KEY_FILE`, `COOKIE_SECURE=true`, and a real certificate such as Let's Encrypt.
- There is no password reset or account recovery flow. A true zero-knowledge recovery design requires careful key escrow or recovery-key decisions and is intentionally out of scope.
- There is no file sharing, version history, delta sync, or mobile application.
- The Security Console password is intentionally public in the local demo default. It must be overridden for any shared or production deployment.
- The included legacy CLI predates the browser console and uses its own local configuration format. The browser app is the primary product experience.
