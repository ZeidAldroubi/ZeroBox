# Zerobox Security Console

Zerobox encrypts file contents and filenames in the browser with AES-256-GCM. The Go server receives ciphertext and metadata only. PostgreSQL stores encrypted filename bytes and MinIO stores encrypted content; the browser-held key is never uploaded.

The Security Console is a password-gated demonstration surface. Enter the password configured as `ADMIN_CONSOLE_PASSWORD` to obtain a separate, short-lived console token. The simulator makes real checks against the running database and object store: parameterized SQL rejects injection, UUID validation rejects traversal, used nonces reject replay, the checksum and GCM authentication design reject tampering, token buckets reject brute force, and refresh rotation invalidates captured tokens.

The tamper demonstration restores the original MinIO object after the check. The downloadable shell script is the independent black-box suite shipped with the project.
