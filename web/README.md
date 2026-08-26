# Zerobox Web

React + TypeScript + Vite browser client for the Zerobox API. File contents and filenames are encrypted in the browser with WebCrypto AES-256-GCM. Argon2id runs client-side through `argon2-browser`; the derived key is held in memory only.

```powershell
npm install
npm run dev
```

Open `http://localhost:5173` after starting the Go backend with `docker compose up --build` from the repository root. Build production assets with `npm run build`.
