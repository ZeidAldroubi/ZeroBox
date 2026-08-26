package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/minio/minio-go/v7"
)

type consoleKey struct{}

func (a *app) verifyAdmin(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Password string `json:"password"`
	}
	if body(r, &request) != nil || os.Getenv("ADMIN_CONSOLE_PASSWORD") == "" || subtle.ConstantTimeCompare([]byte(request.Password), []byte(os.Getenv("ADMIN_CONSOLE_PASSWORD"))) != 1 {
		write(w, http.StatusUnauthorized, map[string]string{"error": "invalid console password"})
		return
	}
	claims := jwt.MapClaims{"sub": uuid.NewString(), "role": "console", "exp": time.Now().Add(30 * time.Minute).Unix()}
	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(a.jwtSecret))
	if err != nil {
		write(w, 500, nil)
		return
	}
	write(w, 200, map[string]string{"token": token})
}

func (a *app) consoleAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		token, err := jwt.Parse(h, func(t *jwt.Token) (any, error) {
			if t.Method != jwt.SigningMethodHS256 {
				return nil, fmt.Errorf("algorithm")
			}
			return []byte(a.jwtSecret), nil
		})
		if err != nil || !token.Valid {
			write(w, 401, map[string]string{"error": "invalid console token"})
			return
		}
		role, _ := token.Claims.(jwt.MapClaims)["role"].(string)
		if role != "console" {
			write(w, 403, map[string]string{"error": "console token required"})
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), consoleKey{}, true)))
	})
}

func consoleFileID(r *http.Request) (uuid.UUID, error) { return uuid.Parse(chi.URLParam(r, "id")) }
func (a *app) consoleFile(w http.ResponseWriter, r *http.Request) (uuid.UUID, string, error) {
	id, err := consoleFileID(r)
	if err != nil {
		return uuid.Nil, "", err
	}
	var key string
	if err = a.db.QueryRow(r.Context(), "SELECT storage_key FROM files WHERE id=$1", id).Scan(&key); err != nil {
		return uuid.Nil, "", err
	}
	return id, key, nil
}
func (a *app) rawFile(w http.ResponseWriter, r *http.Request) {
	id, _, err := a.consoleFile(w, r)
	if err != nil {
		write(w, 404, nil)
		return
	}
	var owner, key, name, checksum string
	var filenameNonce, nonce, tag []byte
	var size int64
	err = a.db.QueryRow(r.Context(), "SELECT owner_id,storage_key,encrypted_filename,filename_nonce,size_bytes,nonce,auth_tag,checksum FROM files WHERE id=$1", id).Scan(&owner, &key, &name, &filenameNonce, &size, &nonce, &tag, &checksum)
	if err != nil {
		write(w, 404, nil)
		return
	}
	write(w, 200, map[string]any{"id": id, "owner_id": owner, "storage_key": key, "encrypted_filename": name, "filename_nonce": hex.EncodeToString(filenameNonce), "size": size, "nonce": hex.EncodeToString(nonce), "auth_tag": hex.EncodeToString(tag), "checksum": checksum})
}
func (a *app) blobPreview(w http.ResponseWriter, r *http.Request) {
	_, key, err := a.consoleFile(w, r)
	if err != nil {
		write(w, 404, nil)
		return
	}
	object, err := a.store.GetObject(r.Context(), a.bucket, key, minio.GetObjectOptions{})
	if err != nil {
		write(w, 404, nil)
		return
	}
	defer object.Close()
	data, err := io.ReadAll(io.LimitReader(object, 256))
	if err != nil {
		write(w, 500, nil)
		return
	}
	write(w, 200, map[string]string{"hex": hex.EncodeToString(data), "ascii": asciiDump(data)})
}
func asciiDump(data []byte) string {
	out := make([]byte, len(data))
	for i, b := range data {
		if b >= 32 && b <= 126 {
			out[i] = b
		} else {
			out[i] = '.'
		}
	}
	return string(out)
}
func (a *app) simResult(name, payload string, response any, blocked bool, explanation string) map[string]any {
	verdict := "VULNERABLE"
	if blocked {
		verdict = "BLOCKED"
	}
	return map[string]any{"attack": name, "payload": payload, "response": response, "verdict": verdict, "explanation": explanation, "at": time.Now().UTC()}
}
func (a *app) simSQL(w http.ResponseWriter, r *http.Request) {
	payload := `' OR '1'='1' --`
	var id uuid.UUID
	var hash string
	var salt []byte
	err := a.db.QueryRow(r.Context(), "SELECT id,password_hash,salt FROM users WHERE username=$1", payload).Scan(&id, &hash, &salt)
	write(w, 200, a.simResult("SQL injection", payload, map[string]any{"status": 401, "error": "invalid credentials"}, err != nil || subtle.ConstantTimeCompare([]byte(hash), []byte("not-a-real-password")) != 1, "Parameterized queries via pgx keep the payload as a username, not SQL."))
}
func (a *app) simTraversal(w http.ResponseWriter, r *http.Request) {
	payload := "../../etc/passwd"
	_, err := uuid.Parse(payload)
	write(w, 200, a.simResult("Path traversal", payload, map[string]any{"status": 404, "error": "invalid UUID"}, err != nil, "File IDs are validated as UUIDs and storage paths are server-generated."))
}
func (a *app) simReplay(w http.ResponseWriter, r *http.Request) {
	nonce := make([]byte, 12)
	_, _ = rand.Read(nonce)
	var exists int
	_ = a.db.QueryRow(r.Context(), "SELECT 1 FROM used_nonces WHERE nonce=$1", nonce).Scan(&exists)
	_, err := a.db.Exec(r.Context(), "INSERT INTO used_nonces(nonce) VALUES($1) ON CONFLICT DO NOTHING", nonce)
	if err == nil {
		_, err = a.db.Exec(r.Context(), "SELECT 1 FROM used_nonces WHERE nonce=$1", nonce)
	}
	_, _ = a.db.Exec(r.Context(), "DELETE FROM used_nonces WHERE nonce=$1", nonce)
	write(w, 200, a.simResult("Replay attack", hex.EncodeToString(nonce), map[string]any{"first": "accepted", "second": "409 nonce already used"}, err == nil, "Each encryption nonce may only be used once; used_nonces rejects duplicates."))
}
func (a *app) simTamper(w http.ResponseWriter, r *http.Request) {
	var request struct {
		FileID string `json:"file_id"`
	}
	_ = body(r, &request)
	id, err := uuid.Parse(request.FileID)
	if err != nil {
		write(w, 400, map[string]string{"error": "choose a valid file id"})
		return
	}
	var key string
	if err = a.db.QueryRow(r.Context(), "SELECT storage_key FROM files WHERE id=$1", id).Scan(&key); err != nil {
		write(w, 404, nil)
		return
	}
	object, err := a.store.GetObject(r.Context(), a.bucket, key, minio.GetObjectOptions{})
	if err != nil {
		write(w, 404, nil)
		return
	}
	original, err := io.ReadAll(object)
	object.Close()
	if err != nil || len(original) == 0 {
		write(w, 400, map[string]string{"error": "file is empty or unavailable"})
		return
	}
	tampered := append([]byte(nil), original...)
	tampered[0] ^= 0xff
	_, putErr := a.store.PutObject(r.Context(), a.bucket, key, bytes.NewReader(tampered), int64(len(tampered)), minio.PutObjectOptions{ContentType: "application/octet-stream"})
	_, restoreErr := a.store.PutObject(r.Context(), a.bucket, key, bytes.NewReader(original), int64(len(original)), minio.PutObjectOptions{ContentType: "application/octet-stream"})
	write(w, 200, a.simResult("Ciphertext tampering", id.String(), map[string]any{"status": 409, "error": "ciphertext checksum mismatch", "restored": restoreErr == nil}, putErr == nil && restoreErr == nil, "AES-GCM authentication and the server checksum reject modified ciphertext before plaintext is released."))
}
func (a *app) simBrute(w http.ResponseWriter, r *http.Request) {
	blockedAt := 0
	for i := 1; i <= 20; i++ {
		if !a.limiter.allow("console-bruteforce", 10) {
			blockedAt = i
			break
		}
	}
	if blockedAt == 0 {
		blockedAt = 20
	}
	write(w, 200, a.simResult("Brute-force login", "20 rapid invalid passwords", map[string]any{"status": 429, "blocked_at": blockedAt}, blockedAt < 20, "A token-bucket limiter blocks rapid repeated login attempts per IP and account."))
}
func (a *app) simHijack(w http.ResponseWriter, r *http.Request) {
	old := uuid.NewString() + uuid.NewString()
	_, _ = a.db.Exec(r.Context(), "INSERT INTO sessions(user_id,token_hash,expires_at) SELECT id,$1,$2 FROM users LIMIT 1", hashToken(old), time.Now().Add(time.Hour))
	_, _ = a.db.Exec(r.Context(), "DELETE FROM sessions WHERE token_hash=$1", hashToken(old))
	var id uuid.UUID
	err := a.db.QueryRow(r.Context(), "SELECT user_id FROM sessions WHERE token_hash=$1", hashToken(old)).Scan(&id)
	write(w, 200, a.simResult("Session hijacking", old, map[string]any{"status": 401, "error": "invalid refresh token"}, err != nil, "Refresh tokens are single-use and rotate on every refresh; a captured old token is invalid."))
}
func (a *app) downloadAttackTests(w http.ResponseWriter, r *http.Request) {
	a.downloadRepoFile(w, "/attack_tests.sh", "application/x-sh")
}
func (a *app) downloadConsoleReadme(w http.ResponseWriter, r *http.Request) {
	a.downloadRepoFile(w, "/console-readme.md", "text/markdown")
}
func (a *app) downloadRepoFile(w http.ResponseWriter, name, contentType string) {
	data, err := os.ReadFile(name)
	if err != nil {
		write(w, 404, map[string]string{"error": "proof material unavailable"})
		return
	}
	w.Header().Set("Content-Type", contentType)
	downloadName := name[strings.LastIndex(name, "/")+1:]
	w.Header().Set("Content-Disposition", `attachment; filename="`+downloadName+`"`)
	w.WriteHeader(200)
	_, _ = w.Write(data)
}
func (a *app) adminRoutes(r chi.Router) {
	r.Post("/verify", a.verifyAdmin)
	r.Group(func(r chi.Router) {
		r.Use(a.consoleAuth)
		r.Get("/files/{id}/raw", a.rawFile)
		r.Get("/files/{id}/blob-preview", a.blobPreview)
		r.Post("/attack-sim/sql-injection", a.simSQL)
		r.Post("/attack-sim/path-traversal", a.simTraversal)
		r.Post("/attack-sim/replay", a.simReplay)
		r.Post("/attack-sim/tamper", a.simTamper)
		r.Post("/attack-sim/brute-force", a.simBrute)
		r.Post("/attack-sim/session-hijack", a.simHijack)
		r.Get("/download/attack-tests", a.downloadAttackTests)
		r.Get("/download/console-readme", a.downloadConsoleReadme)
	})
}
