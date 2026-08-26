package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	"golang.org/x/crypto/argon2"
)

// SECURITY: every database query below uses pgx placeholders and arguments; never concatenate user input into SQL.
type app struct {
	db                *pgxpool.Pool
	store             *minio.Client
	bucket, jwtSecret string
	limiter           *limiter
}
type limiter struct {
	mu    sync.Mutex
	items map[string]*bucket
}
type bucket struct {
	tokens float64
	at     time.Time
}

func (l *limiter) allow(key string, limit float64) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	b := l.items[key]
	now := time.Now()
	if b == nil {
		b = &bucket{limit, now}
		l.items[key] = b
	} else {
		b.tokens += now.Sub(b.at).Seconds() * limit / 60
		if b.tokens > limit {
			b.tokens = limit
		}
		b.at = now
	}
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}
func main() {
	ctx := context.Background()
	db, err := pgxpool.New(ctx, env("DB_URL", "postgres://zerobox:zerobox@localhost:5432/zerobox"))
	if err != nil {
		panic(err)
	}
	defer db.Close()
	s, err := minio.New(env("MINIO_ENDPOINT", "localhost:9000"), &minio.Options{Creds: credentials.NewStaticV4(env("MINIO_ACCESS_KEY", "zerobox"), env("MINIO_SECRET_KEY", "zeroboxsecret"), ""), Secure: false})
	if err != nil {
		panic(err)
	}
	a := &app{db: db, store: s, bucket: "zerobox", jwtSecret: env("JWT_SECRET", "dev-only-change-me"), limiter: &limiter{items: map[string]*bucket{}}}
	go a.ensureBucket(ctx)
	r := chi.NewRouter()
	r.Use(a.rate)
	r.Use(a.cors)
	r.Get("/health", func(w http.ResponseWriter, r *http.Request) { write(w, 200, map[string]string{"status": "ok"}) })
	r.Post("/register", a.register)
	r.Post("/login", a.login)
	r.Post("/refresh", a.refresh)
	r.Route("/admin", a.adminRoutes)
	r.Group(func(r chi.Router) {
		r.Use(a.auth)
		r.Post("/logout", a.logout)
		r.Post("/files", a.upload)
		r.Get("/files", a.list)
		r.Get("/files/{id}", a.download)
		r.Delete("/files/{id}", a.delete)
	})
	port := env("PORT", "8080")
	certFile, keyFile := os.Getenv("TLS_CERT_FILE"), os.Getenv("TLS_KEY_FILE")
	if certFile != "" && keyFile != "" {
		if err := http.ListenAndServeTLS(":"+port, certFile, keyFile, r); err != nil {
			panic(err)
		}
		return
	}
	if err := http.ListenAndServe(":"+port, r); err != nil {
		panic(err)
	}
}
func env(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}
func (a *app) ensureBucket(ctx context.Context) {
	for i := 0; i < 30; i++ {
		if a.store.MakeBucket(ctx, a.bucket, minio.MakeBucketOptions{}) == nil {
			return
		}
		time.Sleep(time.Second)
	}
}
func write(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}
func body(r *http.Request, v any) error {
	return json.NewDecoder(r.Body).Decode(v)
}
func hashToken(s string) string              { h := sha256.Sum256([]byte(s)); return hex.EncodeToString(h[:]) }
func passwordHash(p string, s []byte) []byte { return argon2.IDKey([]byte(p), s, 1, 64*1024, 4, 32) }
func (a *app) register(w http.ResponseWriter, r *http.Request) {
	var x struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if body(r, &x) != nil || len(x.Username) < 3 || len(x.Password) < 8 {
		write(w, 400, map[string]string{"error": "invalid registration"})
		return
	}
	salt := make([]byte, 16)
	kdfSalt := make([]byte, 16)
	if _, e := rand.Read(salt); e != nil {
		write(w, 500, nil)
		return
	}
	if _, e := rand.Read(kdfSalt); e != nil {
		write(w, 500, nil)
		return
	}
	_, e := a.db.Exec(r.Context(), "INSERT INTO users (username,password_hash,salt,kdf_salt) VALUES ($1,$2,$3,$4)", x.Username, hex.EncodeToString(passwordHash(x.Password, salt)), salt, kdfSalt)
	if e != nil {
		write(w, 409, map[string]string{"error": "username unavailable"})
		return
	}
	write(w, 201, map[string]string{"status": "registered"})
}
func (a *app) login(w http.ResponseWriter, r *http.Request) {
	var x struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if body(r, &x) != nil {
		write(w, 400, nil)
		return
	}
	var id uuid.UUID
	var stored string
	var salt []byte
	var kdfSalt []byte
	e := a.db.QueryRow(r.Context(), "SELECT id,password_hash,salt,kdf_salt FROM users WHERE username=$1", x.Username).Scan(&id, &stored, &salt, &kdfSalt)
	if e != nil || subtle.ConstantTimeCompare([]byte(stored), []byte(hex.EncodeToString(passwordHash(x.Password, salt)))) != 1 {
		write(w, 401, map[string]string{"error": "invalid credentials"})
		return
	}
	a.writeTokens(w, r, id, kdfSalt)
}
func (a *app) writeJWT(id uuid.UUID) (string, error) {
	c := jwt.MapClaims{"sub": id.String(), "exp": time.Now().Add(15 * time.Minute).Unix()}
	return jwt.NewWithClaims(jwt.SigningMethodHS256, c).SignedString([]byte(a.jwtSecret))
}
func (a *app) writeTokens(w http.ResponseWriter, r *http.Request, id uuid.UUID, kdfSalt []byte) {
	access, e := a.writeJWT(id)
	if e != nil {
		write(w, 500, nil)
		return
	}
	raw := uuid.NewString() + uuid.NewString()
	_, e = a.db.Exec(r.Context(), "INSERT INTO sessions (user_id,token_hash,expires_at) VALUES ($1,$2,$3)", id, hashToken(raw), time.Now().Add(7*24*time.Hour))
	if e != nil {
		write(w, 500, nil)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: "zerobox_refresh", Value: raw, Path: "/", HttpOnly: true, Secure: os.Getenv("COOKIE_SECURE") == "true", SameSite: http.SameSiteStrictMode, MaxAge: 7 * 24 * 60 * 60})
	write(w, 200, map[string]string{"access_token": access, "refresh_token": raw, "kdf_salt": hex.EncodeToString(kdfSalt)})
}
func (a *app) refresh(w http.ResponseWriter, r *http.Request) {
	var x struct {
		RefreshToken string `json:"refresh_token"`
	}
	_ = body(r, &x)
	if cookie, err := r.Cookie("zerobox_refresh"); err == nil {
		x.RefreshToken = cookie.Value
	}
	if x.RefreshToken == "" {
		write(w, 401, map[string]string{"error": "missing refresh token"})
		return
	}
	tx, e := a.db.Begin(r.Context())
	if e != nil {
		write(w, 500, nil)
		return
	}
	defer tx.Rollback(r.Context())
	var id uuid.UUID
	e = tx.QueryRow(r.Context(), "SELECT user_id FROM sessions WHERE token_hash=$1 AND expires_at>$2 FOR UPDATE", hashToken(x.RefreshToken), time.Now()).Scan(&id)
	if e != nil {
		write(w, 401, map[string]string{"error": "invalid refresh token"})
		return
	}
	if _, e = tx.Exec(r.Context(), "DELETE FROM sessions WHERE token_hash=$1", hashToken(x.RefreshToken)); e != nil {
		write(w, 500, nil)
		return
	}
	if e = tx.Commit(r.Context()); e != nil {
		write(w, 500, nil)
		return
	}
	var kdfSalt []byte
	if e = a.db.QueryRow(r.Context(), "SELECT kdf_salt FROM users WHERE id=$1", id).Scan(&kdfSalt); e != nil {
		write(w, 500, nil)
		return
	}
	a.writeTokens(w, r, id, kdfSalt)
}

func (a *app) logout(w http.ResponseWriter, r *http.Request) {
	if cookie, e := r.Cookie("zerobox_refresh"); e == nil {
		_, _ = a.db.Exec(r.Context(), "DELETE FROM sessions WHERE token_hash=$1", hashToken(cookie.Value))
	}
	http.SetCookie(w, &http.Cookie{Name: "zerobox_refresh", Value: "", Path: "/", HttpOnly: true, MaxAge: -1, SameSite: http.SameSiteStrictMode})
	w.WriteHeader(http.StatusNoContent)
}
func (a *app) auth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		t, e := jwt.Parse(h, func(t *jwt.Token) (any, error) {
			if t.Method != jwt.SigningMethodHS256 {
				return nil, fmt.Errorf("algorithm")
			}
			return []byte(a.jwtSecret), nil
		})
		if e != nil || !t.Valid {
			write(w, 401, map[string]string{"error": "invalid token"})
			return
		}
		sub, _ := t.Claims.GetSubject()
		id, e := uuid.Parse(sub)
		if e != nil {
			write(w, 401, nil)
			return
		}
		if !a.limiter.allow("user:"+id.String(), 100) {
			w.Header().Set("Retry-After", "60")
			write(w, 429, map[string]string{"error": "rate limit exceeded"})
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), userKey{}, id)))
	})
}

func (a *app) cors(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		allowedOrigins := os.Getenv("CORS_ORIGIN")
		if allowedOrigins == "" {
			allowedOrigins = "http://localhost:5173,http://127.0.0.1:5173"
		}
		requestOrigin := r.Header.Get("Origin")
		originAllowed := requestOrigin == ""
		for _, allowed := range strings.Split(allowedOrigins, ",") {
			if strings.TrimSpace(allowed) == requestOrigin {
				originAllowed = true
				break
			}
		}
		if !originAllowed {
			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			write(w, http.StatusForbidden, map[string]string{"error": "origin not allowed"})
			return
		}
		if requestOrigin != "" {
			w.Header().Set("Access-Control-Allow-Origin", requestOrigin)
		}
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type, X-Zerobox-Nonce, X-Zerobox-Auth-Tag, X-Zerobox-Filename, X-Zerobox-Filename-Nonce")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

type userKey struct{}

func uid(r *http.Request) uuid.UUID { return r.Context().Value(userKey{}).(uuid.UUID) }
func (a *app) rate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		clientIP, _, splitErr := net.SplitHostPort(r.RemoteAddr)
		if splitErr != nil {
			clientIP = r.RemoteAddr
		}
		limit := 100.
		if r.URL.Path == "/login" || r.URL.Path == "/register" {
			limit = 10
		}
		if !a.limiter.allow("ip:"+clientIP+":"+r.URL.Path, limit) {
			w.Header().Set("Retry-After", "60")
			write(w, 429, map[string]string{"error": "rate limit exceeded"})
			return
		}
		next.ServeHTTP(w, r)
	})
}
func (a *app) upload(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 100<<20)
	var x struct {
		Nonce             string `json:"nonce"`
		AuthTag           string `json:"auth_tag"`
		Filename          string `json:"filename"`
		EncryptedFilename string `json:"encrypted_filename"`
		FilenameNonce     string `json:"filename_nonce"`
		Ciphertext        string `json:"ciphertext"`
	}
	var data []byte
	if strings.HasPrefix(r.Header.Get("Content-Type"), "application/octet-stream") {
		x.Nonce = r.Header.Get("X-Zerobox-Nonce")
		x.AuthTag = r.Header.Get("X-Zerobox-Auth-Tag")
		x.EncryptedFilename = r.Header.Get("X-Zerobox-Filename")
		x.FilenameNonce = r.Header.Get("X-Zerobox-Filename-Nonce")
		var readErr error
		data, readErr = io.ReadAll(r.Body)
		if readErr != nil {
			write(w, 413, map[string]string{"error": "upload exceeds the 100 MB limit"})
			return
		}
	} else if body(r, &x) != nil {
		write(w, 400, map[string]string{"error": "invalid upload"})
		return
	}
	if strings.Contains(x.Filename, "..") || strings.ContainsAny(x.Filename, "/\\\x00") {
		write(w, 400, map[string]string{"error": "invalid filename"})
		return
	}
	nonce, e := hex.DecodeString(x.Nonce)
	tag, e2 := hex.DecodeString(x.AuthTag)
	var e3 error
	if len(data) == 0 {
		data, e3 = hex.DecodeString(x.Ciphertext)
	}
	filename, e4 := hex.DecodeString(x.EncryptedFilename)
	filenameNonce, e5 := hex.DecodeString(x.FilenameNonce)
	if x.EncryptedFilename == "" {
		filename = []byte(x.Filename)
	}
	if e != nil || e2 != nil || e3 != nil || e4 != nil || e5 != nil || len(nonce) != 12 || len(tag) != 16 || (x.EncryptedFilename != "" && len(filenameNonce) != 12) {
		write(w, 400, map[string]string{"error": "invalid crypto metadata"})
		return
	}
	var exists int
	e = a.db.QueryRow(r.Context(), "SELECT 1 FROM used_nonces WHERE nonce=$1", nonce).Scan(&exists)
	if e == nil {
		write(w, 409, map[string]string{"error": "nonce already used"})
		return
	}
	id := uuid.New()
	key := "users/" + uid(r).String() + "/" + id.String()
	sum := sha256.Sum256(data)
	if _, e = a.store.PutObject(r.Context(), a.bucket, key, strings.NewReader(string(data)), int64(len(data)), minio.PutObjectOptions{ContentType: "application/octet-stream"}); e != nil {
		write(w, 500, nil)
		return
	}
	_, e = a.db.Exec(r.Context(), "INSERT INTO used_nonces(nonce) VALUES($1)", nonce)
	if e != nil {
		write(w, 500, nil)
		return
	}
	_, e = a.db.Exec(r.Context(), "INSERT INTO files(id,owner_id,storage_key,encrypted_filename,filename_nonce,size_bytes,nonce,auth_tag,checksum) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)", id, uid(r), key, hex.EncodeToString(filename), filenameNonce, len(data), nonce, tag, hex.EncodeToString(sum[:]))
	if e != nil {
		write(w, 500, nil)
		return
	}
	write(w, 201, map[string]string{"id": id.String()})
}
func (a *app) list(w http.ResponseWriter, r *http.Request) {
	rows, e := a.db.Query(r.Context(), "SELECT id,encrypted_filename,filename_nonce,size_bytes,nonce,auth_tag,checksum FROM files WHERE owner_id=$1 ORDER BY created_at DESC", uid(r))
	if e != nil {
		write(w, 500, nil)
		return
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var id uuid.UUID
		var n, t, filenameNonce []byte
		var name, sum string
		var size int64
		if rows.Scan(&id, &name, &filenameNonce, &size, &n, &t, &sum) == nil {
			out = append(out, map[string]any{"id": id, "encrypted_filename": name, "filename_nonce": hex.EncodeToString(filenameNonce), "size": size, "nonce": hex.EncodeToString(n), "auth_tag": hex.EncodeToString(t), "checksum": sum})
		}
	}
	write(w, 200, out)
}
func (a *app) find(r *http.Request) (uuid.UUID, string, error) {
	id, e := uuid.Parse(chi.URLParam(r, "id"))
	if e != nil {
		return uuid.Nil, "", e
	}
	var owner uuid.UUID
	var key string
	e = a.db.QueryRow(r.Context(), "SELECT owner_id,storage_key FROM files WHERE id=$1", id).Scan(&owner, &key)
	if e != nil || owner != uid(r) {
		return uuid.Nil, "", pgx.ErrNoRows
	}
	return id, key, nil
}
func (a *app) download(w http.ResponseWriter, r *http.Request) {
	id, key, e := a.find(r)
	if e != nil {
		write(w, 404, nil)
		return
	}
	var name string
	var size int64
	var n, t, filenameNonce []byte
	var sum string
	e = a.db.QueryRow(r.Context(), "SELECT encrypted_filename,filename_nonce,size_bytes,nonce,auth_tag,checksum FROM files WHERE id=$1", id).Scan(&name, &filenameNonce, &size, &n, &t, &sum)
	o, e := a.store.GetObject(r.Context(), a.bucket, key, minio.GetObjectOptions{})
	if e != nil {
		write(w, 404, nil)
		return
	}
	defer o.Close()
	data, e := io.ReadAll(o)
	if e != nil {
		write(w, 500, nil)
		return
	}
	h := sha256.Sum256(data)
	if hex.EncodeToString(h[:]) != sum {
		write(w, 409, map[string]string{"error": "ciphertext checksum mismatch"})
		return
	}
	write(w, 200, map[string]any{"encrypted_filename": name, "filename_nonce": hex.EncodeToString(filenameNonce), "size": size, "nonce": hex.EncodeToString(n), "auth_tag": hex.EncodeToString(t), "ciphertext": hex.EncodeToString(data)})
}
func (a *app) delete(w http.ResponseWriter, r *http.Request) {
	id, key, e := a.find(r)
	if e != nil {
		write(w, 404, nil)
		return
	}
	if e = a.store.RemoveObject(r.Context(), a.bucket, key, minio.RemoveObjectOptions{}); e != nil {
		write(w, 500, nil)
		return
	}
	_, e = a.db.Exec(r.Context(), "DELETE FROM files WHERE id=$1", id)
	if e != nil {
		write(w, 500, nil)
		return
	}
	w.WriteHeader(204)
}
func _() { _ = strconv.IntSize }
