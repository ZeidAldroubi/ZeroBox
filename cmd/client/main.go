package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"golang.org/x/crypto/argon2"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

type config struct {
	Server, Username, Access, Refresh string
	Salt                              string
}

var cfg config

func main() {
	load()
	if len(os.Args) < 2 {
		usage()
		return
	}
	switch os.Args[1] {
	case "register":
		register()
	case "login":
		login()
	case "upload":
		upload(os.Args[2])
	case "list":
		request("GET", "/files", nil)
	case "download":
		download(os.Args[2])
	case "delete":
		request("DELETE", "/files/"+os.Args[2], nil)
	default:
		usage()
	}
}
func usage() { fmt.Println("zerobox register|login|upload <file>|list|download <id>|delete <id>") }
func load() {
	home, _ := os.UserHomeDir()
	b, _ := os.ReadFile(filepath.Join(home, ".zerobox", "config.json"))
	json.Unmarshal(b, &cfg)
	if cfg.Server == "" {
		cfg.Server = "http://localhost:8080"
	}
}
func save() {
	home, _ := os.UserHomeDir()
	d := filepath.Join(home, ".zerobox")
	os.MkdirAll(d, 0700)
	b, _ := json.Marshal(cfg)
	os.WriteFile(filepath.Join(d, "config.json"), b, 0600)
}
func prompt(s string) string {
	fmt.Print(s)
	v, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	return strings.TrimSpace(v)
}
func password() string { return prompt("Password: ") }
func post(path string, v any) (map[string]any, error) {
	b, _ := json.Marshal(v)
	r, e := http.Post(cfg.Server+path, "application/json", strings.NewReader(string(b)))
	if e != nil {
		return nil, e
	}
	defer r.Body.Close()
	var x map[string]any
	json.NewDecoder(r.Body).Decode(&x)
	if r.StatusCode >= 300 {
		return x, errors.New("request failed")
	}
	return x, nil
}
func register() {
	u := prompt("Username: ")
	_, e := post("/register", map[string]string{"username": u, "password": password()})
	fmt.Println(e)
}
func login() {
	cfg.Username = prompt("Username: ")
	x, e := post("/login", map[string]string{"username": cfg.Username, "password": password()})
	if e == nil {
		cfg.Access = x["access_token"].(string)
		cfg.Refresh = x["refresh_token"].(string)
		if cfg.Salt == "" {
			s := make([]byte, 16)
			rand.Read(s)
			cfg.Salt = hex.EncodeToString(s)
		}
		save()
	}
	fmt.Println(e)
}
func key() []byte {
	p := password()
	s, _ := hex.DecodeString(cfg.Salt)
	return argon2.IDKey([]byte(p), s, 1, 64*1024, 4, 32)
}
func encrypt(data []byte) ([]byte, []byte, []byte) {
	k := key()
	b, _ := aes.NewCipher(k)
	g, _ := cipher.NewGCM(b)
	n := make([]byte, g.NonceSize())
	rand.Read(n)
	sealed := g.Seal(nil, n, data, nil)
	return sealed[:len(sealed)-g.Overhead()], sealed[len(sealed)-g.Overhead():], n
}
func upload(path string) {
	data, e := os.ReadFile(path)
	if e != nil {
		fmt.Println(e)
		return
	}
	c, t, n := encrypt(data)
	x, e := request("POST", "/files", map[string]any{"filename": filepath.Base(path), "ciphertext": hex.EncodeToString(c), "auth_tag": hex.EncodeToString(t), "nonce": hex.EncodeToString(n)})
	fmt.Println(x, e)
}
func request(method, path string, v any) (map[string]any, error) {
	var r io.Reader
	if v != nil {
		b, _ := json.Marshal(v)
		r = strings.NewReader(string(b))
	}
	q, _ := http.NewRequest(method, cfg.Server+path, r)
	q.Header.Set("Authorization", "Bearer "+cfg.Access)
	if v != nil {
		q.Header.Set("Content-Type", "application/json")
	}
	res, e := http.DefaultClient.Do(q)
	if e != nil {
		return nil, e
	}
	defer res.Body.Close()
	var x map[string]any
	json.NewDecoder(res.Body).Decode(&x)
	return x, func() error {
		if res.StatusCode >= 300 {
			return errors.New("request failed")
		}
		return nil
	}()
}
func download(id string) {
	x, e := request("GET", "/files/"+id, nil)
	if e != nil {
		fmt.Println(e)
		return
	}
	c, _ := hex.DecodeString(x["ciphertext"].(string))
	t, _ := hex.DecodeString(x["auth_tag"].(string))
	n, _ := hex.DecodeString(x["nonce"].(string))
	b, _ := aes.NewCipher(key())
	g, _ := cipher.NewGCM(b)
	plain, e := g.Open(nil, n, append(c, t...), nil)
	if e != nil {
		fmt.Println("tamper detected: authentication failed")
		return
	}
	name := x["filename"].(string)
	if name == "" {
		name = id
	}
	os.WriteFile(name, plain, 0600)
	fmt.Println("downloaded", name)
}

var _ = sha256.Size
