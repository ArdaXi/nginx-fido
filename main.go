package main

import (
	"bufio"
	"bytes"
	"crypto/subtle"
	"crypto/tls"
	"encoding/binary"
	"encoding/gob"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"syscall"
	"time"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/ssh/terminal"

	"github.com/gorilla/securecookie"
	"github.com/tstranex/u2f"
	bolt "go.etcd.io/bbolt"
)

const appID = "https://localhost:3483"

var trustedFacets = []string{appID}

var secureCookie *securecookie.SecureCookie
var runAsServer bool

type registration struct {
	data    u2f.Registration
	counter uint32
	key     []byte
}

type SessionCookie struct {
	Username  string
	IP        string
	KeyHandle []byte
}

type StatusResult struct {
	Username string
	Password bool
}

func prompt(prompt string, password bool) ([]byte, error) {
	tries := 0
	var bytes []byte
	var err error
	scanner := bufio.NewScanner(os.Stdin)
	for {
		fmt.Print(prompt)
		if password {
			bytes, err = terminal.ReadPassword(int(syscall.Stdin))
			if err != nil {
				return nil, err
			}
		} else {
			if !scanner.Scan() {
				if err := scanner.Err(); err != nil {
					return nil, err
				}
				tries++
				if tries < 3 {
					continue
				} else {
					return nil, fmt.Errorf("No input provided")
				}
			}
			bytes = scanner.Bytes()
		}
		if len(bytes) == 0 {
			tries++
			if tries < 3 {
				continue
			} else {
				return nil, fmt.Errorf("No input provided")
			}
		}
		return bytes, nil
	}
}

func changePassword(db *bolt.DB) {
	existent := false
	username, err := prompt("Username: ", false)
	if err != nil {
		log.Fatal(err)
	}
	err = db.Update(func(tx *bolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists(username)
		if err != nil {
			return err
		}
		if b.Get([]byte("password")) != nil {
			existent = true
		}
		return nil
	})
	if err != nil {
		log.Fatal(err)
	}
	if existent {
		fmt.Println("User already exists, modifying")
	}
	password, err := prompt("New password: ", true)
	if err != nil {
		log.Fatal(err)
	}
	hashed, err := bcrypt.GenerateFromPassword(password, 13)
	if err != nil {
		log.Fatal(err)
	}
	err = db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(username)
		if b == nil {
			return fmt.Errorf("Bucket not found: %s", username)
		}
		return b.Put([]byte("password"), hashed)
	})
	os.Exit(0)
}

func makeCookie(name string, value string, maxAge int) *http.Cookie {
	return &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		Secure:   true,
		HttpOnly: true,
		MaxAge:   maxAge,
		SameSite: http.SameSiteStrictMode,
	}
}

func getIp(r *http.Request) string {
	ip := r.Header.Get("X-Forwarded-For")
	if ip == "" {
		ip = strings.Split(r.RemoteAddr, ":")[0]
	}
	return ip
}

func passwordLogin(db *bolt.DB) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		username := r.FormValue("username")
		if username == "" {
			http.Error(w, "no username provided", http.StatusBadRequest)
			return
		}
		if strings.HasPrefix(username, ".") {
			http.Error(w, "invalid username provided", http.StatusBadRequest)
			return
		}
		password := r.FormValue("password")
		if password == "" {
			http.Error(w, "no password provided", http.StatusBadRequest)
			return
		}
		var hash []byte
		err := db.View(func(tx *bolt.Tx) error {
			b := tx.Bucket([]byte(username))
			if b == nil {
				return fmt.Errorf("Bucket %s not found", username)
			}
			hash = b.Get([]byte("password"))
			if hash == nil {
				return fmt.Errorf("Password not found for user %s", username)
			}
			return nil
		})
		if err != nil {
			log.Printf("db error: %v", err)
			time.Sleep(10 * time.Second)
			http.Error(w, "Credentials incorrect", http.StatusForbidden)
			return
		}
		err = bcrypt.CompareHashAndPassword(hash, []byte(password))
		if err != nil {
			log.Printf("bcrypt error: %v", err)
			time.Sleep(10 * time.Second)
			http.Error(w, "Credentials incorrect", http.StatusForbidden)
			return
		}

		cookieName := "session1"
		encoded, err := secureCookie.Encode(cookieName, username)
		if err != nil {
			log.Printf("securecookie error: %v", err)
			http.Error(w, "Failed to login", http.StatusInternalServerError)
			return
		}
		http.SetCookie(w, makeCookie(cookieName, encoded, 86400*365))
		w.Write([]byte("success"))
	}
}

func status(db *bolt.DB) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		result := StatusResult{}
		cookieName := "session1"
		cookie, err := r.Cookie(cookieName)
		if err != nil {
			json.NewEncoder(w).Encode(result)
			return
		}
		if err = secureCookie.Decode(cookieName, cookie.Value, &result.Username); err != nil {
			http.SetCookie(w, makeCookie(cookieName, "", -1))
			json.NewEncoder(w).Encode(result)
			return
		}
		result.Password = true
		json.NewEncoder(w).Encode(result)
		return
	}
}

func checkAuth(db *bolt.DB, w http.ResponseWriter, r *http.Request, needU2F bool) (string, []registration, error) {
	cookieName := "session1"
	cookie, err := r.Cookie(cookieName)
	if err != nil {
		http.Error(w, "no cookie present", http.StatusForbidden)
		return "", nil, err
	}
	var username string
	if err = secureCookie.Decode(cookieName, cookie.Value, &username); err != nil {
		http.SetCookie(w, makeCookie(cookieName, "", -1))
		http.Error(w, "session cookie invalid", http.StatusForbidden)
		return "", nil, err
	}
	registrations := make([]registration, 0)
	if err = db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(username))
		if b == nil {
			return fmt.Errorf("Bucket %s not found", username)
		}
		regs := b.Bucket([]byte("registrations"))
		if regs == nil {
			return nil
		}
		err = regs.ForEach(func(k, v []byte) error {
			regBucket := regs.Bucket(k)
			if regBucket == nil {
				return nil
			}
			regData := regBucket.Get([]byte("registration"))
			if regData == nil {
				log.Printf("Bucket registration not found in %s", k)
				return nil
			}
			var u2fRegistration u2f.Registration
			err := u2fRegistration.UnmarshalBinary(regData)
			if err != nil {
				return err
			}
			var counter uint32 = 0
			if counterData := regBucket.Get([]byte("counter")); counterData != nil {
				counter = binary.BigEndian.Uint32(counterData)
			}
			registrations = append(registrations, registration{
				data:    u2fRegistration,
				counter: counter,
				key:     k,
			})
			return nil
		})
		return err
	}); err != nil {
		http.Error(w, "failed to lookup registrations", http.StatusInternalServerError)
		return "", nil, err
	}
	if needU2F && len(registrations) > 0 {
		cookieName = "session2"
		cookie, err := r.Cookie(cookieName)
		if err != nil {
			http.Error(w, "not logged in with u2f", http.StatusForbidden)
			return "", nil, fmt.Errorf("No keyhandle found in cookie, but %v registrations", len(registrations))
		}
		var data SessionCookie
		if err = secureCookie.Decode(cookieName, cookie.Value, &data); err != nil {
			http.SetCookie(w, makeCookie(cookieName, "", -1))
			http.Error(w, "session cookie invalid", http.StatusForbidden)
			return "", nil, err
		}
		ip := getIp(r)
		if subtle.ConstantTimeCompare([]byte(ip), []byte(data.IP)) == 0 {
			http.Error(w, "ip not in session", http.StatusForbidden)
			return "", nil, fmt.Errorf("Connecting from wrong IP")
		}
	}
	return username, registrations, nil
}

func storeChallenge(db *bolt.DB, username string, challenge *u2f.Challenge) error {
	var challengeData bytes.Buffer
	enc := gob.NewEncoder(&challengeData)
	if err := enc.Encode(challenge); err != nil {
		return err
	}
	return db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(username))
		if b == nil {
			return fmt.Errorf("Bucket %s not found", username)
		}
		return b.Put([]byte("challenge"), challengeData.Bytes())
	})
}

func getChallenge(db *bolt.DB, username string) (*u2f.Challenge, error) {
	var challengeData []byte
	if err := db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(username))
		if b == nil {
			return fmt.Errorf("Bucket %s not found", username)
		}
		challengeData = b.Get([]byte("challenge"))
		if challengeData == nil {
			return fmt.Errorf("Challenge in bucket %s not found", username)
		}
		return nil
	}); err != nil {
		return nil, err
	}
	var challenge u2f.Challenge
	if err := gob.NewDecoder(bytes.NewBuffer(challengeData)).Decode(&challenge); err != nil {
		return nil, err
	}
	return &challenge, nil
}

func registerRequest(db *bolt.DB) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		username, registrations, err := checkAuth(db, w, r, true)
		if err != nil {
			log.Printf("checkAuth err: %v", err)
			return
		}
		challenge, err := u2f.NewChallenge(appID, trustedFacets)
		if err != nil {
			log.Printf("u2f.NewChallenge error: %v", err)
			http.Error(w, "failed to generate challenge", http.StatusInternalServerError)
			return
		}
		if err := storeChallenge(db, username, challenge); err != nil {
			log.Printf("db error: %v", err)
			http.Error(w, "failed to store challenge", http.StatusInternalServerError)
			return
		}
		var regs = make([]u2f.Registration, len(registrations))
		for _, v := range registrations {
			regs = append(regs, v.data)
		}
		req := u2f.NewWebRegisterRequest(challenge, regs)
		//TODO: fix upstream
		if req.RegisteredKeys == nil {
			req.RegisteredKeys = make([]u2f.RegisteredKey, 0)
		}
		json.NewEncoder(w).Encode(req)
	}
}

func registerResponse(db *bolt.DB) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		username, _, err := checkAuth(db, w, r, true)
		if err != nil {
			log.Printf("checkAuth err: %v", err)
			return
		}
		var regResp u2f.RegisterResponse
		if err := json.NewDecoder(r.Body).Decode(&regResp); err != nil {
			log.Printf("json.Decode err: %v", err)
			http.Error(w, "invalid response", http.StatusBadRequest)
			return
		}
		challenge, err := getChallenge(db, username)
		if err != nil {
			log.Printf("getChallenge err: %v", err)
			http.Error(w, "couldn't find challenge", http.StatusBadRequest)
			return
		}
		reg, err := u2f.Register(regResp, *challenge, nil)
		if err != nil {
			log.Printf("u2f.Register error: %v", err)
			http.Error(w, "error verifying response", http.StatusBadRequest)
			return
		}
		regData, err := reg.MarshalBinary()
		if err != nil {
			log.Printf("u2f.Registration.MarshalBinary err: %v", err)
			http.Error(w, "couldn't form registraton", http.StatusInternalServerError)
			return
		}
		if err := db.Update(func(tx *bolt.Tx) error {
			b := tx.Bucket([]byte(username))
			if b == nil {
				return fmt.Errorf("Bucket %s not found", username)
			}
			if err := b.Delete([]byte("challenge")); err != nil {
				return err
			}
			regs, err := b.CreateBucketIfNotExists([]byte("registrations"))
			if err != nil {
				return err
			}
			key, err := regs.NextSequence()
			if err != nil {
				return err
			}
			keyBytes := make([]byte, 8)
			binary.BigEndian.PutUint64(keyBytes, key)
			regB, err := regs.CreateBucket(keyBytes)
			if err != nil {
				return err
			}
			return regB.Put([]byte("registration"), regData)
		}); err != nil {
			log.Printf("db err: %v", err)
			http.Error(w, "failed to store registration", http.StatusServiceUnavailable)
			return
		}
		w.Write([]byte("success"))
	}
}

func signRequest(db *bolt.DB) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		username, registrations, err := checkAuth(db, w, r, false)
		if err != nil {
			log.Printf("checkAuth err: %v", err)
			return
		}
		if registrations == nil {
			http.Error(w, "registration missing", http.StatusBadRequest)
			return
		}
		if len(registrations) == 0 {
			http.Error(w, "registration missing", http.StatusBadRequest)
			return
		}
		challenge, err := u2f.NewChallenge(appID, trustedFacets)
		if err != nil {
			log.Printf("u2f.NewChallenge error: %v", err)
			http.Error(w, "error", http.StatusInternalServerError)
			return
		}
		if err := storeChallenge(db, username, challenge); err != nil {
			log.Printf("db error: %v", err)
			http.Error(w, "failed to store challenge", http.StatusInternalServerError)
			return
		}
		var regs = make([]u2f.Registration, len(registrations))
		for _, v := range registrations {
			regs = append(regs, v.data)
		}
		req := challenge.SignRequest(regs)
		json.NewEncoder(w).Encode(req)
	}
}

func signResponse(db *bolt.DB) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		username, registrations, err := checkAuth(db, w, r, false)
		if err != nil {
			log.Printf("checkAuth err: %v", err)
			return
		}
		if len(registrations) == 0 {
			http.Error(w, "no registrations found", http.StatusBadRequest)
			return
		}
		var signResp u2f.SignResponse
		if err := json.NewDecoder(r.Body).Decode(&signResp); err != nil {
			log.Printf("json.Decode err: %v", err)
			http.Error(w, "invalid response", http.StatusBadRequest)
			return
		}
		challenge, err := getChallenge(db, username)
		if err != nil {
			log.Printf("getChallenge err: %v", err)
			http.Error(w, "couldn't find challenge", http.StatusBadRequest)
			return
		}
		var authErr error
		for _, reg := range registrations {
			if newCounter, err := reg.data.Authenticate(signResp, *challenge, reg.counter); err == nil {
				if err := db.Update(func(tx *bolt.Tx) error {
					b := tx.Bucket([]byte(username))
					if b == nil {
						return fmt.Errorf("Bucket %s not found", username)
					}
					regs := b.Bucket([]byte("registrations"))
					if regs == nil {
						return fmt.Errorf("Registrations not found in bucket %s", username)
					}
					data := regs.Bucket(reg.key)
					if data == nil {
						return fmt.Errorf("%s/registrations/%s not found", username, reg.key)
					}
					counterData := make([]byte, 8)
					binary.BigEndian.PutUint32(counterData, newCounter)
					return data.Put([]byte("counter"), counterData)
				}); err != nil {
					log.Printf("db error: %v", err)
					http.Error(w, "failed to update counter", http.StatusInternalServerError)
					return
				}
				ip := getIp(r)
				data := SessionCookie{
					Username:  username,
					KeyHandle: []byte(signResp.KeyHandle),
					IP:        ip,
				}
				cookieName := "session2"
				encoded, err := secureCookie.Encode(cookieName, data)
				if err != nil {
					log.Printf("securecookie error: %v", err)
					http.Error(w, "Failed to login", http.StatusInternalServerError)
					return
				}
				http.SetCookie(w, makeCookie(cookieName, encoded, 86400))
				w.Write([]byte("success"))
				return
			} else {
				authErr = err
			}
		}

		log.Printf("u2fRegistration.Authenticate error: %v", authErr)
		http.Error(w, "error verifying response", http.StatusForbidden)
		return
	}
}

func logout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Only POST allowed", http.StatusBadRequest)
		return
	}
	http.SetCookie(w, makeCookie("session1", "", -1))
	http.SetCookie(w, makeCookie("session2", "", -1))
	w.Write([]byte("Success"))
}

func auth(db *bolt.DB) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		username, _, err := checkAuth(db, w, r, true)
		if err != nil {
			log.Printf("checkAuth err: %s", err)
			return
		}
		w.Header().Set("X-Forwarded-User", username)
		w.Write([]byte("Logged in as "))
		w.Write([]byte(username))
		return
	}
}

func init() {
	flag.BoolVar(&runAsServer, "server", false, "Run as server")
}

func main() {
	db, err := bolt.Open("nginx-fido.db", 0600, nil)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()
	flag.Parse()

	if !runAsServer {
		changePassword(db)
	}

	var hashKey []byte
	var blockKey []byte
	if err := db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(".config"))
		if b == nil {
			return fmt.Errorf("Config not present")
		}
		hashKey = b.Get([]byte("hashkey"))
		if hashKey == nil {
			return fmt.Errorf("Hashkey not present")
		}
		blockKey = b.Get([]byte("blockkey"))
		if blockKey == nil {
			return fmt.Errorf("Blockkey not present")
		}
		return nil
	}); err != nil {
		hashKey = securecookie.GenerateRandomKey(64)
		if hashKey == nil {
			log.Fatal("Failed to generate hash key!")
		}
		blockKey = securecookie.GenerateRandomKey(32)
		if blockKey == nil {
			log.Fatal("Failed to generate block key!")
		}
		db.Update(func(tx *bolt.Tx) error {
			b, err := tx.CreateBucketIfNotExists([]byte(".config"))
			if err != nil {
				return err
			}
			b.Put([]byte("blockkey"), blockKey)
			b.Put([]byte("hashkey"), hashKey)
			return nil
		})
	}
	secureCookie = securecookie.New(hashKey, blockKey)

	http.HandleFunc("/manage", manageHandler)
	http.HandleFunc("/", loginHandler)
	http.HandleFunc("/logout", logout)
	http.HandleFunc("/auth", auth(db))
	http.HandleFunc("/registerRequest", registerRequest(db))
	http.HandleFunc("/registerResponse", registerResponse(db))
	http.HandleFunc("/signRequest", signRequest(db))
	http.HandleFunc("/signResponse", signResponse(db))
	http.HandleFunc("/passwordLogin", passwordLogin(db))
	http.HandleFunc("/status", status(db))
	fs := http.FileServer(http.Dir("static"))
	http.Handle("/static/", http.StripPrefix("/static", fs))

	certs, err := tls.X509KeyPair([]byte(tlsCert), []byte(tlsKey))
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("Running on %s", appID)

	var s http.Server
	s.Addr = ":3483"
	s.TLSConfig = &tls.Config{Certificates: []tls.Certificate{certs}}
	log.Fatal(s.ListenAndServeTLS("", ""))
}
