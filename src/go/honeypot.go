package main

import (
	"bytes"
	"crypto/md5"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gregdel/pushover"
)

/* ====== GLOBAL STATE (thread-safe) ====== */

var (
	counterRequests        int64 // atomic
	counterRequests404     int64 // atomic
	counterRequestsAttacks int64 // atomic
	statsDurationWaitMS    int64 // atomic, milliseconds

	notifyMu                    sync.Mutex
	dtLastPushoverNotifyCountry = time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)
)

/* ====== TYPES ====== */

type HoneypotRequest struct {
	http      *http.Request
	timestamp time.Time
	wait      time.Duration
	ip        string
	ipinfo    map[string]interface{}
	cookie    string
	postBody  string
	isAttack  bool
}

// LogEntry is the structured JSON line written per request.
type LogEntry struct {
	Timestamp string                 `json:"timestamp"`
	IP        string                 `json:"ip"`
	WaitSec   float64                `json:"wait_sec"`
	Method    string                 `json:"method"`
	Host      string                 `json:"host"`
	Path      string                 `json:"path"`
	UserAgent string                 `json:"user_agent"`
	Cookie    string                 `json:"cookie"`
	IsAttack  bool                   `json:"is_attack"`
	PostBody  string                 `json:"post_body,omitempty"`
	IPInfo    map[string]interface{} `json:"ipinfo,omitempty"`
}

/* ====== MAIN ====== */

func main() {
	http.HandleFunc("/", handler)
	fmt.Println("Server is listening on port 80")
	log.Fatal(http.ListenAndServe(":80", nil))
}

func handler(w http.ResponseWriter, r *http.Request) {

	/* ── Prometheus metrics endpoint ── */
	if r.URL.Path == "/metrics" {
		if !basicAuth(w, r) {
			return
		}
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		fmt.Fprintf(w, "# HELP http_requests_all Total number of requests\n")
		fmt.Fprintf(w, "# TYPE http_requests_all counter\n")
		fmt.Fprintf(w, "http_requests_all{} %d\n", atomic.LoadInt64(&counterRequests))
		fmt.Fprintf(w, "# HELP http_requests Requests by classification\n")
		fmt.Fprintf(w, "# TYPE http_requests counter\n")
		fmt.Fprintf(w, "http_requests{code=\"404\"} %d\n", atomic.LoadInt64(&counterRequests404))
		fmt.Fprintf(w, "http_requests{code=\"attack\"} %d\n", atomic.LoadInt64(&counterRequestsAttacks))
		fmt.Fprintf(w, "# HELP http_duration_ms Cumulative tar-pit delay in milliseconds\n")
		fmt.Fprintf(w, "# TYPE http_duration_ms counter\n")
		fmt.Fprintf(w, "http_duration_ms{} %d\n", atomic.LoadInt64(&statsDurationWaitMS))
		return
	}

	/* ── Build request context ── */
	info := HoneypotRequest{
		http:      r,
		timestamp: time.Now(),
		wait:      time.Duration(rand.Float64()*20) * time.Second,
		ip:        getIPAddress(r),
	}

	atomic.AddInt64(&counterRequests, 1)
	atomic.AddInt64(&statsDurationWaitMS, info.wait.Milliseconds())
	fmt.Println(info.timestamp.Format("2006-01-02 15:04:05"), " ", info.ip, " ", r.URL.Path)

	/* ── IP lookup (non-fatal) ── */
	var ipErr error
	info.ipinfo, ipErr = ipinfo(info.ip)
	if ipErr != nil {
		log.Printf("ipinfo lookup failed for %s: %v", info.ip, ipErr)
	}

	/* ── Pushover country notification (throttled to once/hour) ── */
	notifyCountry := getenv("PUSHOVER_NOTIFY_COUNTRY", "")
	if notifyCountry != "" && info.ipinfo != nil && info.ipinfo["country"] == notifyCountry {
		notifyMu.Lock()
		canNotify := time.Since(dtLastPushoverNotifyCountry).Hours() >= 1
		if canNotify {
			dtLastPushoverNotifyCountry = time.Now()
		}
		notifyMu.Unlock()
		if canNotify {
			go sendPushover(info)
			go sendWebhook(info, "country_notify")
		}
	}

	/* ── Cookie: read existing or create new ── */
	info.cookie = getHoneypotCookie(r)
	if info.cookie == "" {
		info.cookie = getMD5Hash(info.timestamp.String())
	}
	expire := time.Now().AddDate(24, 0, 0) // 24 years
	http.SetCookie(w, &http.Cookie{
		Name:     "akhp",
		Value:    info.cookie,
		Path:     "/",
		Domain:   strings.Split(r.Host, ":")[0],
		Expires:  expire,
		MaxAge:   86400 * 365,
		HttpOnly: true,
		SameSite: http.SameSiteDefaultMode,
	})

	/* ── Read POST/PUT body early (before tar-pit sleep) ── */
	if r.Method == http.MethodPost || r.Method == http.MethodPut {
		body, err := io.ReadAll(io.LimitReader(r.Body, 8*1024)) // cap at 8 KB
		if err == nil {
			info.postBody = string(body)
		}
	}

	/* ── Tar-pit: delay every response to waste attacker time ── */
	time.Sleep(info.wait)

	/* ── Ensure request is always logged regardless of code path ── */
	defer func() { go logJSON(info) }()

	/* ── Route ── */
	switch r.URL.Path {
	case "/":
		serveFile(w, "assets/nginx_default.html")
	case "/favicon.ico":
		w.Header().Set("Content-Type", "image/ico")
		serveFile(w, "assets/favicon.ico")
	case "/.well-known/security.txt":
		w.Header().Set("Content-Type", "text/plain")
		serveFile(w, "security.txt")
	case "/robots.txt":
		w.Header().Set("Content-Type", "text/plain")
		serveFile(w, "assets/robots.txt")
	case "/actuator/health":
		markAttack(&info)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"status":"UP","groups":["nuclear"]}`)
	case "/admin/config.php", "/admin//config.php":
		markAttack(&info)
		fmt.Fprintf(w, "No valid entrypoint")
	case "/bag2":
		markAttack(&info)
		fmt.Fprintf(w, "Thanks for visiting bag2")
	case "/config/getuser":
		markAttack(&info)
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprintf(w, "admindemo:$1$YFru^g}j$iY7qJ0IEAcUGO5wJdUTbO1\n")
	case "/login_sid.lua":
		markAttack(&info)
		w.Header().Set("Content-Type", "text/xml")
		fmt.Fprintf(w, `<?xml version="1.0" encoding="utf-8"?><SessionInfo><SID>0000000000000000</SID><Challenge>bd011af8</Challenge><BlockTime>11</BlockTime><Rights></Rights><Users><User>admin</User><User last="1">fritz6332</User></Users></SessionInfo>`)
	case "/owa/":
		w.Header().Set("Location", "/owa/auth/logon.aspx")
		http.Error(w, "Moved", 301)
	case "/owa/auth/logon.aspx":
		markAttack(&info)
		serveFile(w, "assets/owa_logon_aspx.html")
	default:
		switch {
		case strings.HasSuffix(r.URL.Path, "/.env"):
			markAttack(&info)
			w.Header().Set("Content-Type", "text/plain")
			fmt.Fprintf(w, "S3_BUCKET=\"superbucket\"\nSECRET_KEY=\"password123456abc\"\n")
		case strings.HasSuffix(r.URL.Path, "/.htpasswd"):
			markAttack(&info)
			w.Header().Set("Content-Type", "text/plain")
			fmt.Fprintf(w, "admindemo:$1$YFru^g}j$iY7qJ0IEAcUGO5wJdUTbO1\n")
		case strings.HasSuffix(r.URL.Path, "/id_rsa"):
			markAttack(&info)
			w.Header().Set("Content-Type", "text/plain")
			serveFile(w, "assets/fake_id_rsa")
		case strings.HasSuffix(r.URL.Path, "swagger.json"):
			markAttack(&info)
			w.Header().Set("Content-Type", "application/json")
			serveFile(w, "assets/swagger.json")
		case strings.HasSuffix(r.URL.Path, "/owa/auth/x.js"):
			markAttack(&info)
			w.Header().Set("Content-Type", "text/javascript")
			fmt.Fprintf(w, `while (true) { alert("The bee makes sum sum!"); }`)
		default:
			pmaIndex, _ := regexp.MatchString(`/(pma|pmd|[_-]*php[_-]*myadmin|myadmin)/(index\.php)?$`, strings.ToLower(r.URL.Path))
			pmaSetup, _ := regexp.MatchString(`/(pma|pmd|[_-]*php[_-]*myadmin|myadmin)/scripts/setup\.php$`, strings.ToLower(r.URL.Path))
			switch {
			case pmaIndex:
				markAttack(&info)
				serveFile(w, "assets/phpmyadmin_index.html")
			case pmaSetup:
				markAttack(&info)
				serveFile(w, "assets/phpmyadmin_scripts_setup.html")
			default:
				atomic.AddInt64(&counterRequests404, 1)
				http.Error(w, "File not found.", 404)
			}
		}
	}
}

// markAttack flags a request as a known attack pattern, increments the attack
// counter, and fires asynchronous notifications and blacklist logging.
func markAttack(info *HoneypotRequest) {
	info.isAttack = true
	atomic.AddInt64(&counterRequestsAttacks, 1)
	go logIPBlacklist(*info)
	go sendWebhook(*info, "attack")
}

/* ====== LOGGING ====== */

// logJSON appends a structured JSON line to /var/log/honeypot.jsonl.
// Attack IPs are additionally written to the legacy blacklist file.
func logJSON(info HoneypotRequest) {
	entry := LogEntry{
		Timestamp: info.timestamp.Format(time.RFC3339),
		IP:        info.ip,
		WaitSec:   float64(info.wait.Milliseconds()) / 1000,
		Method:    info.http.Method,
		Host:      info.http.Host,
		Path:      info.http.URL.Path,
		UserAgent: info.http.Header.Get("User-Agent"),
		Cookie:    info.cookie,
		IsAttack:  info.isAttack,
		PostBody:  info.postBody,
		IPInfo:    info.ipinfo,
	}

	data, err := json.Marshal(entry)
	if err != nil {
		log.Printf("logJSON marshal error: %v", err)
		return
	}

	f, err := os.OpenFile("/var/log/honeypot.jsonl", os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		log.Printf("logJSON open error: %v", err)
		return
	}
	defer f.Close()
	f.Write(append(data, '\n'))
}

// logIPBlacklist appends the attacker IP to the legacy plaintext blacklist.
func logIPBlacklist(info HoneypotRequest) {
	f, err := os.OpenFile("/var/log/honeypot.ip.blacklist.log", os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		log.Printf("logIPBlacklist open error: %v", err)
		return
	}
	defer f.Close()
	f.Write([]byte(info.ip + "\n"))
}

/* ====== NOTIFICATIONS ====== */

// sendPushover sends a Pushover push notification.
func sendPushover(info HoneypotRequest) {
	app := getenv("PUSHOVER_APP", "")
	recipient := getenv("PUSHOVER_RECIPIENT", "")
	if app == "" || recipient == "" {
		return
	}

	po := pushover.New(app)
	rec := pushover.NewRecipient(recipient)

	msg := "Check the honeypot — request from notify country\n"
	msg += "URL: " + info.http.URL.Scheme + "://" + info.http.Host + info.http.URL.Path + "\n"
	msg += "Server: " + getenv("NAME", "") + "\n"
	msg += "IP: " + info.ip + "\n"
	if info.ipinfo != nil {
		msg += fmt.Sprintf("Location: %s %s; %s; %s\n",
			info.ipinfo["postal"], info.ipinfo["city"],
			info.ipinfo["region"], info.ipinfo["country"])
	}

	message := &pushover.Message{
		Title:     "Honeypot: country " + getenv("PUSHOVER_NOTIFY_COUNTRY", ""),
		Message:   msg,
		Priority:  pushover.PriorityNormal,
		Timestamp: time.Now().Unix(),
		Retry:     60 * time.Second,
		Expire:    time.Hour,
		Sound:     pushover.SoundGamelan,
	}
	if _, err := po.SendMessage(message, rec); err != nil {
		log.Printf("pushover send error: %v", err)
	}
}

// sendWebhook fires a generic HTTP POST webhook (e.g. n8n, Slack, etc.).
// Set WEBHOOK_URL in the environment to enable. Optionally set WEBHOOK_SECRET
// for a shared secret sent in the X-Honeypot-Secret header.
func sendWebhook(info HoneypotRequest, event string) {
	url := getenv("WEBHOOK_URL", "")
	if url == "" {
		return
	}

	payload := map[string]interface{}{
		"event":      event,
		"server":     getenv("NAME", ""),
		"timestamp":  info.timestamp.Format(time.RFC3339),
		"ip":         info.ip,
		"method":     info.http.Method,
		"host":       info.http.Host,
		"path":       info.http.URL.Path,
		"user_agent": info.http.Header.Get("User-Agent"),
		"is_attack":  info.isAttack,
		"ipinfo":     info.ipinfo,
	}
	if info.postBody != "" {
		payload["post_body"] = info.postBody
	}

	body, err := json.Marshal(payload)
	if err != nil {
		log.Printf("webhook marshal error: %v", err)
		return
	}

	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		log.Printf("webhook request build error: %v", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	if secret := getenv("WEBHOOK_SECRET", ""); secret != "" {
		req.Header.Set("X-Honeypot-Secret", secret)
	}

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("webhook send error: %v", err)
		return
	}
	defer resp.Body.Close()
	log.Printf("webhook fired event=%s status=%d", event, resp.StatusCode)
}

/* ====== HELPERS ====== */

func serveFile(w http.ResponseWriter, filename string) {
	f, err := os.Open(filename)
	if err != nil {
		http.Error(w, "File not found.", 404)
		return
	}
	defer f.Close()
	io.Copy(w, f)
}

func basicAuth(w http.ResponseWriter, r *http.Request) bool {
	admin := getenv("METRICS_USER", "admin")
	password := getenv("METRICS_PASSWORD", "password")
	realm := getenv("METRICS_REALM", "Prometheus Server")

	user, pass, ok := r.BasicAuth()
	if !ok ||
		subtle.ConstantTimeCompare([]byte(user), []byte(admin)) != 1 ||
		subtle.ConstantTimeCompare([]byte(pass), []byte(password)) != 1 {
		w.Header().Set("WWW-Authenticate", `Basic realm="`+realm+`"`)
		w.WriteHeader(401)
		w.Write([]byte("Unauthorized.\n"))
		return false
	}
	return true
}

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// ipinfo calls the goo1.de IP info API and returns the result map.
// Returns a non-nil error instead of crashing the process on failure.
func ipinfo(ip string) (map[string]interface{}, error) {
	client := &http.Client{Timeout: 3 * time.Second}

	req, err := http.NewRequest(http.MethodGet, "https://api.goo1.de/ipinfo.scan.json?ip="+ip, nil)
	if err != nil {
		return nil, err
	}

	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	body, err := io.ReadAll(res.Body) // io.ReadAll — ioutil.ReadAll removed in Go 1.22
	if err != nil {
		return nil, err
	}

	var results map[string]map[string]interface{}
	if err := json.Unmarshal(body, &results); err != nil {
		return nil, err
	}

	return results["result"], nil
}

func getHoneypotCookie(r *http.Request) string {
	for _, c := range r.Cookies() {
		if c.Name == "akhp" {
			return c.Value
		}
	}
	return ""
}

func getMD5Hash(text string) string {
	h := md5.New()
	h.Write([]byte(text))
	return hex.EncodeToString(h.Sum(nil))
}

// getIPAddress extracts the real client IP, respecting Cloudflare, HAProxy,
// and Traefik headers before falling back to RemoteAddr.
func getIPAddress(r *http.Request) string {
	if v := r.Header.Get("CF-Connecting-IP"); v != "" {
		return v
	}
	if v := r.Header.Get("X-Forwarded-For"); v != "" {
		// X-Forwarded-For can be a comma-separated list; first entry is the client
		return strings.TrimSpace(strings.Split(v, ",")[0])
	}
	if v := r.Header.Get("X-Real-IP"); v != "" {
		return v
	}
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return ip
}
