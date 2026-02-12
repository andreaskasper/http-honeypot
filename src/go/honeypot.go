package main

import (
	"bytes"
	"crypto/md5"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gregdel/pushover"
)

/* ═══════════════════════════════════════════════════════════════════════════
   GLOBAL STATE  (all accesses are thread-safe)
═══════════════════════════════════════════════════════════════════════════ */

var (
	counterRequests        int64 // atomic
	counterRequests404     int64 // atomic
	counterRequestsAttacks int64 // atomic
	statsDurationWaitMS    int64 // atomic, milliseconds

	notifyMu                    sync.Mutex
	dtLastPushoverNotifyCountry = time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)

	// logMu serialises writes + rotations so two goroutines don't race on Rename
	logMu sync.Mutex
)

/* ═══════════════════════════════════════════════════════════════════════════
   RATE LIMITER  —  per-IP sliding window, 1-minute buckets
═══════════════════════════════════════════════════════════════════════════ */

type rateLimiter struct {
	mu      sync.Mutex
	counts  map[string]int
	limit   int
	resetAt time.Time
}

var rl = &rateLimiter{
	counts:  make(map[string]int),
	resetAt: time.Now().Add(time.Minute),
}

func (r *rateLimiter) allow(ip string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if time.Now().After(r.resetAt) {
		r.counts = make(map[string]int)
		r.resetAt = time.Now().Add(time.Minute)
	}
	r.counts[ip]++
	return r.counts[ip] <= r.limit
}

/* ═══════════════════════════════════════════════════════════════════════════
   TYPES
═══════════════════════════════════════════════════════════════════════════ */

type HoneypotRequest struct {
	http       *http.Request
	timestamp  time.Time
	wait       time.Duration
	ip         string
	ipinfo     map[string]interface{}
	cookie     string
	postBody   string
	apiKeyUsed string // captured from X-Api-Key / Authorization headers
	isAttack   bool
	attackTag  string
}

// LogEntry is the structured JSON line written per request.
type LogEntry struct {
	Timestamp  string                 `json:"timestamp"`
	IP         string                 `json:"ip"`
	WaitSec    float64                `json:"wait_sec"`
	Method     string                 `json:"method"`
	Host       string                 `json:"host"`
	Path       string                 `json:"path"`
	UserAgent  string                 `json:"user_agent"`
	Cookie     string                 `json:"cookie"`
	IsAttack   bool                   `json:"is_attack"`
	AttackTag  string                 `json:"attack_tag,omitempty"`
	PostBody   string                 `json:"post_body,omitempty"`
	APIKeyUsed string                 `json:"api_key_used,omitempty"`
	IPInfo     map[string]interface{} `json:"ipinfo,omitempty"`
}

/* ═══════════════════════════════════════════════════════════════════════════
   MAIN
═══════════════════════════════════════════════════════════════════════════ */

func main() {
	rl.limit = getenvInt("RATE_LIMIT_PER_MIN", 1000)
	log.Printf("honeypot starting | rate_limit=%d/min | log_disabled=%s | tar_pit_max=%ds | metrics_disabled=%s",
		rl.limit, getenv("LOG_DISABLED", "false"),
		getenvInt("TAR_PIT_MAX_SEC", 20), getenv("METRICS_DISABLED", "false"))

	http.HandleFunc("/", handler)
	log.Fatal(http.ListenAndServe(":80", nil))
}

/* ═══════════════════════════════════════════════════════════════════════════
   MAIN HANDLER
═══════════════════════════════════════════════════════════════════════════ */

func handler(w http.ResponseWriter, r *http.Request) {

	/* ── Prometheus metrics ───────────────────────────────────────────────── */
	if r.URL.Path == "/metrics" {
		if strings.EqualFold(getenv("METRICS_DISABLED", "false"), "true") {
			http.Error(w, "Not found.", 404)
			return
		}
		if !basicAuth(w, r) {
			return
		}
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		fmt.Fprintf(w, "# HELP http_requests_all Total requests\n")
		fmt.Fprintf(w, "# TYPE http_requests_all counter\nhttp_requests_all{} %d\n", atomic.LoadInt64(&counterRequests))
		fmt.Fprintf(w, "# HELP http_requests Requests by class\n")
		fmt.Fprintf(w, "# TYPE http_requests counter\n")
		fmt.Fprintf(w, "http_requests{code=\"404\"} %d\n", atomic.LoadInt64(&counterRequests404))
		fmt.Fprintf(w, "http_requests{code=\"attack\"} %d\n", atomic.LoadInt64(&counterRequestsAttacks))
		fmt.Fprintf(w, "# HELP http_duration_ms Cumulative tar-pit delay ms\n")
		fmt.Fprintf(w, "# TYPE http_duration_ms counter\nhttp_duration_ms{} %d\n", atomic.LoadInt64(&statsDurationWaitMS))
		return
	}

	/* ── Build request context ────────────────────────────────────────────── */
	info := HoneypotRequest{
		http:      r,
		timestamp: time.Now(),
		wait:      randomDelay(),
		ip:        getIPAddress(r),
	}

	atomic.AddInt64(&counterRequests, 1)
	atomic.AddInt64(&statsDurationWaitMS, info.wait.Milliseconds())
	log.Printf("%s  %s  %s  %s", info.timestamp.Format("2006-01-02 15:04:05"), info.ip, r.Method, r.URL.Path)

	/* ── Rate limiting ────────────────────────────────────────────────────── */
	if !rl.allow(info.ip) {
		w.WriteHeader(http.StatusTooManyRequests)
		return
	}

	/* ── IP info lookup (non-fatal) ───────────────────────────────────────── */
	var ipErr error
	info.ipinfo, ipErr = ipinfo(info.ip)
	if ipErr != nil {
		log.Printf("ipinfo lookup failed for %s: %v", info.ip, ipErr)
	}

	/* ── Capture API keys / Bearer tokens ────────────────────────────────── */
	info.apiKeyUsed = captureAPIKey(r)

	/* ── Log4Shell detection in headers ──────────────────────────────────── */
	if detectLog4Shell(r) {
		info.attackTag = "log4shell"
	}

	/* ── Pushover country notification (throttled to once/hour) ──────────── */
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

	/* ── Cookie: read existing or mint new ───────────────────────────────── */
	info.cookie = getHoneypotCookie(r)
	if info.cookie == "" {
		info.cookie = getMD5Hash(info.timestamp.String())
	}
	expire := time.Now().AddDate(24, 0, 0)
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

	/* ── Read POST/PUT body (capped at 8 KB) ─────────────────────────────── */
	if r.Method == http.MethodPost || r.Method == http.MethodPut {
		body, err := io.ReadAll(io.LimitReader(r.Body, 8*1024))
		if err == nil {
			info.postBody = string(body)
		}
	}

	/* ── Tar-pit delay ────────────────────────────────────────────────────── */
	time.Sleep(info.wait)

	/* ── Always log after handler returns ────────────────────────────────── */
	defer func() { go logJSON(info) }()

	/* ══════════════════════════════════════════════════════════════════════
	   ROUTING
	══════════════════════════════════════════════════════════════════════ */

	path := r.URL.Path
	pathLower := strings.ToLower(path)

	/* ── Safe / informational paths ───────────────────────────────────────── */
	switch path {
	case "/":
		serveFile(w, "assets/nginx_default.html")
		return
	case "/favicon.ico":
		w.Header().Set("Content-Type", "image/ico")
		serveFile(w, "assets/favicon.ico")
		return
	case "/.well-known/security.txt":
		w.Header().Set("Content-Type", "text/plain")
		serveFile(w, "security.txt")
		return
	case "/robots.txt":
		w.Header().Set("Content-Type", "text/plain")
		serveFile(w, "assets/robots.txt")
		return
	}

	/* ── Spring Boot Actuators ───────────────────────────────────────────── */
	switch path {
	case "/actuator/health":
		markAttack(&info, "spring-actuator-health")
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"status":"UP","groups":["liveness","readiness"]}`)
		return
	case "/actuator/env":
		markAttack(&info, "spring-actuator-env")
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"activeProfiles":["prod"],"propertySources":[{"name":"systemEnvironment","properties":{"DB_PASSWORD":{"value":"prod_db_pass_2024!"},"AWS_SECRET_ACCESS_KEY":{"value":"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"},"SPRING_DATASOURCE_URL":{"value":"jdbc:postgresql://prod-db.internal:5432/appdb"}}}]}`)
		return
	case "/actuator/beans", "/actuator/mappings", "/actuator/trace", "/actuator/httptrace":
		markAttack(&info, "spring-actuator")
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"_links":{},"beans":[]}`)
		return
	case "/actuator/heapdump":
		markAttack(&info, "spring-actuator-heapdump")
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Write([]byte("JAVA PROFILE 1.0.2\x00\x00\x00"))
		return
	case "/actuator/shutdown":
		markAttack(&info, "spring-actuator-shutdown")
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"message":"Shutting down, bye..."}`)
		return
	}

	/* ── WordPress ───────────────────────────────────────────────────────── */
	switch path {
	case "/wp-login.php":
		markAttack(&info, "wp-login")
		w.Header().Set("Content-Type", "text/html; charset=UTF-8")
		fmt.Fprint(w, wpLoginHTML())
		return
	case "/wp-admin/", "/wp-admin":
		markAttack(&info, "wp-admin")
		w.Header().Set("Location", "/wp-login.php?redirect_to=%2Fwp-admin%2F")
		w.WriteHeader(302)
		return
	case "/xmlrpc.php":
		markAttack(&info, "xmlrpc")
		w.Header().Set("Content-Type", "text/xml")
		fmt.Fprint(w, `<?xml version="1.0"?><methodResponse><fault><value><struct><member><name>faultCode</name><value><int>405</int></value></member><member><name>faultString</name><value><string>XML-RPC server accepts POST requests only.</string></value></member></struct></value></fault></methodResponse>`)
		return
	case "/wp-includes/wlwmanifest.xml":
		markAttack(&info, "wp-wlwmanifest")
		w.Header().Set("Content-Type", "text/xml")
		fmt.Fprint(w, `<?xml version="1.0" encoding="utf-8"?><manifest xmlns="http://schemas.microsoft.com/wlw/manifest/weblog"><options><clientType>WordPress</clientType><supportsSlug>Yes</supportsSlug></options></manifest>`)
		return
	}

	/* ── Joomla ──────────────────────────────────────────────────────────── */
	if path == "/administrator/" || path == "/administrator" {
		markAttack(&info, "joomla-admin")
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><body><form><h1>Joomla Administration</h1><input name="username"/><input type="password" name="passwd"/></form></body></html>`)
		return
	}

	/* ── Apache Tomcat Manager ───────────────────────────────────────────── */
	if path == "/manager/html" || path == "/host-manager/html" {
		markAttack(&info, "tomcat-manager")
		w.Header().Set("WWW-Authenticate", `Basic realm="Tomcat Manager Application"`)
		w.WriteHeader(401)
		fmt.Fprint(w, `<html><body><p>You are not authorized to view this page. If you have not changed any configuration files, please examine the file conf/tomcat-users.xml.</p></body></html>`)
		return
	}

	/* ── Apache Solr ─────────────────────────────────────────────────────── */
	if strings.HasPrefix(path, "/solr") {
		markAttack(&info, "apache-solr")
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"responseHeader":{"status":0,"QTime":1},"mode":"std","solr_home":"/var/solr/data","version":"9.4.0"}`)
		return
	}

	/* ── Jenkins ─────────────────────────────────────────────────────────── */
	switch path {
	case "/script":
		markAttack(&info, "jenkins-script")
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><body><h1>Script Console</h1><form method="POST"><textarea name="script"></textarea><input type="submit" value="Run"/></form></body></html>`)
		return
	case "/computer/(master)/api/json", "/computer/api/json":
		markAttack(&info, "jenkins-api")
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"_class":"hudson.model.Hudson","numExecutors":4,"version":"2.440"}`)
		return
	}

	/* ── H2 / JBoss Console ──────────────────────────────────────────────── */
	if path == "/console" || path == "/console/" || path == "/h2-console" {
		markAttack(&info, "h2-console")
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><head><title>H2 Console</title></head><body><h1>H2 Console</h1><form method="POST"><input name="url" value="jdbc:h2:~/test"/><input name="user" value="sa"/><input type="password" name="password"/><input type="submit" value="Connect"/></form></body></html>`)
		return
	}

	/* ── Kubernetes API ──────────────────────────────────────────────────── */
	switch path {
	case "/api/v1/pods", "/api/v1/namespaces/default/pods":
		markAttack(&info, "k8s-pods")
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"kind":"PodList","apiVersion":"v1","metadata":{"resourceVersion":"12345"},"items":[{"metadata":{"name":"app-deployment-abc12","namespace":"default"}}]}`)
		return
	case "/api/v1/secrets", "/api/v1/namespaces/default/secrets":
		markAttack(&info, "k8s-secrets")
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"kind":"SecretList","apiVersion":"v1","metadata":{},"items":[{"metadata":{"name":"db-credentials"},"data":{"password":"cHJvZF9wYXNzd29yZDEyMw=="}}]}`)
		return
	}

	/* ── Docker API ──────────────────────────────────────────────────────── */
	if strings.HasPrefix(path, "/v1.") && strings.Contains(path, "/containers") {
		markAttack(&info, "docker-api")
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `[{"Id":"abc123","Names":["/webapp"],"Image":"nginx:latest","Status":"running","Ports":[{"PrivatePort":80,"PublicPort":8080,"Type":"tcp"}]}]`)
		return
	}

	/* ── Microsoft Exchange ──────────────────────────────────────────────── */
	switch path {
	case "/owa/", "/owa":
		w.Header().Set("Location", "/owa/auth/logon.aspx")
		http.Error(w, "Moved", 301)
		return
	case "/owa/auth/logon.aspx":
		markAttack(&info, "owa-login")
		serveFile(w, "assets/owa_logon_aspx.html")
		return
	case "/ews/exchange.asmx":
		markAttack(&info, "exchange-ews")
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><body>Exchange Web Services are working.</body></html>`)
		return
	case "/autodiscover/autodiscover.json":
		markAttack(&info, "exchange-proxylogon")
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"Protocol":"Autodiscoverv1","Url":"https://autodiscover.contoso.com/autodiscover/autodiscover.xml"}`)
		return
	case "/ecp/", "/ecp":
		markAttack(&info, "exchange-ecp")
		w.Header().Set("WWW-Authenticate", `Basic realm="Exchange Control Panel"`)
		w.WriteHeader(401)
		return
	}

	/* ── Fortinet / VPN Appliances ───────────────────────────────────────── */
	switch {
	case strings.HasPrefix(path, "/remote/fgt_lang"):
		markAttack(&info, "fortinet-fgt")
		w.WriteHeader(200)
		w.Write([]byte("-72:LF"))
		return
	case path == "/remote/login" || path == "/remote/logincheck":
		markAttack(&info, "sonicwall-vpn")
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><title>SonicWall SSL-VPN</title><body><h2>SonicWall SSL-VPN 10.2</h2></body></html>`)
		return
	case path == "/dana-na/auth/url_default/welcome.cgi":
		markAttack(&info, "pulse-secure")
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><title>Ivanti Connect Secure</title><body><h2>Ivanti Connect Secure Portal</h2></body></html>`)
		return
	case path == "/+CSCOE+/logon.html":
		markAttack(&info, "cisco-asa-vpn")
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><title>SSL VPN Service</title><body><h2>Cisco Adaptive Security Appliance</h2></body></html>`)
		return
	}

	/* ── Grafana ─────────────────────────────────────────────────────────── */
	if strings.HasPrefix(path, "/grafana") || path == "/api/snapshots" || path == "/api/ds/query" {
		markAttack(&info, "grafana")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(401)
		fmt.Fprint(w, `{"message":"Unauthorized","traceID":"00000000000000000000000000000000"}`)
		return
	}

	/* ── Confluence ──────────────────────────────────────────────────────── */
	if strings.Contains(pathLower, "/pages/createpage") || strings.Contains(pathLower, "/rest/tinymce") {
		markAttack(&info, "confluence-rce")
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"statusCode":200,"message":"OK"}`)
		return
	}

	/* ── Liferay (CVE-2020-7961) ─────────────────────────────────────────── */
	if strings.HasPrefix(path, "/api/jsonws") {
		markAttack(&info, "liferay-rce")
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"exception":"com.liferay.portal.security.auth.PrincipalException"}`)
		return
	}

	/* ── phpMyAdmin ──────────────────────────────────────────────────────── */
	pmaIndex, _ := regexp.MatchString(`/(pma|pmd|[_-]*php[_-]*myadmin|myadmin)/(index\.php)?$`, pathLower)
	pmaSetup, _ := regexp.MatchString(`/(pma|pmd|[_-]*php[_-]*myadmin|myadmin)/scripts/setup\.php$`, pathLower)
	switch {
	case pmaIndex:
		markAttack(&info, "phpmyadmin-index")
		serveFile(w, "assets/phpmyadmin_index.html")
		return
	case pmaSetup:
		markAttack(&info, "phpmyadmin-setup")
		serveFile(w, "assets/phpmyadmin_scripts_setup.html")
		return
	}

	/* ── phpunit RCE (CVE-2017-9841) ─────────────────────────────────────── */
	if strings.Contains(pathLower, "phpunit") && strings.Contains(pathLower, "eval-stdin") {
		markAttack(&info, "phpunit-rce")
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprint(w, "PHP Fatal error: syntax error")
		return
	}

	/* ── AWS / GCP / DigitalOcean Metadata ───────────────────────────────── */
	switch {
	case strings.HasPrefix(path, "/latest/meta-data"):
		markAttack(&info, "aws-metadata")
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprint(w, "ami-id\nami-launch-index\nhostname\ninstance-id\ninstance-type\nlocal-ipv4\npublic-ipv4\n")
		return
	case strings.HasPrefix(path, "/computeMetadata/v1"):
		markAttack(&info, "gcp-metadata")
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"instance":{"id":"1234567890","zone":"projects/12345/zones/us-central1-a","serviceAccounts":{"default":{"email":"compute@developer.gserviceaccount.com"}}}}`)
		return
	case strings.HasPrefix(path, "/metadata/v1"):
		markAttack(&info, "do-metadata")
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"droplet_id":123456789,"hostname":"web-prod-01","region":"fra1"}`)
		return
	}

	/* ── Dynamic REST API IDOR trap ─────────────────────────────────────── */
	// Catches scanners probing /api/v*/users/1, /api/v*/accounts/42, etc.
	if restAPITrap(w, r, &info) {
		return
	}

	/* ── Old/legacy admin paths ──────────────────────────────────────────── */
	switch path {
	case "/admin/config.php", "/admin//config.php":
		markAttack(&info, "admin-config")
		fmt.Fprint(w, "No valid entrypoint")
		return
	case "/bag2":
		markAttack(&info, "bag2")
		fmt.Fprint(w, "Thanks for visiting bag2")
		return
	case "/config/getuser":
		markAttack(&info, "config-getuser")
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprint(w, "admindemo:$1$YFru^g}j$iY7qJ0IEAcUGO5wJdUTbO1\n")
		return
	case "/login_sid.lua":
		markAttack(&info, "fritzbox")
		w.Header().Set("Content-Type", "text/xml")
		fmt.Fprint(w, `<?xml version="1.0" encoding="utf-8"?><SessionInfo><SID>0000000000000000</SID><Challenge>bd011af8</Challenge><BlockTime>11</BlockTime><Rights></Rights><Users><User>admin</User><User last="1">fritz6332</User></Users></SessionInfo>`)
		return
	}

	/* ── Suffix-based traps ──────────────────────────────────────────────── */
	switch {
	case strings.HasSuffix(path, "/.env") || path == "/.env":
		markAttack(&info, "env-file")
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprint(w, "APP_ENV=production\nDB_HOST=prod-db.internal\nDB_PASSWORD=Sup3rS3cr3t!\nAWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\nAWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\nSTRIPE_SECRET_KEY=sk_live_examplekey123456\n")
		return
	case strings.HasSuffix(path, "/.htpasswd"):
		markAttack(&info, "htpasswd")
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprint(w, "admindemo:$1$YFru^g}j$iY7qJ0IEAcUGO5wJdUTbO1\n")
		return
	case strings.HasSuffix(path, "/id_rsa") || strings.HasSuffix(path, "/id_ecdsa"):
		markAttack(&info, "ssh-key")
		w.Header().Set("Content-Type", "text/plain")
		serveFile(w, "assets/fake_id_rsa")
		return
	case strings.HasSuffix(pathLower, "swagger.json") || strings.HasSuffix(pathLower, "swagger.yaml") || strings.HasSuffix(pathLower, "openapi.json"):
		markAttack(&info, "swagger")
		w.Header().Set("Content-Type", "application/json")
		serveFile(w, "assets/swagger.json")
		return
	case strings.HasSuffix(path, "/owa/auth/x.js"):
		markAttack(&info, "owa-xjs")
		w.Header().Set("Content-Type", "text/javascript")
		fmt.Fprint(w, `while (true) { alert("The bee makes sum sum!"); }`)
		return
	case strings.HasSuffix(path, "/.git/config"):
		markAttack(&info, "git-config")
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprint(w, "[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n[remote \"origin\"]\n\turl = https://github.com/contoso/internal-api.git\n\tfetch = +refs/heads/*:refs/remotes/origin/*\n")
		return
	case strings.HasSuffix(path, "/.git/HEAD"):
		markAttack(&info, "git-head")
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprint(w, "ref: refs/heads/main\n")
		return
	case strings.HasSuffix(pathLower, ".aws/credentials") || strings.HasSuffix(pathLower, ".aws/config"):
		markAttack(&info, "aws-credentials")
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprint(w, "[default]\naws_access_key_id = AKIAIOSFODNN7EXAMPLE\naws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\nregion = eu-west-1\n")
		return
	case strings.HasSuffix(pathLower, ".sql") || strings.HasSuffix(pathLower, "backup.zip") || strings.HasSuffix(pathLower, "backup.tar.gz"):
		markAttack(&info, "backup-file")
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprint(w, "-- MySQL dump 10.13  Distrib 8.0.32\n-- Host: localhost  Database: proddb\nCREATE TABLE users (id int, email varchar(255), password_hash varchar(255));\n")
		return
	case strings.HasSuffix(pathLower, "phpinfo.php") || strings.HasSuffix(pathLower, "info.php"):
		markAttack(&info, "phpinfo")
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><body><h1>PHP Version 8.2.7</h1><table><tr><td>System</td><td>Linux prod-web 5.15.0</td></tr><tr><td>Document Root</td><td>/var/www/html</td></tr></table></body></html>`)
		return
	case strings.HasSuffix(pathLower, "application.yml") || strings.HasSuffix(pathLower, "application.yaml") || strings.HasSuffix(pathLower, "application.properties"):
		markAttack(&info, "spring-config-leak")
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprint(w, "spring.datasource.url=jdbc:postgresql://prod-db:5432/appdb\nspring.datasource.username=appuser\nspring.datasource.password=ProdPass2024!\n")
		return
	case strings.HasSuffix(pathLower, "docker-compose.yml") || strings.HasSuffix(pathLower, "docker-compose.yaml"):
		markAttack(&info, "docker-compose-leak")
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprint(w, "version: '3.8'\nservices:\n  db:\n    image: postgres:15\n    environment:\n      POSTGRES_PASSWORD: prod_secret_123\n")
		return
	case path == "/server-status" || strings.HasSuffix(path, "/server-status"):
		markAttack(&info, "apache-server-status")
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><body><h1>Apache Server Status</h1><p>Server Version: Apache/2.4.57</p><p>Total accesses: 823519</p></body></html>`)
		return
	case strings.HasSuffix(pathLower, "shell.php") || strings.HasSuffix(pathLower, "cmd.php") ||
		strings.HasSuffix(pathLower, "c99.php") || strings.HasSuffix(pathLower, "r57.php") ||
		strings.HasSuffix(pathLower, "webshell.php"):
		markAttack(&info, "webshell")
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><body><form method="GET"><input name="cmd" placeholder="command"/><input type="submit" value="exec"/></form></body></html>`)
		return
	case strings.Contains(path, "/etc/passwd") || strings.Contains(path, "../etc/passwd"):
		markAttack(&info, "path-traversal-passwd")
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprint(w, "root:x:0:0:root:/root:/bin/bash\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\ndeploy:x:1001:1001::/home/deploy:/bin/bash\n")
		return
	}

	/* ── Prefix-based traps ──────────────────────────────────────────────── */
	switch {
	case strings.HasPrefix(pathLower, "/wp-content") || strings.HasPrefix(pathLower, "/wp-json"):
		markAttack(&info, "wordpress-scan")
		http.Error(w, "Not Found", 404)
		return
	case strings.HasPrefix(path, "/cgi-bin/"):
		markAttack(&info, "cgi-scan")
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprint(w, "CGI script not found")
		return
	}

	/* ── Default 404 ─────────────────────────────────────────────────────── */
	atomic.AddInt64(&counterRequests404, 1)
	http.Error(w, "File not found.", 404)
}

/* ═══════════════════════════════════════════════════════════════════════════
   TRAP FUNCTIONS
═══════════════════════════════════════════════════════════════════════════ */

// restAPITrap catches IDOR-style scanners probing /api/v*/users/{id},
// /api/v*/accounts/{id}, etc. It captures any supplied API key in the headers.
func restAPITrap(w http.ResponseWriter, r *http.Request, info *HoneypotRequest) bool {
	apiRe := regexp.MustCompile(`^/api/v\d+/(users|accounts|admin|customers|employees)/(\d+)`)
	m := apiRe.FindStringSubmatch(r.URL.Path)
	if m == nil {
		return false
	}
	resource := m[1]
	id := m[2]
	markAttack(info, "rest-api-idor-"+resource)
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w,
		`{"id":%s,"email":"user%s@contoso.internal","role":"user",`+
			`"password_hash":"$2b$12$FakeHashForHoneypotXXXXXXXXXXXXXXX",`+
			`"api_key":"sk_live_honeypot%s","created_at":"2024-01-15T10:30:00Z"}`,
		id, id, id)
	return true
}

/* ═══════════════════════════════════════════════════════════════════════════
   HELPERS
═══════════════════════════════════════════════════════════════════════════ */

// markAttack flags the request, increments counters, and fires async side effects.
func markAttack(info *HoneypotRequest, tag string) {
	info.isAttack = true
	if info.attackTag == "" {
		info.attackTag = tag
	}
	atomic.AddInt64(&counterRequestsAttacks, 1)
	go logIPBlacklist(*info)
	go sendWebhook(*info, "attack")
}

// detectLog4Shell scans all request headers and the query string for JNDI injection.
func detectLog4Shell(r *http.Request) bool {
	payload := "${jndi:"
	for _, vals := range r.Header {
		for _, v := range vals {
			if strings.Contains(strings.ToLower(v), payload) {
				return true
			}
		}
	}
	return strings.Contains(r.URL.RawQuery, payload)
}

// captureAPIKey returns any API key or Bearer token present in the request.
func captureAPIKey(r *http.Request) string {
	if key := r.Header.Get("X-Api-Key"); key != "" {
		return key
	}
	if auth := r.Header.Get("Authorization"); strings.HasPrefix(auth, "Bearer ") {
		return strings.TrimPrefix(auth, "Bearer ")
	}
	if auth := r.Header.Get("Authorization"); strings.HasPrefix(auth, "Token ") {
		return strings.TrimPrefix(auth, "Token ")
	}
	return ""
}

// randomDelay returns a cryptographically random duration in [0, TAR_PIT_MAX_SEC].
func randomDelay() time.Duration {
	maxSec := int64(getenvInt("TAR_PIT_MAX_SEC", 20))
	if maxSec <= 0 {
		return 0
	}
	n, err := rand.Int(rand.Reader, big.NewInt(maxSec*1000))
	if err != nil {
		return 5 * time.Second
	}
	return time.Duration(n.Int64()) * time.Millisecond
}

// wpLoginHTML returns a minimal but convincing fake WordPress login page.
func wpLoginHTML() string {
	return `<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><title>Log In &lsaquo; WordPress</title></head><body class="login"><div id="login"><h1><a href="https://wordpress.org/">WordPress</a></h1><form name="loginform" id="loginform" action="/wp-login.php" method="post"><p><label for="user_login">Username or Email Address<br/><input type="text" name="log" id="user_login" class="input" size="20" autocapitalize="none" autocomplete="username"/></label></p><p><label for="user_pass">Password<br/><input type="password" name="pwd" id="user_pass" class="input" size="20" autocomplete="current-password"/></label></p><input type="hidden" name="redirect_to" value="/wp-admin/"/><input type="hidden" name="testcookie" value="1"/><p class="submit"><input type="submit" name="wp-submit" id="wp-submit" class="button button-primary button-large" value="Log In"/></p></form></div></body></html>`
}

/* ═══════════════════════════════════════════════════════════════════════════
   LOGGING
═══════════════════════════════════════════════════════════════════════════ */

// logJSON writes a structured JSON line to /var/log/honeypot.jsonl.
// Skipped entirely when LOG_DISABLED=true.
func logJSON(info HoneypotRequest) {
	if strings.EqualFold(getenv("LOG_DISABLED", "false"), "true") {
		return
	}

	entry := LogEntry{
		Timestamp:  info.timestamp.Format(time.RFC3339),
		IP:         info.ip,
		WaitSec:    float64(info.wait.Milliseconds()) / 1000,
		Method:     info.http.Method,
		Host:       info.http.Host,
		Path:       info.http.URL.Path,
		UserAgent:  info.http.Header.Get("User-Agent"),
		Cookie:     info.cookie,
		IsAttack:   info.isAttack,
		AttackTag:  info.attackTag,
		PostBody:   info.postBody,
		APIKeyUsed: info.apiKeyUsed,
		IPInfo:     info.ipinfo,
	}

	data, err := json.Marshal(entry)
	if err != nil {
		log.Printf("logJSON marshal error: %v", err)
		return
	}
	appendToLogFile("/var/log/honeypot.jsonl", append(data, '\n'))
}

// logIPBlacklist appends the attacker IP to the legacy plaintext blacklist.
func logIPBlacklist(info HoneypotRequest) {
	if strings.EqualFold(getenv("LOG_DISABLED", "false"), "true") {
		return
	}
	appendToLogFile("/var/log/honeypot.ip.blacklist.log", []byte(info.ip+"\n"))
}

// appendToLogFile handles rotation and appends data to a log file.
func appendToLogFile(path string, data []byte) {
	logMu.Lock()
	defer logMu.Unlock()

	maxBytes := int64(getenvInt("LOG_MAX_SIZE_MB", 100)) * 1024 * 1024
	if fi, err := os.Stat(path); err == nil && fi.Size() >= maxBytes {
		rotated := path + "." + time.Now().Format("20060102-150405")
		if err := os.Rename(path, rotated); err != nil {
			log.Printf("log rotate error for %s: %v", path, err)
		}
	}

	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		log.Printf("appendToLogFile open error %s: %v", path, err)
		return
	}
	defer f.Close()
	f.Write(data)
}

/* ═══════════════════════════════════════════════════════════════════════════
   NOTIFICATIONS
═══════════════════════════════════════════════════════════════════════════ */

func sendPushover(info HoneypotRequest) {
	app := getenv("PUSHOVER_APP", "")
	recipient := getenv("PUSHOVER_RECIPIENT", "")
	if app == "" || recipient == "" {
		return
	}
	po := pushover.New(app)
	rec := pushover.NewRecipient(recipient)

	msg := "Honeypot hit from notify country\n"
	msg += "URL: " + info.http.Host + info.http.URL.Path + "\n"
	msg += "Server: " + getenv("NAME", "") + "\n"
	msg += "IP: " + info.ip + "\n"
	if info.ipinfo != nil {
		msg += fmt.Sprintf("Location: %v %v; %v; %v\n",
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

func sendWebhook(info HoneypotRequest, event string) {
	url := getenv("WEBHOOK_URL", "")
	if url == "" {
		return
	}
	payload := map[string]interface{}{
		"event":        event,
		"server":       getenv("NAME", ""),
		"timestamp":    info.timestamp.Format(time.RFC3339),
		"ip":           info.ip,
		"method":       info.http.Method,
		"host":         info.http.Host,
		"path":         info.http.URL.Path,
		"user_agent":   info.http.Header.Get("User-Agent"),
		"is_attack":    info.isAttack,
		"attack_tag":   info.attackTag,
		"api_key_used": info.apiKeyUsed,
		"ipinfo":       info.ipinfo,
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
	log.Printf("webhook fired event=%s attack_tag=%s status=%d", event, info.attackTag, resp.StatusCode)
}

/* ═══════════════════════════════════════════════════════════════════════════
   UTILITY
═══════════════════════════════════════════════════════════════════════════ */

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

func getenvInt(key string, fallback int) int {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return fallback
	}
	return n
}

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
	body, err := io.ReadAll(res.Body)
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

// getIPAddress extracts the real client IP, respecting Cloudflare → HAProxy → Traefik headers.
func getIPAddress(r *http.Request) string {
	if v := r.Header.Get("CF-Connecting-IP"); v != "" {
		return v
	}
	if v := r.Header.Get("X-Forwarded-For"); v != "" {
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
