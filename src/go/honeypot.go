package main

import (
	"crypto/md5"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math/rand"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gregdel/pushover"
)

var counter_requests int = 0
var counter_requests_404 int = 0
var counter_requests_attacks int = 0
var stats_duration_wait float64 = 0
var dt_last_pushover_notify_country time.Time = time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)



/*  ====== TYPES  ======= */

type HoneypotRequest struct {
	http *http.Request
	timestamp time.Time
	wait time.Duration
	ip string
	ipinfo map[string]interface{}
	cookie string
}

type ipinfojson struct {
	ip string `json:"ip"`
	hostname string `json:"hostname"`
	city string `json:"city"`
	region string `json:"region"`
	county string `json:"country"`
	loc string  `json:"loc"`
	geo struct {
		lat float64 `json:"lat"`
		lon float64 `json:"lon"`
	}
	org string  `json:"org"`
	postal string  `json:"postal"`
	timezone string  `json:"timezone"`
	lastscan string  `json:"last_scan"`
}



/* ====== MAIN ======*/

func main() {
	http.HandleFunc("/", handler)
	fmt.Println("Server is listening on port 80")
	log.Fatal(http.ListenAndServe(":80", nil))
}

func handler(w http.ResponseWriter, r *http.Request) {

	/* Prometheus Metrics */
	if (r.URL.Path == "/metrics") {
		if (!BasicAuth(w,r)) { 
			return
		}
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")

		fmt.Fprintf(w, "# HELP http_requests_all Number of webrequests\n")
		fmt.Fprintf(w, "# TYPE http_requests_all counter\n")

		fmt.Fprintf(w, "http_requests_all{} %d\n", counter_requests)

		fmt.Fprintf(w, "# HELP http_requests Number of webrequests\n")
		fmt.Fprintf(w, "# TYPE http_requests counter\n")

		fmt.Fprintf(w, "http_requests{code=\"404\"} %d\n", counter_requests_404)
		fmt.Fprintf(w, "http_requests{code=\"attack\"} %d\n", counter_requests_attacks)

		fmt.Fprintf(w, "# HELP http_duration Duration of web requests\n")
		fmt.Fprintf(w, "# TYPE http_duration summary\n")

		fmt.Fprintf(w, "http_duration{} %f\n", stats_duration_wait)
		return
	}

	info := HoneypotRequest{
		http: r,
		timestamp: time.Now(),
		wait: time.Duration(rand.Float64()*20) * time.Second,
		ip: get_ip_address(r),

	}

	fmt.Println(info.timestamp.Format("2006-01-02 15:04:05"), " ", info.ip, " ", info.http.URL.Path)
	counter_requests++;
	stats_duration_wait += float64(info.wait.Milliseconds())/1000

	info.ipinfo = ipinfo(info.ip)


	if ((getenv("PUSHOVER_NOTIFY_COUNTRY", "") != "") && (info.timestamp.Sub(dt_last_pushover_notify_country).Hours() >= 1)) {
		if (info.ipinfo["country"] == getenv("PUSHOVER_NOTIFY_COUNTRY","")) {
			pushover_app := getenv("PUSHOVER_APP", "")
			pushover_recipient := getenv("PUSHOVER_RECIPIENT", "")
			if (pushover_app != "" && pushover_recipient != "") {
				po := pushover.New(pushover_app)
				recipient := pushover.NewRecipient(pushover_recipient)
				message := &pushover.Message{
					Title:       "Honeypot Attack for country "+getenv("PUSHOVER_NOTIFY_COUNTRY", ""),
					Message:     "Check the honeypot, it seems you got a request the notify country\nURL: "+info.http.URL.Scheme+"://"+info.http.Host+info.http.URL.Path+"\nCountry: "+getenv("PUSHOVER_NOTIFY_COUNTRY", ""),
					Priority:    pushover.PriorityNormal,
					/*URL:         "http://google.com",
					URLTitle:    "Google",*/
					Timestamp:   time.Now().Unix(),
					Retry:       60 * time.Second,
					Expire:      time.Hour,
					DeviceName:  "Honeypot",
					/*CallbackURL: "http://yourapp.com/callback",*/
					Sound:       pushover.SoundGamelan,
				}
				// Send the message to the recipient
				_, err := po.SendMessage(message, recipient)
				if err != nil {
					log.Panic(err)
				}
				dt_last_pushover_notify_country = time.Now()
			}
		}
	}

	/* Check Cookie set or renew */

	info.cookie = getHoneypotCookie(info.http)
	if (info.cookie == "") { 
		a := info.timestamp.String()
		info.cookie = GetMD5Hash(a)
	}

	expire := time.Now().AddDate(24*365, 0, 0)
    cookie := http.Cookie{"akhp", info.cookie, "/", strings.Split(r.Host,":")[0], expire, expire.Format(time.UnixDate), 86400*365, false, true, http.SameSiteDefaultMode, "akhp="+info.cookie, []string{"akhp="+info.cookie}}
    http.SetCookie(w, &cookie)

	//fmt.Println("Cookie: "+hp_cookie)

	log_csv(info)

	time.Sleep(info.wait)

	switch r.URL.Path {
		case "/":
			serveFile(w, "assets/nginx_default.html")
			return
		case "/favicon.ico":
			w.Header().Set("Content-Type", "image/ico")
			serveFile(w, "assets/favicon.ico")
			return
		case "/admin/config.php", "/admin//config.php":
			counter_requests_attacks++
			go log_ip_blacklist(info)
			fmt.Fprintf(w, "No valid entrypoint")
			return
		case "/owa/":
			http.Error(w, "go to login", 301)
			w.Header().Set("Location", "/owa/auth/logon.aspx")
			return
		case "/owa/auth/logon.aspx":
			counter_requests_attacks++
			go log_ip_blacklist(info)
			serveFile(w, "assets/owa_logon_aspx.html")
			return
	}

	if (strings.HasSuffix(r.URL.Path, "/.env")) {
		counter_requests_attacks++
		go log_ip_blacklist(info)
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprintf(w, "S3_BUCKET=\"superbucket\"\nSECRET_KEY=\"password123456abc\"\n")
		return
	}

	if (strings.HasSuffix(r.URL.Path, "swagger.json")) {
		counter_requests_attacks++
		go log_ip_blacklist(info)
		w.Header().Set("Content-Type", "application/json")
		serveFile(w, "assets/swagger.json")
		return
	}

	if (strings.HasSuffix(r.URL.Path, "/owa/auth/x.js")) {
		counter_requests_attacks++
		go log_ip_blacklist(info)
		w.Header().Set("Content-Type", "text/javascript")
		fmt.Fprintf(w, "while (true) { alert(\"The bee makes sum sum!\"); }")
		return
	}

	go log_404(info)
	counter_requests_404++

	http.Error(w, "File not found.", 404)
}

func serveFile(w http.ResponseWriter, Filename string) {
	Openfile, err := os.Open(Filename)
	defer Openfile.Close() //Close after function return
	if err != nil {
		//File not found, send 404
		http.Error(w, "File not found.", 404)
		return
	}
	Openfile.Seek(0, 0)
	io.Copy(w, Openfile)
}



/* ====== LOG FUNCTIONS ====== */

//Example: http://87.238.197.130/portal/redlion
func log_404(info HoneypotRequest) {
	f, err := os.OpenFile("/var/log/honeypot.urls.404.log", os.O_RDWR | os.O_CREATE | os.O_APPEND, 0666)
	if err != nil {
		log.Fatalf("error opening file: %v", err)
	}
	defer f.Close()

	f.Write([]byte(info.http.URL.Scheme+"://"+info.http.Host+info.http.URL.Path+"\n"))
	f.Close();
}

func log_csv(info HoneypotRequest) {
	f, err := os.OpenFile("/var/log/honeypot.log1.csv", os.O_RDWR | os.O_CREATE | os.O_APPEND, 0666)
	if err != nil {
		log.Fatalf("error opening file: %v", err)
	}
	defer f.Close()

	f.Write([]byte(fmt.Sprintf("%s;", info.timestamp.Format("2006-01-02 15:04:05") )))
	f.Write([]byte(fmt.Sprintf("%s;", info.ip )))
	f.Write([]byte(fmt.Sprintf("%f;", float64(info.wait.Milliseconds())/1000 )))
	f.Write([]byte(fmt.Sprintf("%s;", info.http.Method )))
	f.Write([]byte(fmt.Sprintf("%s;", info.http.Host )))
	f.Write([]byte(fmt.Sprintf("%s;", info.http.URL.Path )))

	f.Write([]byte(fmt.Sprintf("%s;", info.ipinfo["hostname"] )))
	f.Write([]byte(fmt.Sprintf("%s;", info.ipinfo["country"] )))
	f.Write([]byte(fmt.Sprintf("%s;", info.ipinfo["region"] )))
	f.Write([]byte(fmt.Sprintf("%s;", info.ipinfo["postal"] )))
	f.Write([]byte(fmt.Sprintf("%s;", info.ipinfo["city"] )))

	f.Write([]byte(fmt.Sprintf("\"%s\";", info.http.Header.Get("User-Agent") )))
	f.Write([]byte(fmt.Sprintf("%s;", info.cookie )))

	f.Write([]byte("\n"))

/*

    $row  = date("Y-m-d H:i:s").';';
    $row .= $remote_ip.';';
    $row .= $wait_sec.';';
    
    $row .= '"'.($_SERVER["REQUEST_METHOD"] ?? null).'";';
    $row .= '"'.($_SERVER["HTTP_HOST"] ?? null).'";';
    $row .= '"'.($_SERVER["REQUEST_URI"] ?? null).'";';
    $row .= '"'.($ipinfo["result"]["hostname"] ?? null).'";';
    $row .= '"'.($ipinfo["result"]["country"] ?? null).'";';
    $row .= '"'.($ipinfo["result"]["region"] ?? null).'";';
    $row .= '"'.($ipinfo["result"]["postal"] ?? null).'";';
    $row .= '"'.($ipinfo["result"]["city"] ?? null).'";';
    $row .= '"'.($_SERVER["HTTP_USER_AGENT"] ?? null).'";';

    $row .= '"'.json_encode($_SERVER ?? null).'";';
    $row .= '"'.json_encode($_ENV ?? null).'";';
    $row .= '"'.json_encode($_GET ?? null).'";';
    $row .= '"'.json_encode($_POST ?? null).'";';
    $row .= '"'.json_encode($_COOKIE ?? null).'";';

 */

	f.Close();
}

func log_ip_blacklist(info HoneypotRequest) {
	f, err := os.OpenFile("/var/log/honeypot.ip.blacklist.log", os.O_RDWR | os.O_CREATE | os.O_APPEND, 0666)
	if err != nil {
		log.Fatalf("error opening file: %v", err)
	}
	defer f.Close()

	f.Write([]byte(info.ip+"\n"))
	f.Close();
}



/* ======= HELPER FUNCS ======== */

func BasicAuth(w http.ResponseWriter, r *http.Request) bool {
	admin := getenv("METRICS_USER", "admin")
	password := getenv("METRICS_PASSWORD", "password")
	realm := getenv("METRICS_REALM", "Prometheus Server")

    user, pass, ok := r.BasicAuth()
    if (!ok || subtle.ConstantTimeCompare([]byte(user), []byte(admin)) != 1 || subtle.ConstantTimeCompare ([]byte(pass), []byte(password)) != 1) {
      w.Header().Set("WWW-Authenticate", `Basic realm="`+realm+`"`)
      w.WriteHeader(401)
      w.Write([]byte("Unauthorized.\n"))
      return false
    }
    return true
  }

func getenv(key, fallback string) string {
	value := os.Getenv(key)
    if len(value) == 0 {
    	return fallback
    }
    return value
}

func ipinfo(ip string) map[string]interface{} {
	goo1APIClient := http.Client{
		Timeout: time.Second * 2, // Timeout after 2 seconds
	}

	req, err := http.NewRequest(http.MethodGet, "https://api.goo1.de/ipinfo.scan.json?ip="+ip, nil)
	if err != nil {
		log.Fatal(err)
	}

	res, getErr := goo1APIClient.Do(req)
	if getErr != nil {
		log.Fatal(getErr)
	}

	if res.Body != nil {
		defer res.Body.Close()
	}

	body, readErr := ioutil.ReadAll(res.Body)
	if readErr != nil {
		log.Fatal(readErr)
	}

	//fmt.Println(string(body))

	var results  map[string]map[string]interface{}
	err2 := json.Unmarshal(body, &results)
	if err2 != nil {
		log.Fatal(err2)
		fmt.Println(err2)
	}

	return results["result"]
}

func getHoneypotCookie(r *http.Request) string {
	for _, cookie := range r.Cookies() {
        if cookie.Name == "akhp" {
			return cookie.Value
        }
	}
	return ""
}

func GetMD5Hash(text string) string {
    hasher := md5.New()
    hasher.Write([]byte(text))
    return hex.EncodeToString(hasher.Sum(nil))
}

func get_ip_address(r *http.Request) string {
	/*Check for Cloudflare*/
	val, ok := r.Header["CF-Connecting-IP"]
	if ok {
		return val[0];
	}
	/*Default Remote Addr*/
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		fmt.Println("userip: %q is not IP:port", r.RemoteAddr)
	}
	return ip
}
