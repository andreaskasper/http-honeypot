package main

import (
	"fmt"
	"io"
	"log"
	"math/rand"
	"net/http"
	"os"
	"time"
)

var counter_requests int = 0
var counter_requests_404 int = 0
var counter_requests_attacks int = 0
var stats_duration_wait float64 = 0

func handler(w http.ResponseWriter, r *http.Request) {

	/* Prometheus Metrics */
	if (r.URL.Path == "/metrics") {
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

	currentTime := time.Now()
	wait_seconds := time.Duration(rand.Float64()*20) * time.Second

	fmt.Println(currentTime.Format("2006-01-02 15:04:05"), " ", r.RemoteAddr, " ", r.URL.Path)
	counter_requests++;
	stats_duration_wait += float64(wait_seconds.Milliseconds())/1000

	log_csv(r, wait_seconds)


	time.Sleep(wait_seconds)

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
			log_ip_blacklist(r)
			fmt.Fprintf(w, "a")
			return
	}

	log_404(r)
	counter_requests_404++

	http.Error(w, "File not found.", 404)
}

func main() {
        http.HandleFunc("/", handler)
        fmt.Println("Server is listening on port 80")
        log.Fatal(http.ListenAndServe(":80", nil))
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

func log_csv(r *http.Request, wait_sec time.Duration) {
	f, err := os.OpenFile("/var/log/honeypot.log1.csv", os.O_RDWR | os.O_CREATE | os.O_APPEND, 0666)
	if err != nil {
		log.Fatalf("error opening file: %v", err)
	}
	defer f.Close()

	f.Write([]byte(fmt.Sprintf("%s;", time.Now().Format("2006-01-02 15:04:05") )))
	f.Write([]byte(fmt.Sprintf("%s;", r.RemoteAddr )))
	f.Write([]byte(fmt.Sprintf("%f;", float64(wait_sec.Milliseconds())/1000 )))
	f.Write([]byte(fmt.Sprintf("%s;", r.Method )))
	f.Write([]byte(fmt.Sprintf("%s;", r.Host )))
	f.Write([]byte(fmt.Sprintf("%s;", r.URL.Path )))
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

func log_ip_blacklist(r *http.Request) {
	f, err := os.OpenFile("/var/log/honeypot.ip.blacklist.log", os.O_RDWR | os.O_CREATE | os.O_APPEND, 0666)
	if err != nil {
		log.Fatalf("error opening file: %v", err)
	}
	defer f.Close()

	f.Write([]byte(r.RemoteAddr+"\n"))
	f.Close();
}

//Example: http://87.238.197.130/portal/redlion
func log_404(r *http.Request) {
	f, err := os.OpenFile("/var/log/honeypot.urls.404.log", os.O_RDWR | os.O_CREATE | os.O_APPEND, 0666)
	if err != nil {
		log.Fatalf("error opening file: %v", err)
	}
	defer f.Close()

	f.Write([]byte(r.URL.Scheme+"://"+r.URL.Host+r.URL.Path+"\n"))
	f.Close();
}
