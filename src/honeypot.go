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
		return
	}

	currentTime := time.Now()
	wait_seconds := time.Duration(rand.Int31n(10)) * time.Second

	fmt.Println(currentTime.Format("2006-01-02 15:04:05"), " ", r.RemoteAddr, " ", r.URL.Path)
	counter_requests++;

	log_csv()


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

func log_csv() {
	f, err := os.OpenFile("/var/log/honeypot.log1.csv", os.O_RDWR | os.O_CREATE | os.O_APPEND, 0666)
	if err != nil {
		log.Fatalf("error opening file: %v", err)
	}
	defer f.Close()

	f.Write([]byte("Dies ist ein Test\n"))
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
