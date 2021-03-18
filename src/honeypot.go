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

func handler(w http.ResponseWriter, r *http.Request) {
	currentTime := time.Now()
	wait_seconds := time.Duration(rand.Int31n(10)) * time.Second

	fmt.Println(currentTime.Format("2006-01-02 15:04:05"), " ", r.RemoteAddr, " ", r.URL.Path)

	log_csv()


	time.Sleep(wait_seconds)

	if (r.URL.Path == "/") {
		serveFile(w, "assets/nginx_default.html")
		return
	}
	if (r.URL.Path == "/favicon.ico") {
		w.Header().Set("Content-Type", "image/ico")
		serveFile(w, "assets/favicon.ico")
		return
	}


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
