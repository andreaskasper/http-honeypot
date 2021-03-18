package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"time"
)

func handler(w http.ResponseWriter, r *http.Request) {
	currentTime := time.Now()
	fmt.Println(currentTime.Format("2006-01-02 15:04:05"), " ", r.RemoteAddr, " ", r.URL.Path)
	if (r.URL.Path == "/") {
		Openfile, err := os.Open("assets/nginx_default.html")
		defer Openfile.Close() //Close after function return
		if err != nil {
			//File not found, send 404
			http.Error(writer, "File not found.", 404)
			return
		}
		Openfile.Seek(0, 0)
		io.Copy(writer, Openfile)
		return
	}
	fmt.Fprintf(w, "Test")
}

func main() {
        http.HandleFunc("/", handler)
        fmt.Println("Server is listening on port 80")
        log.Fatal(http.ListenAndServe(":80", nil))
}
