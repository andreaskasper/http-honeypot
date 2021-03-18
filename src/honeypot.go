package main

import (
    "fmt"
    "log"
    "net/http"
    "time"
)

func handler(w http.ResponseWriter, r *http.Request) {
	currentTime := time.Now()
	fmt.Println(currentTime.Format("2006-01-02 15:04:05")+" "+r.RemoteAddr+" "+r.URL.Path)
	fmt.Fprintf(w, "Test")
}

func main() {
        http.HandleFunc("/", handler)
        fmt.Println("Server is listening on port 80")
        log.Fatal(http.ListenAndServe(":80", nil))
}
