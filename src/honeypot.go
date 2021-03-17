package main

import (
    "fmt"
    "log"
    "net/http"
)

func handler(w http.ResponseWriter, r *http.Request) {
	fmt.Println(r.URL.Path)
    fmt.Fprintf(w, "Test")
}

func main() {
	http.HandleFunc("/", handler)
	fmt.Println("Server is listening on port 80")
	log.Fatal(http.ListenAndServe(":80", nil))
}