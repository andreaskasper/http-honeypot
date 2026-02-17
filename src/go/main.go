package main

import (
	"log"
	"net/http"
)

func main() {
	rl.limit = getenvInt("RATE_LIMIT_PER_MIN", 1000)
	log.Printf(
		"honeypot starting | rate_limit=%d/min | log_disabled=%s | tar_pit_max=%ds | "+
			"metrics_disabled=%s | abuseipdb=%s",
		rl.limit,
		getenv("LOG_DISABLED", "false"),
		getenvInt("TAR_PIT_MAX_SEC", 20),
		getenv("METRICS_DISABLED", "false"),
		func() string {
			if getenv("ABUSEIPDB_KEY", "") != "" {
				return "enabled (sleep=" + getenv("ABUSEIPDB_SLEEP", "86400") + "s)"
			}
			return "disabled"
		}(),
	)

	http.HandleFunc("/", handler)
	log.Fatal(http.ListenAndServe(":80", nil))
}
