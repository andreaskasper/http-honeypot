package main

import (
	"sync"
	"time"
)

// Global state - all accesses are thread-safe
var (
	counterRequests        int64 // atomic
	counterRequests404     int64 // atomic
	counterRequestsAttacks int64 // atomic
	counterHoneytokensUsed int64 // atomic
	statsDurationWaitMS    int64 // atomic, milliseconds

	notifyMu                    sync.Mutex
	dtLastPushoverNotifyCountry = time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)

	// logMu serialises writes + rotations so two goroutines don't race on Rename
	logMu sync.Mutex
)
