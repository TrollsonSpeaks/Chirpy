package main

import (
	"net/http"
)

func main() {
	// Step 1: Create a new ServeMux
	mux := http.NewServeMux()

	// Step 2: Create the server and attach the mux
	server := &http.Server{
		Addr:    ":8080", // Listen on port 8080
		Handler: mux,     // Use the ServeMux as the handler
	}

	// Step 3: Start the server
	server.ListenAndServe()
}
