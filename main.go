package main

import (
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
	"log"
	"net/http"
	"test_medods/handlers"
	"test_medods/storage"
)

func main() {
	err := godotenv.Load()
	if err != nil {
		log.Fatalln("Error loading .env file")
	}
	db := storage.NewPostgres()
	http.HandleFunc("POST /token", handlers.ReturnTokens(db))
	http.HandleFunc("POST /refresh", handlers.RefreshToken(db))
	err = http.ListenAndServe(":8080", nil)
	if err != nil {
		log.Fatalf("Error starting server: %s", err)
	}
}
