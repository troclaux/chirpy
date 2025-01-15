package main

import (
	"database/sql"
	"log"
	"net/http"
	"os"

	"github.com/google/uuid"
	"github.com/troclaux/chirpy/internal/auth"
)

func (cfg *apiConfig) handleChirpDelete(w http.ResponseWriter, r *http.Request) {

	// get chirp id from the URL path
	strID := r.PathValue("chirpID")
	chirpID, err := uuid.Parse(strID)
	if err != nil {
		log.Println("Error parsing UUID string from URL:", err)
		return
	}

	// check if request has authorization headers
	jwtString, err := auth.GetBearerToken(r.Header)
	if err != nil {
		log.Printf("error getting bearer token: %v", err)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	// get the server's signing key from .env
	jwtSigningKey := os.Getenv("SIGNING_KEY")

	// validate jwt string
	userID, err := auth.ValidateJWT(jwtString, jwtSigningKey)
	if err != nil {
		log.Printf("error validating jwt: %v", err)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	chirp, err := cfg.databaseQueries.GetChirp(r.Context(), chirpID)
	if err == sql.ErrNoRows {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	if err != nil {
		log.Printf("error getting chirp: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if chirp.UserID != userID {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	deletedChirp, err := cfg.databaseQueries.DeleteChirp(r.Context(), chirpID)
	// if chirp's not found in database
	if err == sql.ErrNoRows {
		log.Printf("couldn't delete chirp that matches both id and userID: %v", err)
		w.WriteHeader(http.StatusNotFound)
		return
	}
	if deletedChirp.UserID != userID {
		log.Printf("chirp's userID is not jwt's userID: %v", err)
		w.WriteHeader(http.StatusForbidden)
		return
	}
	if err != nil {
		log.Printf("error deleting chirp: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusNoContent)

	return
}
