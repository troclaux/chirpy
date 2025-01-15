package main

import (
	"database/sql"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/troclaux/chirpy/internal/auth"
)

func (cfg *apiConfig) handleRefreshToken(w http.ResponseWriter, r *http.Request) {

	// check if request has authorization headers
	jwtString, err := auth.GetBearerToken(r.Header)
	if err != nil {
		log.Printf("error getting bearer token: %v", err)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	// run sql query that searches the refresh token in the database
	refreshToken, err := cfg.databaseQueries.GetUserFromRefreshToken(r.Context(), jwtString)
	if err != nil {
		log.Printf("error getting user with refresh token: %v", err)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	// if refresh token is expired
	if refreshToken.ExpiresAt.Before(time.Now()) {
		log.Printf("refresh token expired: %v", refreshToken.ExpiresAt)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	// if refresh token is revoked
	if refreshToken.RevokedAt.Valid {
		log.Printf("refresh token has been revoked at: %v", refreshToken.RevokedAt)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	// if refresh token is not found in database
	if err == sql.ErrNoRows {
		log.Printf("refresh token not found in database: %v", refreshToken.ExpiresAt)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	// create access token string
	jwtSigningKey := os.Getenv("SIGNING_KEY")
	timeToExpire := time.Hour
	accessTokenString, err := auth.MakeJWT(refreshToken.UserID, jwtSigningKey, timeToExpire)
	if err != nil {
		log.Println("couldn't generate jwt")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	type jwtResponse struct {
		Token string `json:"token"`
	}

	response := jwtResponse{
		Token: accessTokenString,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	// Check for encoding errors
	if err := json.NewEncoder(w).Encode(response); err != nil {
		log.Printf("error encoding response: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

}
