package main

import (
	"database/sql"
	"log"
	"net/http"

	"github.com/troclaux/chirpy/internal/auth"
)

func (cfg *apiConfig) handleTokenRevocation(w http.ResponseWriter, r *http.Request) {

	// check if request has authorization headers
	jwtString, err := auth.GetBearerToken(r.Header)
	if err != nil {
		log.Printf("error getting bearer token: %v", err)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	err = cfg.databaseQueries.RevokeRefreshToken(r.Context(), jwtString)
	if err != nil {
		log.Printf("error revoking refresh token: %v", err)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	// if refresh token is not found in database
	if err == sql.ErrNoRows {
		log.Println("refresh token not found in database")
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
