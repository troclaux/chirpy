package main

import (
	"database/sql"
	"encoding/json"
	"log"
	"net/http"

	"github.com/google/uuid"
	"github.com/troclaux/chirpy/internal/auth"
)

func (cfg *apiConfig) handleEventWebhook(w http.ResponseWriter, r *http.Request) {

	// check if request has correct api key
	requestApiKey, err := auth.GetAPIKey(r.Header)
	if err != nil {
		log.Printf("error getting authorization header: %v", err)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	if requestApiKey != cfg.polkaKey {
		log.Printf("invalid polka key: %v", err)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	// decode request
	decoder := json.NewDecoder(r.Body)

	type Webhook struct {
		Event string `json:"event"`
		Data  struct {
			UserID uuid.UUID `json:"user_id"`
		} `json:"data"`
	}

	webhook := Webhook{}

	// read decoded data and store it in empty struct
	if err := decoder.Decode(&webhook); err != nil {
		log.Printf("error decoding credentials: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	if webhook.Event != "user.upgraded" {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	if webhook.Event == "user.upgraded" {
		_, err := cfg.databaseQueries.UpgradeUser(r.Context(), webhook.Data.UserID)
		if err == sql.ErrNoRows {
			log.Printf("couldn't find user: %v", err)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if err != nil {
			log.Printf("error upgrading user to chirpy red: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNoContent)
		return
	}

}
