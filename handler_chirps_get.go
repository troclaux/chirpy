package main

import (
	"database/sql"
	"encoding/json"
	"log"
	"net/http"

	"github.com/google/uuid"
)

func (cfg *apiConfig) handleChirpsGet(w http.ResponseWriter, r *http.Request) {

	dbChirps, err := cfg.databaseQueries.GetChirps(r.Context())
	if err == sql.ErrNoRows {
		log.Printf("couldn't get chirps: %v", err)
		w.WriteHeader(http.StatusNotFound)
		return
	}
	if err != nil {
		log.Printf("error getting chirps: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	authorID := uuid.Nil
	authorIDString := r.URL.Query().Get("author_id")

	if authorIDString != "" {
		authorID, err = uuid.Parse(authorIDString)
		if err != nil {
			log.Println("Error parsing UUID string from URL:", err)
			return
		}
	}

	// IMPORTANT: convert the dbChirps to a map of Chirps{}
	chirps := []Chirp{}
	for _, dbChirp := range dbChirps {
		if authorID != dbChirp.UserID && authorID != uuid.Nil {
			continue
		}
		chirps = append(chirps, Chirp{
			ID:        dbChirp.ID,
			CreatedAt: dbChirp.CreatedAt,
			UpdatedAt: dbChirp.UpdatedAt,
			UserID:    dbChirp.UserID,
			Body:      dbChirp.Body,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	if err := json.NewEncoder(w).Encode(chirps); err != nil {
		log.Printf("error encoding response: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	return
}
