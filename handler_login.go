package main

import (
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/troclaux/chirpy/internal/auth"
)

func (cfg *apiConfig) handleLogin(w http.ResponseWriter, r *http.Request) {

	// decode request
	decoder := json.NewDecoder(r.Body)

	// declare struct to store data
	type Credential struct {
		Password string `json:"password"`
		Email    string `json:"email"`
	}

	credential := Credential{}

	// read decoded data and store it in empty struct
	if err := decoder.Decode(&credential); err != nil {
		log.Printf("error decoding credentials: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// run query
	potentialUser, err := cfg.databaseQueries.AuthenticateUser(r.Context(), credential.Email)
	if err != nil {
		log.Printf("error finding user: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// compare request password with database password
	if err := auth.CheckPasswordHash(credential.Password, potentialUser.HashedPassword); err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		errorResp := errorResponse{
			Error: "Incorrect email or password",
		}
		dat, err := json.Marshal(errorResp)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			log.Printf("Error marshalling JSON: %s", err)
			return
		}
		w.Write(dat)
		return
	}

	type UserWithoutPassword struct {
		ID        uuid.UUID `json:"id"`
		CreatedAt time.Time `json:"created_at"`
		UpdatedAt time.Time `json:"updated_at"`
		Email     string    `json:"email"`
	}

	user := UserWithoutPassword{
		ID:        potentialUser.ID,
		CreatedAt: potentialUser.CreatedAt,
		UpdatedAt: potentialUser.UpdatedAt,
		Email:     potentialUser.Email,
	}

	// Set headers before writing response
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	// Check for encoding errors
	if err := json.NewEncoder(w).Encode(user); err != nil {
		log.Printf("error encoding response: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	return
}
