package main

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/google/uuid"
	"github.com/troclaux/chirpy/internal/auth"
)

func (cfg *apiConfig) handleLogin(w http.ResponseWriter, r *http.Request) {

	// decode request
	decoder := json.NewDecoder(r.Body)

	// declare struct to store data
	type Credential struct {
		Password           string `json:"password"`
		Email              string `json:"email"`
		Expires_in_seconds *int   `json:"expires_in_seconds,omitempty"`
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

	// get servers secret key used in the jwt's signature
	jwtSigningKey := os.Getenv("SIGNING_KEY")

	// Default expiration time is 1 hour
	expirationSeconds := 3600
	if credential.Expires_in_seconds != nil {
		// If specified, use the minimum between requested time and max time
		expirationSeconds = *credential.Expires_in_seconds
	}

	// Convert seconds to Duration (need to multiply by time.Second)
	expirationDuration := time.Duration(expirationSeconds) * time.Second

	tokenString, err := auth.MakeJWT(potentialUser.ID, jwtSigningKey, expirationDuration)
	if err != nil {
		log.Println("couldn't generate jwt")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// response struct
	type UserWithoutPassword struct {
		ID        uuid.UUID `json:"id"`
		CreatedAt time.Time `json:"created_at"`
		UpdatedAt time.Time `json:"updated_at"`
		Email     string    `json:"email"`
		Token     string    `json:"token"`
	}

	// set response values (user fields without password and with the jwt)
	user := UserWithoutPassword{
		ID:        potentialUser.ID,
		CreatedAt: potentialUser.CreatedAt,
		UpdatedAt: potentialUser.UpdatedAt,
		Email:     potentialUser.Email,
		Token:     tokenString,
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
