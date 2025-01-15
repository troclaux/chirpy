package main

import (
	"database/sql"
	"encoding/json"
	"log"
	"net/http"
	"os"

	"github.com/troclaux/chirpy/internal/auth"
	"github.com/troclaux/chirpy/internal/database"
)

type Credentials struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

func (cfg *apiConfig) handleUsersUpdate(w http.ResponseWriter, r *http.Request) {

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

	decoder := json.NewDecoder(r.Body)
	// create empty User struct to store the decoded JSON
	credentials := Credentials{}
	// attempts to decode the JSON from the request body and store it in the reqUser struct
	if err := decoder.Decode(&credentials); err != nil {
		log.Printf("error decoding credentials: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	hashedPassword, err := auth.HashPassword(credentials.Password)
	if err != nil {
		log.Printf("error hashing new password: %v", err)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	updateUserParams := database.UpdateUserParams{
		Email:          credentials.Email,
		HashedPassword: hashedPassword,
		ID:             userID,
	}

	updatedUser, err := cfg.databaseQueries.UpdateUser(r.Context(), updateUserParams)

	// if user is not found on database by id
	if err == sql.ErrNoRows {
		log.Printf("couldn't find user by id: %v", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	userResponse := User{
		ID:        updatedUser.ID,
		CreatedAt: updatedUser.CreatedAt,
		UpdatedAt: updatedUser.UpdatedAt,
		Email:     updatedUser.Email,
		Password:  updatedUser.HashedPassword,
	}

	// Set headers before writing response
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	// Check for encoding errors
	if err := json.NewEncoder(w).Encode(userResponse); err != nil {
		log.Printf("error encoding response: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	return
}
