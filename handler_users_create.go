package main

import (
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/troclaux/chirpy/internal/auth"
	"github.com/troclaux/chirpy/internal/database"
)

type User struct {
	ID        uuid.UUID `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Email     string    `json:"email"`
	Password  string    `json:"password"`
}

func (cfg *apiConfig) handleUsersCreate(w http.ResponseWriter, r *http.Request) {
	// creates new JSON decoder to read the request body
	decoder := json.NewDecoder(r.Body)
	// create empty User struct to store the decoded JSON
	reqUser := User{}
	// attempts to decode the JSON from the request body and store it in the reqUser struct
	if err := decoder.Decode(&reqUser); err != nil {
		log.Printf("error decoding user: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	hash, err := auth.HashPassword(reqUser.Password)
	if err != nil {
		log.Printf("error hashing password: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// create parameters for query created by sqlc in database package
	parameters := database.CreateUserParams{
		Email:          reqUser.Email,
		HashedPassword: hash,
	}

	// http.Request.Context() cancels the database query if the http request is cancelled or times out
	// use sqlc generated code to create a new user in the database and store it in newUser variable
	newUser, err := cfg.databaseQueries.CreateUser(r.Context(), parameters)
	if err != nil {
		log.Printf("error creating user: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	user := User{
		ID:        newUser.ID,
		CreatedAt: newUser.CreatedAt,
		UpdatedAt: newUser.UpdatedAt,
		Email:     newUser.Email,
		Password:  newUser.HashedPassword,
	}

	// Set headers before writing response
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)

	// Check for encoding errors
	if err := json.NewEncoder(w).Encode(user); err != nil {
		log.Printf("error encoding response: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	return
}
