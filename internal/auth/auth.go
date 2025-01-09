package auth

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

const (
	TokenIssuer string = "issuer_is_chirpy"
)

func HashPassword(password string) (string, error) {

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}

	return string(hashedPassword), nil
}

func CheckPasswordHash(password string, hash string) error {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
}

func MakeJWT(userID uuid.UUID, tokenSecret string, expiresIn time.Duration) (string, error) {
	// convert the secret to byte slice because cryptographic operations fundamentally work with bytes
	// converting the string to bytes ensures consistent handling across different character encondings and platforms
	signingKey := []byte(tokenSecret)
	claims := jwt.RegisteredClaims{
		Issuer:    TokenIssuer,
		IssuedAt:  jwt.NewNumericDate(time.Now()),
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(expiresIn)),
		Subject:   userID.String(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(signingKey)
}

// Takes an encoded JWT token string and its secret key, returns the user's ID if valid
func ValidateJWT(tokenString string, tokenSecret string) (uuid.UUID, error) {
	// ParseWithClaims validates the token and extracts the claims
	// what does it mean to validate the token and extract the claims?
	// compare the calculated signature with the signature provided in the jwt
	// check if the token is expired with the registered claim "expiration time"

	// jwt.RegisteredClaims is a type (a struct).
	// jwt.RegisteredClaims{} is a composite literal, which creates a new instance of the jwt.RegisteredClaims struct with default values.
	// &jwt.RegisteredClaims{} is taking the address of the new instance created by the composite literal.
	// input: encoded string, default claims and a key function that tells the parser how to validade the token's signature
	// encoded string is header.payload.signature
	// &jwt.RegisteredClaims{} is the struct that will store the decoded jwt
	// output is the decoded validated token with claims, if there's any problems, return error
	parsedToken, err := jwt.ParseWithClaims(tokenString, &jwt.RegisteredClaims{}, func(token *jwt.Token) (interface{}, error) {
		// this anonymous function provides the secret key for signature validation
		// convert string into a byte slice (because the jwt.ParseWithClaims requires a slice of bytes)
		return []byte(tokenSecret), nil
	})
	if err != nil {
		// Return an error if the token is invalid
		return uuid.Nil, err
	}

	userIDString, err := parsedToken.Claims.GetSubject()
	if err != nil {
		return uuid.Nil, err
	}

	issuer, err := parsedToken.Claims.GetIssuer()
	if err != nil {
		return uuid.Nil, err
	}
	if issuer != TokenIssuer {
		return uuid.Nil, errors.New("invalid issuer")
	}

	id, err := uuid.Parse(userIDString)
	if err != nil {
		return uuid.Nil, fmt.Errorf("invalid user ID: %w", err)
	}
	return id, nil
}
