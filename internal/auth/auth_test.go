package auth

import (
	"testing"
	"time"
	"github.com/google/uuid"
)

func TestMakeJWT(t *testing.T) {
	userID := uuid.New()
	secret := "test-secret"
	expiresIn := time.Hour

	token, err := MakeJWT(userID, secret, expiresIn)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if token == "" {
		t.Fatal("Expected token to be non-empty")
	}
}

func TestValidateJWT(t *testing.T) {
	userID := uuid.New()
	secret := "test-secret"
	expiresIn := time.Hour

	token, err := MakeJWT(userID, secret, expiresIn)
	if err != nil {
		t.Fatalf("Failed to validate token: %v", err)
	}

	validatedUserID, err := ValidateJWT(token, secret)
	if err != nil {
		t.Fatalf("Failed to validate token: %v", err)
	}

	if validatedUserID != userID {
		t.Fatalf("Expected user ID %v, got %v", userID, validatedUserID)
	}
}

func TestValidateJWT_ExpiredToken(t *testing.T) {
	userID := uuid.New()
	secret := "test-secret"
	expiresIn := -time.Hour

	token, err := MakeJWT(userID, secret, expiresIn)
	if err != nil {
		t.Fatalf("Failed to create token: %v", err)
	}

	_, err = ValidateJWT(token, secret)
	if err == nil {
		t.Fatal("Expected error for expired token, got none")
	}
}

func TestValidateJWT_WrongSecret(t *testing.T) {
	userID := uuid.New()
	secret := "test-secret"
	wrongSecret := "wrong-secret"
	expiresIn := time.Hour

	token, err := MakeJWT(userID, secret, expiresIn)
	if err != nil {
		t.Fatalf("Failed to create token: %v", err)
	}

	_, err = ValidateJWT(token, wrongSecret)
	if err == nil {
		t.Fatal("Expected error for wrong secret, got none")
	}
}

func TestHashAndCheckPassword (t *testing.T) {
	password := "04234"

	hash, err := HashPassword(password)
	if err != nil {
		t.Fatalf("error hashing password: %v", err)
	}

	if err := CheckPasswordHash(password, hash); err != nil {
		t.Errorf("passwords don't match: %v", err)
	}
}
