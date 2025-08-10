package auth

import (
	"testing"
)

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
