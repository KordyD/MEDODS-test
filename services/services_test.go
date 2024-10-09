package services

import (
	"os"
	"testing"
)

// Устанавливаем переменные окружения в тесте
func init() {
	os.Setenv("JWT_SECRET", "test_secret_key")
}

func TestGenerateJWT(t *testing.T) {
	userId := "123e4567-e89b-12d3-a456-426614174000"
	ip := "192.168.0.1"
	token, err := GenerateJWT(userId, ip)
	if err != nil {
		t.Fatalf("Expected no error while generating JWT, got %v", err)
	}
	if token == "" {
		t.Fatal("Generated JWT token should not be empty")
	}
	claims, err := ValidateJWT(token)
	if err != nil {
		t.Fatalf("Expected no error while validating JWT, got %v", err)
	}
	if claims.UserId != userId {
		t.Errorf("Expected UserId to be %s, got %s", userId, claims.UserId)
	}
	if claims.Ip != ip {
		t.Errorf("Expected IP address to be %s, got %s", ip, claims.Ip)
	}
}

func TestGenerateRandomToken(t *testing.T) {
	token, err := GenerateRandomToken()
	if err != nil {
		t.Fatalf("Expected no error while generating random token, got %v", err)
	}
	if token == "" {
		t.Fatal("Generated random token should not be empty")
	}
}

func TestValidateJWT(t *testing.T) {
	userId := "123e4567-e89b-12d3-a456-426614174000"
	ip := "192.168.0.1"
	token, _ := GenerateJWT(userId, ip)
	claims, err := ValidateJWT(token)
	if err != nil {
		t.Fatalf("Expected no error while validating JWT, got %v", err)
	}
	if claims.UserId != userId {
		t.Errorf("Expected UserId to be %s, got %s", userId, claims.UserId)
	}
	if claims.Ip != ip {
		t.Errorf("Expected IP address to be %s, got %s", ip, claims.Ip)
	}
	invalidToken := "invalid.token.string"
	_, err = ValidateJWT(invalidToken)
	if err == nil {
		t.Fatal("Expected an error while validating invalid token, but got none")
	}
}

func TestSendEmailWarning(t *testing.T) {
	userId := "123e4567-e89b-12d3-a456-426614174000"
	err := SendEmailWarning(userId)
	if err != nil {
		t.Fatalf("Expected no error while sending email warning, got %v", err)
	}
}
