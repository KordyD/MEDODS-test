package main

import (
	"encoding/json"
	"golang.org/x/crypto/bcrypt"
	"log"
	"net/http"
)

type TokenRequest struct {
	UserId string `json:"user_id"`
}

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

type RefreshRequest struct {
	TokenResponse
}

type RefreshResponse struct {
	TokenResponse
}

type TokenSaver interface {
	SaveRefreshToken(userId string, tokenHash string, ip string) (int64, error)
}

type TokenValidator interface {
	TokenSaver
	ValidateRefreshToken(userId string, providedToken string, ipAddress string) error
}

func ReturnTokens(provider TokenSaver) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		var req TokenRequest
		err := json.NewDecoder(r.Body).Decode(&req)
		if err != nil {
			log.Printf("Error decoding body: %s", err)
			http.Error(w, "Invalid request", http.StatusBadRequest)
			return
		}
		accessToken, err := GenerateJWT(req.UserId, r.RemoteAddr)
		if err != nil {
			log.Printf("Error generating access token: %s", err)
			http.Error(w, "Something went wrong", http.StatusInternalServerError)
			return
		}
		refreshToken, err := GenerateRandomToken()
		if err != nil {
			log.Printf("Error generating refresh token: %s", err)
			http.Error(w, "Something went wrong", http.StatusInternalServerError)
			return
		}
		hashedRefreshToken, err := bcrypt.GenerateFromPassword([]byte(refreshToken), bcrypt.DefaultCost)
		if err != nil {
			log.Printf("Error hashing refresh token: %s", err)
			http.Error(w, "Something went wrong", http.StatusInternalServerError)
			return
		}
		_, err = provider.SaveRefreshToken(req.UserId, string(hashedRefreshToken), r.RemoteAddr)
		if err != nil {
			log.Printf("Error saving refresh token: %s", err)
			http.Error(w, "Something went wrong", http.StatusInternalServerError)
			return
		}

		err = json.NewEncoder(w).Encode(TokenResponse{
			AccessToken:  accessToken,
			RefreshToken: refreshToken,
		})
		if err != nil {
			log.Printf("Error encoding response: %s", err)
			http.Error(w, "Something went wrong", http.StatusInternalServerError)
			return
		}
	}
}

func RefreshToken(validator TokenValidator) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		var req RefreshRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			log.Printf("Error decoding body: %s", err)
			http.Error(w, "Invalid request", http.StatusBadRequest)
			return
		}
		claims, err := ValidateJWT(req.AccessToken)
		if err != nil {
			log.Printf("Error validating access token: %s", err)
			http.Error(w, "Invalid access token", http.StatusUnauthorized)
			return
		}
		if err = validator.ValidateRefreshToken(claims.UserId, req.RefreshToken, claims.Ip); err != nil {
			log.Printf("Error validating refresh token: %s", err)
			http.Error(w, "Invalid refresh token", http.StatusUnauthorized)
			return
		}
		if claims.Ip != r.RemoteAddr {
			err = SendEmailWarning(claims.UserId)
			if err != nil {
				log.Printf("Error sending email warning: %s", err)
				http.Error(w, "Something went wrong", http.StatusInternalServerError)
				return
			}
		}
		newAccessToken, err := GenerateJWT(claims.UserId, r.RemoteAddr)
		if err != nil {
			log.Printf("Error generating access token: %s", err)
			http.Error(w, "Something went wrong", http.StatusInternalServerError)
			return
		}
		newRefreshToken, err := GenerateRandomToken()
		if err != nil {
			log.Printf("Error generating refresh token: %s", err)
			http.Error(w, "Something went wrong", http.StatusInternalServerError)
			return
		}
		hashedNewToken, err := bcrypt.GenerateFromPassword([]byte(newRefreshToken), bcrypt.DefaultCost)
		if err != nil {
			log.Printf("Error hashing new refresh token: %s", err)
			http.Error(w, "Something went wrong", http.StatusInternalServerError)
			return
		}
		if _, err = validator.SaveRefreshToken(claims.UserId, string(hashedNewToken), r.RemoteAddr); err != nil {
			log.Printf("Error updating refresh token: %s", err)
			http.Error(w, "Something went wrong", http.StatusInternalServerError)
			return
		}
		err = json.NewEncoder(w).Encode(RefreshResponse{TokenResponse{
			AccessToken:  newAccessToken,
			RefreshToken: newRefreshToken,
		}})
		if err != nil {
			log.Printf("Error encoding response: %s", err)
			http.Error(w, "Something went wrong", http.StatusInternalServerError)
			return
		}
	}
}
