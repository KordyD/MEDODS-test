package handlers

import (
	"encoding/json"
	"golang.org/x/crypto/bcrypt"
	"log"
	"net/http"
	"test_medods/services"
)

type tokenRequest struct {
	UserId string `json:"user_id"`
}

type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

type refreshRequest struct {
	tokenResponse
}

type refreshResponse struct {
	tokenResponse
}

type tokenSaver interface {
	SaveRefreshToken(userId string, tokenHash string, ip string) (int64, error)
}

type tokenValidator interface {
	tokenSaver
	GetRefreshToken(userId string) (string, error)
}

func ReturnTokens(provider tokenSaver) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		var req tokenRequest
		err := json.NewDecoder(r.Body).Decode(&req)
		if err != nil {
			log.Printf("Error decoding body: %s", err)
			http.Error(w, "Invalid request", http.StatusBadRequest)
			return
		}
		accessToken, err := services.GenerateJWT(req.UserId, r.RemoteAddr)
		if err != nil {
			log.Printf("Error generating access token: %s", err)
			http.Error(w, "Something went wrong", http.StatusInternalServerError)
			return
		}
		refreshToken, err := services.GenerateRandomToken()
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

		err = json.NewEncoder(w).Encode(tokenResponse{
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

func RefreshToken(validator tokenValidator) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		var req refreshRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			log.Printf("Error decoding body: %s", err)
			http.Error(w, "Invalid request", http.StatusBadRequest)
			return
		}
		claims, err := services.ValidateJWT(req.AccessToken)
		if err != nil {
			log.Printf("Error validating access token: %s", err)
			http.Error(w, "Invalid access token", http.StatusUnauthorized)
			return
		}
		foundToken, err := validator.GetRefreshToken(claims.UserId)
		if err != nil {
			log.Printf("Can't find the token for the user: %s", err)
			http.Error(w, "This user doesn't have the token", http.StatusUnauthorized)
			return
		}
		err = bcrypt.CompareHashAndPassword([]byte(foundToken), []byte(req.RefreshToken))
		if err != nil {
			log.Printf("Error validating refresh token: %s", err)
			http.Error(w, "Invalid refresh token", http.StatusUnauthorized)
			return
		}

		if claims.Ip != r.RemoteAddr {
			err = services.SendEmailWarning(claims.UserId)
			if err != nil {
				log.Printf("Error sending email warning: %s", err)
				http.Error(w, "Something went wrong", http.StatusInternalServerError)
				return
			}
		}
		newAccessToken, err := services.GenerateJWT(claims.UserId, r.RemoteAddr)
		if err != nil {
			log.Printf("Error generating access token: %s", err)
			http.Error(w, "Something went wrong", http.StatusInternalServerError)
			return
		}
		newRefreshToken, err := services.GenerateRandomToken()
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
		err = json.NewEncoder(w).Encode(refreshResponse{tokenResponse{
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
