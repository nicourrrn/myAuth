package main

import (
	"errors"
	"github.com/golang-jwt/jwt"
	"log"
	"strings"
	"time"
)

func GenerateToken(email, key string, lifeTime int64) (string, error) {
	claim := jwt.StandardClaims{
		Id:        email,
		ExpiresAt: lifeTime,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claim)
	return token.SignedString([]byte(key))
}

func GetFromBearer(req string) string {
	bearerReq := strings.HasPrefix(req, "Bearer")
	words := strings.Split(req, " ")
	if len(words) == 2 && bearerReq {
		return words[1]
	}
	return ""
}

func ValidateToken(tokenEncrypted, key string) (*jwt.StandardClaims, error) {
	token, err := jwt.ParseWithClaims(tokenEncrypted, &jwt.StandardClaims{},
		func(token *jwt.Token) (interface{}, error) {
			return []byte(key), nil
		})
	if err != nil {
		return nil, err
	}
	claim, ok := token.Claims.(*jwt.StandardClaims)
	if !ok || !token.Valid {
		return nil, errors.New("Invalid...")
	}
	return claim, nil
}

func RefreshToken(refTokenEnc, accTokenEnc, refKey, accKey string) (string, string, error) {
	refToken, err := jwt.ParseWithClaims(refTokenEnc, &jwt.StandardClaims{},
		func(token *jwt.Token) (interface{}, error) {
			return []byte(refKey), nil
		})
	if err != nil {
		return "", "", errors.New("invalid refToken")
	}
	accToken, _ := jwt.ParseWithClaims(accTokenEnc, &jwt.StandardClaims{},
		func(token *jwt.Token) (interface{}, error) {
			return []byte(accKey), nil
		})
	if err != nil && !strings.HasPrefix(err.Error(), "token is expired") {
		return "", "", err
	}
	refData, okR := refToken.Claims.(*jwt.StandardClaims)
	accData, okA := accToken.Claims.(*jwt.StandardClaims)
	if !okR || !okA {
		return "", "", errors.New("token not parsed")
	}
	if refData.Id != accData.Id {
		return "", "", errors.New("tokens data not equals")
	}
	newAccessToken, err := GenerateToken(refData.Id, AccessKey, time.Now().Add(time.Minute).Unix())
	if err != nil {
		log.Fatalln(err)
	}
	newRefreshToken, err := GenerateToken(refData.Id, RefreshKey, time.Now().Add(time.Hour).Unix())
	if err != nil {
		log.Fatalln(err)
	}
	return newAccessToken, newRefreshToken, nil
}
