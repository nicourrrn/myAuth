package main

import (
	"github.com/golang-jwt/jwt"
)

func GenerateToken(email, key string, lifeTime int64) (string, error) {
	claim := jwt.StandardClaims{
		Id: email,
		ExpiresAt: lifeTime,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claim)
	return token.SignedString([]byte(key))
}
