package main

import (
	"encoding/json"
	"golang.org/x/crypto/bcrypt"
	"log"
	"net/http"
	"os"
	"time"
)

func main() {
	http.HandleFunc("/register", Register)
	http.ListenAndServe(":8080", nil)
}

func Register(w http.ResponseWriter, r *http.Request)  {
	if r.Method != "POST" {
		return
	}
	var data User
	if json.NewDecoder(r.Body).Decode(&data) != nil {
		log.Fatalln("Error from decode")
	}
	pass, err := bcrypt.GenerateFromPassword([]byte(data.Password), bcrypt.DefaultCost)
	if err != nil {
		log.Fatalln(err)
	}
	data.Password = string(pass)
	file, err := os.Create(data.Email)
	if err != nil {
		log.Fatalln(err)
	}
	defer file.Close()
	json.NewEncoder(file).Encode(data)
	//w.WriteHeader(http.StatusOK)
	accessToken, err := GenerateToken(data.Email, AccessKey, time.Now().Add(time.Minute).Unix())
	if err != nil {
		log.Fatalln(err)
	}
	refreshToken, err := GenerateToken(data.Email, RefreshKey, time.Now().Add(time.Hour).Unix())
	if err != nil {
		log.Fatalln(err)
	}
	cookie := http.Cookie{
		Name: "access_token",
		Value: accessToken,
		Expires: time.Now().Add(time.Minute),
		HttpOnly: true,
	}
	http.SetCookie(w, &cookie)
	json.NewEncoder(w).Encode(map[string]string{
		"refresh_token": refreshToken,
	})
}