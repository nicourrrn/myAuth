package main

import (
	"encoding/json"
	"golang.org/x/crypto/bcrypt"
	"io"
	"log"
	"net/http"
	"os"
	"time"
)

func main() {
	http.HandleFunc("/register", Register)
	http.HandleFunc("/getme", GetMe)
	http.ListenAndServe(":8080", nil)
}

func Refresh(w http.ResponseWriter, r *http.Request) {
	accCookie, err := r.Cookie("access_token")
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	var body map[string]string
	if json.NewDecoder(r.Body).Decode(&body) != nil {
		http.Error(w, "Error body", http.StatusBadRequest)
		return
	}
	refEnc := GetFromBearer(body["refresh_token"])
	if accCookie.Value == "" || refEnc == "" {
		http.Error(w, "req not contain tokens", http.StatusBadRequest)
		return
	}
	RefreshToken(refEnc, accCookie.Value, RefreshKey, AccessKey)
}

func Register(w http.ResponseWriter, r *http.Request) {
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
	accessToken, err := GenerateToken(data.Email, AccessKey, time.Now().Add(time.Minute).Unix())
	if err != nil {
		log.Fatalln(err)
	}
	refreshToken, err := GenerateToken(data.Email, RefreshKey, time.Now().Add(time.Hour).Unix())
	if err != nil {
		log.Fatalln(err)
	}
	cookie := http.Cookie{
		Name:  "access_token",
		Value: accessToken,
		//Expires: time.Now().Add(time.Minute),
		HttpOnly: true,
	}
	http.SetCookie(w, &cookie)
	json.NewEncoder(w).Encode(map[string]string{
		"refresh_token": refreshToken,
	})
}

func GetMe(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		return
	}
	//var auth jwt.StandardClaims
	authCookie, err := r.Cookie("access_token")
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	auth, err := ValidateToken(authCookie.Value, AccessKey)
	if err != nil {
		//http.Error(w, "Old token, go to /refresh", http.StatusUnauthorized)
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	//if auth.ExpiresAt < time.Now().Unix(){
	//	http.Error(w, "Old token, go to /refresh", http.StatusUnauthorized)
	//	return
	//}
	w.WriteHeader(http.StatusOK)
	file, err := os.Open(auth.Id)
	if err != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}
	io.Copy(w, file)
}
