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
	mux := http.NewServeMux()
	mux.HandleFunc("/register", Register)
	//mux.HandleFunc("/getme", GetMe)
	mux.Handle("/getme", Logging(http.HandlerFunc(GetMe)))
	mux.HandleFunc("/refresh", Refresh)
	http.ListenAndServe("localhost:8080", mux)
}

func Refresh(w http.ResponseWriter, r *http.Request) {
	accCookie, err := r.Cookie("access_token")
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	refData := GetFromBearer(r.Header.Get("refresh_token"))
	if accCookie.Value == "" || refData == "" {
		http.Error(w, "req not contain tokens", http.StatusBadRequest)
		return
	}
	newAcc, newRef, err := RefreshToken(refData, accCookie.Value, RefreshKey, AccessKey)
	if err != nil {
		http.Error(w, "My error", http.StatusBadRequest)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     "access_token",
		Value:    newAcc,
		HttpOnly: true,
	})
	data, _ := json.Marshal(map[string]string{
		"refresh_token": newRef,
	})
	w.Write(data)

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
	w.WriteHeader(http.StatusOK)
	file, err := os.Open(auth.Id)
	if err != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}
	io.Copy(w, file)
}

func Logging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, req)
		log.Printf("%s %s %s", req.Method, req.RequestURI, time.Since(start))
	})
}
