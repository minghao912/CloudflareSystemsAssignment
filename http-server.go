package main

import (
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"

	jwt "github.com/golang-jwt/jwt"
	godotenv "github.com/joho/godotenv"
)

const (
	privateKeyPath = "keys/private.pem"
	publicKeyPath  = "keys/public.pem"
)

var (
	verifyBytes []byte
	verifyKey   *rsa.PublicKey
	signKey     *rsa.PrivateKey
)

// Read the key files before starting http handlers
func init() {
	fmt.Println("Reading in key files...")

	// Load env
	err := godotenv.Load(".env")
	if err != nil {
		fmt.Errorf("%s", err)
	}

	// Read keys
	signBytes, err := ioutil.ReadFile(privateKeyPath)
	if err != nil {
		fmt.Errorf("%s", err)
	}

	signKey, err = jwt.ParseRSAPrivateKeyFromPEMWithPassword(signBytes, os.Getenv("KEY_PASSWORD"))
	if err != nil {
		fmt.Errorf("%s", err)
	}

	verifyBytes, err = ioutil.ReadFile(publicKeyPath)
	if err != nil {
		fmt.Errorf("%s", err)
	}

	verifyKey, err = jwt.ParseRSAPublicKeyFromPEM(verifyBytes)
	if err != nil {
		fmt.Errorf("%s", err)
	}

	fmt.Println("Successfully read key files")
}

// Response, simple "hello"
func hello(writer http.ResponseWriter, request *http.Request) {
	fmt.Fprintf(writer, signKey.N.String())
}

// ENDPOINT 1: /auth/<username>
func auth(writer http.ResponseWriter, request *http.Request) {
	// GET requests only
	if request.Method != "GET" {
		writer.WriteHeader(http.StatusBadRequest)
		fmt.Fprintln(writer, "GET requests only", request.Method)
		return
	}

	url := request.URL.Path[1:]
	parsedURL := strings.Split(url, "/")

	// Invalid if it is /auth/something/something/...
	if len(parsedURL) != 2 {
		InvalidURL(&writer)
		return
	}

	// Get username
	username := parsedURL[1]
	fmt.Println("Authenticating user: " + username)

	// Create the JWT token
	// Set claims
	claims := &jwt.StandardClaims{
		ExpiresAt: 86400, // 24 hours in seconds
		Subject:   username,
		Issuer:    "me",
	}

	// Create signer and try generating token using RSA private key
	token := jwt.NewWithClaims(jwt.GetSigningMethod("RS256"), claims)
	signedString, err := token.SignedString(signKey)
	if err != nil {
		writer.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(writer, "Error while signing token:\n"+err.Error())
		fmt.Errorf("%s", "Error while signing token\n")
		return
	}

	// Create cookie
	http.SetCookie(writer, &http.Cookie{
		Name:     "token",
		Value:    signedString,
		Path:     "/",
		HttpOnly: true,
	})

	writer.Header().Set("Content-Type", "text/plain")
	writer.WriteHeader(http.StatusOK)
	fmt.Fprintf(writer, string(verifyBytes)+"\n")
}

// Returns a 404 for an invalid URL
func InvalidURL(writer *http.ResponseWriter) {
	// Set headers and status code
	(*writer).WriteHeader(404)
	(*writer).Header().Set("Content-Type", "application/json")

	// Make JSON
	response := make(map[string]string)
	response["message"] = "Invalid URL"

	jsonResponse, err := json.Marshal(response)
	if err != nil {
		fmt.Printf("Error happened in JSON marshal. Err: %s", err)
	}

	(*writer).Write(jsonResponse)
}

// Main function, runs automatically
func main() {
	http.HandleFunc("/hello", hello)
	http.HandleFunc("/auth/", auth)

	// Host server on port 8090
	http.ListenAndServe(":8090", nil)
}
