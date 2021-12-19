package main

import (
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
	"time"

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

	// Initialize global vars for stats
	authTotalNumberOfRuns = 0
	authCurrentAverage = 0
	verifyTotalNumberOfRuns = 0
	verifyCurrentAverage = 0
	fmt.Println("Initialized stat-tracker")
}

// Response, simple "hello"
func hello(writer http.ResponseWriter, request *http.Request) {
	fmt.Fprintf(writer, signKey.N.String())
}

// ENDPOINT 1: /auth/<username>
func auth(writer http.ResponseWriter, request *http.Request) {
	// Start timer
	authStartTime := time.Now()

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
		ExpiresAt: time.Now().Add(time.Hour * 24).Unix(), // 24 hours in seconds
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

	// End timer, update stats
	authTimeElapsed := time.Now().Sub(authStartTime).Milliseconds()
	authCurrentAverage = ((authCurrentAverage * authTotalNumberOfRuns) + int(authTimeElapsed)) / (authTotalNumberOfRuns + 1)
	authTotalNumberOfRuns++
}

// ENDPOINT 2: /verify
func verify(writer http.ResponseWriter, request *http.Request) {
	// Start timer
	verifyStartTime := time.Now()

	// GET requests only
	if request.Method != "GET" {
		writer.WriteHeader(http.StatusBadRequest)
		fmt.Fprintln(writer, "GET requests only", request.Method)
		return
	}

	fmt.Println("Verifying cookie...")

	// Get cookie from header
	cookie := request.Header.Get("Set-Cookie")
	if cookie == "" {
		writer.WriteHeader(http.StatusBadRequest)
		fmt.Fprintln(writer, "Unable to find cookie in header")
		return
	}

	// Get the value of the token
	cookieSplit := strings.Split(cookie, "token=")
	if len(cookieSplit) < 2 {
		writer.WriteHeader(http.StatusBadRequest)
		fmt.Fprintln(writer, "Unable to find cookie with token")
		return
	}

	fmt.Println("> Cookie found")

	// Validate token
	fmt.Println("> Parsing token...")
	token, err := jwt.Parse(cookieSplit[1], func(token *jwt.Token) (interface{}, error) {
		// Use public key to verify
		return verifyKey, nil
	})

	// Process validation errors
	switch err.(type) {
	case *jwt.ValidationError: // Something went wrong during validation
		// Expired token
		if err.(*jwt.ValidationError).Errors == jwt.ValidationErrorExpired {
			writer.WriteHeader(http.StatusUnauthorized)
			fmt.Fprintln(writer, "Expired token")
			return
		}

		// Other error
		writer.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintln(writer, "Error while parsing token")
		fmt.Println("Token parse error: ", err)
		return
	case nil: // No error
		// Invalid token
		if !token.Valid {
			writer.WriteHeader(http.StatusUnauthorized)
			fmt.Fprintln(writer, "Invalid token")
			return
		}

		// Valid token
		fmt.Println("> Successfully verified token: ", token)
		username, err := ExtractTokenData(token)
		if err != nil {
			writer.WriteHeader(http.StatusUnauthorized)
			fmt.Fprintln(writer, "Error parsing token: ", err)
			return
		}

		// Everything OK, return the username
		writer.WriteHeader(http.StatusOK)
		fmt.Fprintln(writer, username)

		break
	default: // Some other error
		writer.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintln(writer, "Error while parsing token")
		fmt.Println("Token parse error: ", err)
		return
	}

	fmt.Println("Cookie verified")

	// End timer, update stats
	verifyTimeElapsed := time.Now().Sub(verifyStartTime).Milliseconds()
	verifyCurrentAverage = ((verifyCurrentAverage * verifyTotalNumberOfRuns) + int(verifyTimeElapsed)) / (verifyTotalNumberOfRuns + 1)
	verifyTotalNumberOfRuns++
}

// Extract data from token
func ExtractTokenData(token *jwt.Token) (string, error) {
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return "", errors.New("Error parsing token claims")
	} else {
		username, ok := claims["sub"].(string)
		if !ok {
			return "", errors.New("Error parsing username")
		}

		return username, nil
	}
}

// Endpoint 3: /README.txt
func showREADME(writer http.ResponseWriter, request *http.Request) {
	readme, err := ioutil.ReadFile("README.txt")
	if err != nil {
		writer.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintln(writer, "Error while loading README")
		fmt.Errorf("%s", err)
		return
	}

	writer.WriteHeader(http.StatusOK)
	fmt.Fprintln(writer, string(readme))
}

// Global variables for stats
var (
	authTotalNumberOfRuns   int
	authCurrentAverage      int
	verifyTotalNumberOfRuns int
	verifyCurrentAverage    int
)

// Endpoint 4: /stats
func stats(writer http.ResponseWriter, request *http.Request) {
	// GET requests only
	if request.Method != "GET" {
		writer.WriteHeader(http.StatusBadRequest)
		fmt.Fprintln(writer, "GET requests only", request.Method)
		return
	}

	// Retreive and show info
	outputString := ""
	outputString += "-- Stats --\n"
	outputString += "Endpoint 1: auth\tNumber of Runs: " + fmt.Sprint(authTotalNumberOfRuns) + "\tAverage: " + fmt.Sprint(authCurrentAverage) + "ms\n"
	outputString += "Endpoint 2: verify\tNumber of Runs: " + fmt.Sprint(verifyTotalNumberOfRuns) + "\tAverage: " + fmt.Sprint(verifyCurrentAverage) + "ms\n"
	fmt.Fprintln(writer, outputString)
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
	// Debug
	http.HandleFunc("/hello", hello)

	// Endpoint 1
	http.HandleFunc("/auth/", auth)

	// Endpoint 2
	http.HandleFunc("/verify", verify)

	// Endpoint 3
	http.HandleFunc("/README.txt", showREADME)

	// Endpoint 4
	http.HandleFunc("/stats", stats)

	// Host server on port 8080
	http.ListenAndServe(":8080", nil)
}
