
// Sample run-helloworld is a minimal Cloud Run service.
package main

import (
    "crypto/rsa"
    "crypto/x509"
    "encoding/pem"
    "errors"
    "fmt"
    "io/ioutil"
    "log"
    "net/http"
    "os"
    "time"

    "golang.org/x/oauth2/google"
    "golang.org/x/oauth2/jws"
)

func main() {
        log.Print("starting server...")
        http.HandleFunc("/hello", handler)
		http.HandleFunc("/token", tokenHandler)
        // Determine port for HTTP service.
        port := os.Getenv("PORT")
        if port == "" {
                port = "8080"
                log.Printf("defaulting to port %s", port)
        }

        // Start HTTP server.
        log.Printf("listening on port %s", port)
        if err := http.ListenAndServe(":"+port, nil); err != nil {
                log.Fatal(err)
        }
}

func handler(w http.ResponseWriter, r *http.Request) {
        name := os.Getenv("NAME")
        if name == "" {
                name = "World"
        }
        fmt.Fprintf(w, "Hello %s!\n", name)
}
func tokenHandler(w http.ResponseWriter, r *http.Request) {
		saKeyfile := "./sound-health-5c414-9a1a17c81e5b.json"
		saEmail := "alignmtsa@sound-health-5c414.iam.gserviceaccount.com"
		audience := "alignmt-poc-a89il31j.uc.gateway.dev"
		// expiryLength := 3600
		
		token, err := generateJWT(saKeyfile, saEmail, audience )
		if err != nil {
				http.Error(w, fmt.Sprintf("Could not generate JWT: %v", err), http.StatusInternalServerError)
				return
		}
		fmt.Fprintf(w, "%s\n", token)
}



// generateJWT creates a signed JSON Web Token using a Google API Service Account.
func generateJWT(saKeyfile, saEmail, audience string) (string, error) {
	now := time.Now().Unix()
	expiry := time.Now().Add(time.Hour * 24).Unix()
	// Build the JWT payload.
	jwt := &jws.ClaimSet{
			Iat: now,
			// expires after 'expiryLength' seconds.
			Exp: expiry,
			// Iss must match 'issuer' in the security configuration in your
			// swagger spec (e.g. service account email). It can be any string.
			Iss: saEmail,
			// Aud must be either your Endpoints service name, or match the value
			// specified as the 'x-google-audience' in the OpenAPI document.
			Aud: audience,
			// Sub and Email should match the service account's email address.
			Sub:           saEmail,
			PrivateClaims: map[string]interface{}{"email": saEmail,"test":"test"},
	}
	jwsHeader := &jws.Header{
			Algorithm: "RS256",
			Typ:       "JWT",
	}

	// Extract the RSA private key from the service account keyfile.
	sa, err := ioutil.ReadFile(saKeyfile)
	if err != nil {
			return "", fmt.Errorf("Could not read service account file: %w", err)
	}
	conf, err := google.JWTConfigFromJSON(sa)
	if err != nil {
			return "", fmt.Errorf("Could not parse service account JSON: %w", err)
	}
	block, _ := pem.Decode(conf.PrivateKey)
	parsedKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
			return "", fmt.Errorf("private key parse error: %w", err)
	}
	rsaKey, ok := parsedKey.(*rsa.PrivateKey)
	// Sign the JWT with the service account's private key.
	if !ok {
			return "", errors.New("private key failed rsa.PrivateKey type assertion")
	}
	return jws.Encode(jwsHeader, jwt, rsaKey)
}



