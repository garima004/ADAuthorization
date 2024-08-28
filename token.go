package main

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"time"

	"github.com/coreos/go-oidc"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/oauth2"
)

const (
	clientID     = "6c17737e-3175-4d30-8224-68cbfe4d8407"
	clientSecret = "s1E8Q~wHnI5R3lrp5hS6ue8wVxcJ8LYxzs7eWcou"
	tenantID     = "03bc542b-c613-436a-a090-916ce925cee0"
	redirectURL  = "http://localhost:8080/callback"

	azureADAuthority = "https://login.microsoftonline.com/"
	azureADJWKsURL   = azureADAuthority + tenantID + "/discovery/v2.0/keys"
	expectedAudience = clientID
	expectedIssuer   = azureADAuthority + tenantID + "/v2.0"
)

var oauth2Config *oauth2.Config

//var verifier *oidc.IDTokenVerifier

func init() {
	ctx := context.Background()
	provider, err := oidc.NewProvider(ctx, azureADAuthority+tenantID+"/v2.0")
	if err != nil {
		log.Fatal(err)
	}

	oauth2Config = &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		Endpoint:     provider.Endpoint(),
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email", "offline_access"},
	}

	//verifier = provider.Verifier(&oidc.Config{ClientID: clientID})
}

func main() {
	http.HandleFunc("/", handleHome)
	http.HandleFunc("/login", handleLogin)
	http.HandleFunc("/callback", handleCallback)

	log.Println("Server is running at http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func handleHome(w http.ResponseWriter, r *http.Request) {
	html := `<html><body><a href="/login">Login with Azure AD</a></body></html>`
	fmt.Fprint(w, html)
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	state := "random" // Generate a secure random state in production
	http.Redirect(w, r, oauth2Config.AuthCodeURL(state), http.StatusFound)
}

func handleCallback(w http.ResponseWriter, r *http.Request) {
	ctx := context.Background()
	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(w, "Code not found in the query string", http.StatusBadRequest)
		return
	}

	oauth2Token, err := oauth2Config.Exchange(ctx, code)
	if err != nil {
		http.Error(w, "Failed to exchange token: "+err.Error(), http.StatusInternalServerError)
		return
	}

	idToken := oauth2Token.Extra("id_token").(string)
	log.Printf("ID Token: %s\n", idToken) // Print the ID token

	// Validate the ID token at the backend
	jwks, err := FetchJWKs(ctx)
	if err != nil {
		http.Error(w, "Failed to fetch JWKs: "+err.Error(), http.StatusInternalServerError)
		return
	}

	token, err := ValidateIDToken(idToken, jwks)
	if err != nil {
		http.Error(w, "Token validation failed: "+err.Error(), http.StatusUnauthorized)
		return
	}

	claims := token.Claims.(jwt.MapClaims)
	fmt.Fprintf(w, "User authenticated! Token claims: %v\n", claims)
}

// FetchJWKs fetches the JWKs from Azure AD
func FetchJWKs(ctx context.Context) (*JWKS, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", azureADJWKsURL, nil)
	if err != nil {
		return nil, err
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var jwks JWKS
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		return nil, err
	}

	fmt.Printf("Fetched JWKs: %+v\n", jwks) // Debugging line
	return &jwks, nil
}

// JWK represents a JSON Web Key
type JWK struct {
	Kid string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
}

// JWKS represents a set of JWKs
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// DecodePublicKey decodes a JWK to an RSA public key
func DecodePublicKey(jwk JWK) (*rsa.PublicKey, error) {
	nBytes, err := base64.RawURLEncoding.DecodeString(jwk.N)
	if err != nil {
		return nil, err
	}

	eBytes, err := base64.RawURLEncoding.DecodeString(jwk.E)
	if err != nil {
		return nil, err
	}

	eInt := 0
	for _, b := range eBytes {
		eInt = eInt*256 + int(b)
	}

	pubKey := &rsa.PublicKey{
		N: new(big.Int).SetBytes(nBytes),
		E: eInt,
	}

	fmt.Printf("Decoded Public Key: %+v\n", pubKey) // Debugging line
	return pubKey, nil
}

// ValidateIDToken validates a JWT ID token using the public key
func ValidateIDToken(tokenString string, jwks *JWKS) (*jwt.Token, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if kid, ok := token.Header["kid"].(string); ok {
			fmt.Printf("Token KID: %s\n", kid) // Debugging line
			for _, key := range jwks.Keys {
				fmt.Printf("JWK KID: %s\n", key.Kid) // Debugging line
				if key.Kid == kid {
					return DecodePublicKey(key)
				}
			}
		}
		return nil, errors.New("no matching key found")
	})

	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return nil, errors.New("invalid token")
	}

	if aud, ok := claims["aud"].(string); !ok || aud != expectedAudience {
		return nil, errors.New("invalid audience")
	}

	if iss, ok := claims["iss"].(string); !ok || iss != expectedIssuer {
		return nil, errors.New("invalid issuer")
	}

	exp := int64(claims["exp"].(float64))
	if exp < time.Now().Unix() {
		return nil, errors.New("token has expired")
	}

	return token, nil
}
