package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

var secret = []byte("myHardSecretToGu$$##")

func main() {
	exp, _ := time.Parse(time.DateTime, "2024-06-15 11:00:00")

	token, err := createToken(secret, &CustomClaim{
		UserID: uuid.NewString(),
		Role:   "admin",
		RegisteredClaims: jwt.RegisteredClaims{
			NotBefore: &jwt.NumericDate{Time: exp},
		},
	})

	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(token)

	claims, err := parseToken(token, secret)
	if err != nil {
		if errors.Is(err, jwt.ErrTokenNotValidYet) {
			log.Fatalf("token will be valid in %f hours\n", time.Until(claims.NotBefore.Time).Hours())
		}
		log.Fatal(err)
	}

	fmt.Println(claims.Role, claims.UserID)
}

type CustomClaim struct {
	jwt.RegisteredClaims
	Role   string
	UserID string
}

func createToken(secret []byte, claims *CustomClaim) (string, error) {
	return jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(secret)
}

func parseToken(tokenString string, secret []byte) (*CustomClaim, error) {
	token, err := jwt.ParseWithClaims(tokenString, &CustomClaim{}, func(t *jwt.Token) (interface{}, error) {
		return secret, nil
	})

	var claim *CustomClaim
	if token.Claims != nil {
		cc, ok := token.Claims.(*CustomClaim)
		if ok {
			claim = cc
		}
	}

	if err != nil {
		return claim, err
	}

	if !token.Valid {
		return claim, errors.New("token is not valid")
	}

	return claim, nil
}

func jwtManualCreation() {
	headerMap := map[string]any{
		// "alg": "HS256",
		"alg": "HS512",
		// "typ": "JWT",
	}

	header, _ := json.Marshal(&headerMap)

	payloadMap := map[string]any{
		"sub":  "view-users-123980",
		"role": "admin",
	}

	payload, _ := json.Marshal(&payloadMap)

	encodedHeader := base64.RawURLEncoding.EncodeToString(header)
	encodedPayload := base64.RawURLEncoding.EncodeToString(payload)

	sign, err := hs512([]byte(encodedHeader+"."+encodedPayload), []byte("D84jd^<sD84jd^<sD84jd^<sD84jd^<sD84jd^<sD84jd^<sD84jd^<sD84jd^<s"))
	if err != nil {
		log.Fatal(err)
	}

	encodedSign := base64.RawURLEncoding.EncodeToString(sign)

	fmt.Printf("%s.%s.%s\n", encodedHeader, encodedPayload, encodedSign)
}

func hs256(data, secret []byte) ([]byte, error) {
	hmc256 := hmac.New(sha256.New, secret)

	_, err := hmc256.Write(data)

	if err != nil {
		return nil, err
	}

	return hmc256.Sum(nil), nil
}

func hs512(data, secret []byte) ([]byte, error) {
	hmc256 := hmac.New(sha512.New, secret)

	_, err := hmc256.Write(data)

	if err != nil {
		return nil, err
	}

	return hmc256.Sum(nil), nil
}
