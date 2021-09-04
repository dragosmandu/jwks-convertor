/*
   jwks.go

   Created by Dragos-Costin Mandu on 04/09/2021.
*/

package jwks

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"math/big"
	"net/http"
)

type (
	Jwk    map[string]interface{}
	JwkSet map[string][]Jwk
)

// Creates a new jwk set from a given target url.
func NewJwkSet(target string) (*JwkSet, error) {
	if target == "" {
		return nil, errors.New("invalid empty target url")
	}

	data, err := getHttpRespData(target)
	if err != nil {
		return nil, err
	}

	return parseJwksData(data)
}

// Searches the key with given kid and returns it as an
// object of that specific key type.
// Possible key types: RSA.
func (jwkSet *JwkSet) GetKey(kid string) (interface{}, error) {
	if kid == "" {
		return nil, errors.New("invalid empty key id")
	}

	jwk, err := jwkSet.lookupJwk(kid)
	if err != nil {
		return nil, err
	}

	return jwk.convertJwkToKey()
}

// Gets the data from the response body from target.
func getHttpRespData(target string) ([]byte, error) {
	resp, err := http.Get(target)
	if err != nil {
		return nil, fmt.Errorf("failed to get from %s: %v", target, err)
	}

	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %v", err)
	}

	return data, nil
}

func parseJwksData(data []byte) (*JwkSet, error) {
	var jwks JwkSet

	if err := json.Unmarshal(data, &jwks); err != nil {
		return nil, fmt.Errorf("failed to parse jwk set data: %v", err)
	}

	return &jwks, nil
}

func (jwkSet *JwkSet) lookupJwk(kid string) (*Jwk, error) {
	if keys, ok := (*jwkSet)["keys"]; ok {
		for _, key := range keys {
			currentKid, ok := key["kid"].(string)

			if ok && currentKid == kid {
				return &key, nil
			}
		}

		return nil, fmt.Errorf("key with id %s not found", kid)
	}

	return nil, fmt.Errorf("invalid jwk set")
}

func (jwk *Jwk) convertJwkToKey() (interface{}, error) {
	kty, ok := (*jwk)["kty"].(string)
	if !ok || kty != "RSA" {
		return nil, fmt.Errorf("invalid key type")
	}

	encN := (*jwk)["n"].(string)

	// Decode bytes for n.
	decN, err := base64.RawURLEncoding.DecodeString(encN)
	if err != nil {
		return nil, err
	}

	e, ok := (*jwk)["e"].(string)
	if ok && (e == "AQAB" || e == "AAEAAQ") {
		return &rsa.PublicKey{
			N: new(big.Int).SetBytes(decN),
			E: 65537, // Set the exponent.
		}, nil
	}

	return nil, fmt.Errorf("invalid jwk")
}
