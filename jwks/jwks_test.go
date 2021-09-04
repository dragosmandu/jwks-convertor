/*
   jwks_test.go

   Created by Dragos-Costin Mandu on 04/09/2021.
*/

package jwks_test

import (
	"crypto/rsa"
	"testing"

	"github.com/dragosmandu/jwks-convertor/jwks"
)

const (
	appleSetTarget  = "https://appleid.apple.com/auth/keys"
	validAppleKid   = "YuyXoY"
	invalidAppleKid = "invalid"
)

func TestNewJwkSet(t *testing.T) {
	t.Run("New JWK Set", func(t *testing.T) {
		jwkSet, err := jwks.NewJwkSet(appleSetTarget)
		if err != nil {
			t.Fatal(err)
		}

		t.Run("Valid Apple Kid", func(t *testing.T) {
			key, err := jwkSet.GetKey(validAppleKid)
			if err != nil {
				t.Fatal(err)
			}

			if _, ok := key.(*rsa.PublicKey); !ok {
				t.Fatal("invalid key type")
			}
		})

		t.Run("Invalid Apple Kid", func(t *testing.T) {
			_, err := jwkSet.GetKey(invalidAppleKid)
			if err == nil {
				t.Fatal("should be an invalid key id")
			}
		})
	})
}
