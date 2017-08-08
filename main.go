// SchnorrSignatureSample project main.go
package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"math/big"
	"reflect"

	"github.com/btcsuite/btcd/btcec"
)

func main() {
	// a is private key
	a, _ := rand.Int(rand.Reader, btcec.S256().N)
	m := []byte("message")

	// Schnorr Signature > sign
	R, s := sign(m, a)

	// A is public key
	aG := new(btcec.PublicKey)
	aG.X, aG.Y = btcec.S256().ScalarBaseMult(a.Bytes())
	A := aG

	// Schnorr Signature > verify
	result := verify(m, A, R, s)
	fmt.Println(result)
}

// m is message, a is private key
func sign(m []byte, a *big.Int) (*btcec.PublicKey, *big.Int) {
	// k is random value
	k, _ := rand.Int(rand.Reader, btcec.S256().N)
	// R is random point
	R := new(btcec.PublicKey)
	R.X, R.Y = btcec.S256().ScalarBaseMult(k.Bytes())
	// sign { s = k - h(m, R)a }
	s := (new(big.Int)).Mod((new(big.Int)).Sub(k, (new(big.Int)).Mul(h(m, R), a)), btcec.S256().N)
	return R, s
}

// m is message, A is public key, R and s are the values ​​returned in sign
func verify(m []byte, A, R *btcec.PublicKey, s *big.Int) bool {
	// left side { sG }
	sG := new(btcec.PublicKey)
	sG.X, sG.Y = btcec.S256().ScalarBaseMult(s.Bytes())

	// right side { R - h(m, R)A }
	// -h(m, R)
	h := (new(big.Int)).Mod((new(big.Int)).Mul(big.NewInt(-1), h(m, R)), btcec.S256().N)
	// -h(m, R)A
	hA := new(btcec.PublicKey)
	hA.X, hA.Y = btcec.S256().ScalarMult(A.X, A.Y, h.Bytes())
	// R - h(m, R)A
	P := new(btcec.PublicKey)
	P.X, P.Y = btcec.S256().Add(R.X, R.Y, hA.X, hA.Y)

	return reflect.DeepEqual(sG.SerializeCompressed(), P.SerializeCompressed())
}

func h(m []byte, R *btcec.PublicKey) *big.Int {
	// Anything is a hash
	h := sha256.Sum256(m)
	mac := hmac.New(sha256.New, R.SerializeCompressed())
	mac.Write(h[:])
	return (new(big.Int)).SetBytes(mac.Sum(nil))
}
