package branca

import (
	"errors"
	"testing"
	"time"
)

func TestCorrectEncodeDecode(t *testing.T) {
	b := NewBranca([]byte("supersecretkeyyoushouldnotcommit"))
	helloWorld := []byte("Hello world!")
	res, e := b.EncodeToString(helloWorld)
	if e != nil {
		t.Error(e)
	}

	res2, e := b.DecodeToString(res)
	if e != nil {
		t.Error(e)
	}

	if len(res2) != len(helloWorld) {
		t.Error("encode and decode byte array different length")
	}

	for i := range res2 {
		if res2[i] != helloWorld[i] {
			t.Error("encode and decode str are not the same")
		}
	}
}
func TestNounceRandomness(t *testing.T) {
	b := NewBranca([]byte("supersecretkeyyoushouldnotcommit"))
	helloWorld := []byte("Hello world!")
	res, e := b.EncodeToString(helloWorld)
	if e != nil {
		t.Error(e)
	}

	res2, e := b.EncodeToString(helloWorld)
	if e != nil {
		t.Error(e)
	}

	if res == res2 {
		t.Error("two sequential encodings produced the same result")
	}
}

// TestExpiredTokenError tests if decoding an expired tokens returns the corresponding error type.
func TestExpiredTokenError(t *testing.T) {
	b := NewBranca([]byte("supersecretkeyyoushouldnotcommit"))

	ttl := time.Second * 1
	b.SetTTL(uint32(ttl.Seconds()))
	token, encErr := b.EncodeToString([]byte("Hello World!"))
	if encErr != nil {
		t.Errorf("%q", encErr)
	}

	// Wait (with enough additional waiting time) until the token is expired...
	time.Sleep(ttl * 3)
	// ...and decode the token again that is expired by now.
	_, decErr := b.DecodeToString(token)
	var errExpiredToken *ErrExpiredToken
	if !errors.As(decErr, &errExpiredToken) {
		t.Errorf("%v", decErr)
	}
}

// TestInvalidTokenError tests if decoding an invalid token returns the corresponding error type.
func TestInvalidTokenError(t *testing.T) {
	b := NewBranca([]byte("supersecretkeyyoushouldnotcommit"))

	_, err := b.DecodeToString("$")
	if !errors.Is(err, ErrInvalidToken) {
		t.Errorf("%v", err)
	}
}

// TestInvalidTokenVersionError tests if decoding an invalid token returns the corresponding error type.
func TestInvalidTokenVersionError(t *testing.T) {
	// A token with an invalid version where the HEX value 0XBA has been replaced with 0xFF.
	// The original token is "1WgRcDTWm6MyptVOMG9TeEPVcYW01K6hW5SzLrzCkLlrOOovO5TmpDxQql12N2n0jELx".
	tokenWithInvalidVersion := "25jsrzc9Q6kmzrnCYWf5Z7LCOG2C7Uiu3NbTP0B9ppLDrxZkhLGOuFVB6FqrWp0ypJTF"

	b := NewBranca([]byte("supersecretkeyyoushouldnotcommit"))
	_, err := b.DecodeToString(tokenWithInvalidVersion)
	if !errors.Is(err, ErrInvalidTokenVersion) {
		t.Errorf("%v", err)
	}
}

// TestBadKeyLengthError tests if (en/de)coding a token with an invalid key returns the corresponding error type.
func TestBadKeyLengthError(t *testing.T) {
	validToken := "875GH233T7IYrxtgXxlQBYiFobZMQdHAT51vChKsAIYCFxZtL1evV54vYqLyZtQ0ekPHt8kJHQp0a"
	testKeys := []string{
		"",
		"thiskeyistooshort",
		"thiskeyislongerthantheexpected32bytes",
	}

	for _, key := range testKeys {
		b := NewBranca([]byte(key))

		_, err := b.DecodeToString(validToken)
		if !errors.Is(err, ErrBadKeyLength) {
			t.Errorf("%v", err)
		}
	}
}
