package auth

import (
	"errors"
	"net/http"
	"strings"
	"testing"
)

func TestGetAPIKeyFound(t *testing.T) {
	fakeHeader := http.Header{}
	fakekey := "fakekey"
	fakeHeader.Add("Authorization", "ApiKey "+fakekey)
	val, err := GetAPIKey(fakeHeader)
	if err != nil {
		t.Fatalf("expected header to contain %s got %v", fakekey, err)
	}

	if val != fakekey {
		t.Errorf("expected %s for %s", fakekey, err)
	}
}

func TestGetAPIKeyNotFound(t *testing.T) {
	fakeHeader := http.Header{}
	fakeHeader.Add("Authorization", "Api")
	val, err := GetAPIKey(fakeHeader)
	if err == nil {
		t.Fatalf("expected header to contain %v got %v", err, val)
	}

	if !strings.Contains(err.Error(), "malformed") {
		t.Errorf("expected %s for %s", "malformed authorization header", err)
	}
}

func TestGetAuthHeaderNotFound(t *testing.T) {
	fakeHeader := http.Header{}
	val, err := GetAPIKey(fakeHeader)
	if err == nil {
		t.Fatalf("expected err got %s", val)
	}

	if !errors.Is(err, ErrNoAuthHeaderIncluded) {
		t.Errorf("expected %s for %s", "malformed authorization header", err)
	}
}
