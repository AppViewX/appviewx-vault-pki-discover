package appviewx

import (
	"testing"
)

func TestGetHeadersWithSessionID(t *testing.T) {
	appViewXEnv := AppViewXEnv{}
	headers := appViewXEnv.getDefaultHeaders()
	appViewXEnv.sessionID = "testSessionID"

	if value, ok := headers["sessionId"]; ok {
		t.Fatalf("GetHeadersWithSessionID value %v, want : %v", value, "nil")
	}

	headersNew := appViewXEnv.getHeadersWithSessionID()
	if value, ok := headersNew["sessionId"]; !ok {
		t.Fatalf("GetHeadersWithSessionID value %v, want : %v", value, "nil")
	}
}

func TestGetDefaultHeaders(t *testing.T) {
	appViewXEnv := AppViewXEnv{}
	defaultHeaders := appViewXEnv.getDefaultHeaders()

	expected := make(map[string]string)
	expected["Content-Type"] = "application/json"
	expected["Accept"] = "application/json"

	for key, value := range defaultHeaders {
		expectedVale, _ := expected[key]
		if value != expectedVale {
			t.Fatalf("GetDefaultHeaders key %v, received : %v, required : %v", key, value, expectedVale)
		}

	}
}

func TestGetHeadersForLogin(t *testing.T) {
	t.Log()
	getPassword = func(password string) (string, error) {
		return "password", nil
	}
	apppviewxEnv := AppViewXEnv{}
	apppviewxEnv.UserName = "username"

	output, err := apppviewxEnv.getHeadersForLogin()
	if err != nil {
		t.Fatalf("Error in getting headers for login %v", err)
	}

	userName, ok := output["username"]
	if !ok {
		t.Fatalf("Error in getting the username %v", err)
	}
	if userName != "username" {
		t.Fatalf("Wrong username ")
	}

}
