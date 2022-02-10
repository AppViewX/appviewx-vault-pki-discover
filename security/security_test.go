package security

import "testing"

func TestSecurityString(t *testing.T) {
	output := SecurityString()
	if output == "" {
		t.Fatalf("Error in getting the security String")
	}
}
