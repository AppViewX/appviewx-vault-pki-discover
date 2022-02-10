package ldb

import (
	"log"
	"testing"
)

func TestGetVaultNameForToken(t *testing.T) {
	vaultName := GetVaultNameForToken(1)
	if vaultName != "vault_1" {
		log.Fatalf("Wrong vaultName for Token")
	}
}

func TestGetVaultNameForPassword(t *testing.T) {
	vaultName := GetVaultNameForPassword(1)
	if vaultName != "vault_password_1" {
		log.Fatalf("Wrong vaultName for password")
	}
}
