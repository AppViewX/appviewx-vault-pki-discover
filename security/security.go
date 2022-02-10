package security

import (
	"vault_util/security/generator"
)

var dummyValue string

func init() {
	dummyValue = generator.SecurityString()
}

//SecurityString - method to get dummyValue
func SecurityString() string {
	return dummyValue
}
