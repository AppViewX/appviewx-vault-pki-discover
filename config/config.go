//Package config handles the external configuration file
package config

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"vault_util/appviewx"
	"vault_util/vault"

	log "github.com/sirupsen/logrus"

	"github.com/pkg/errors"
)

//GetEnvironments - method to generate the required underlying structs to proceed
func GetEnvironments(fileNameWithPath string) (appViewX *appviewx.AppViewXEnv, hashicorpVault *vault.HashicorpVaultEnv, err error) {
	log.Debug("Starting GetEnvironments")
	fileContents, err := ioutil.ReadFile(fileNameWithPath)
	if err != nil {
		log.Error("Error in reading the config file : ", err.Error())
		err = errors.Wrap(err, "Error in reading the config file : ")
		return
	}

	appViewXEnv := appviewx.AppViewXEnv{}
	hashicorpVaultEnv := vault.HashicorpVaultEnv{}

	err = json.Unmarshal(fileContents, &appViewXEnv)
	if err != nil {
		log.Errorf("error in Unmarshalling appViewXEnv: %v", err)
		return &appViewXEnv, &hashicorpVaultEnv, errors.Wrap(err, "Error in Unmarshalling the AppViewX Environment : ")
	}

	err = json.Unmarshal(fileContents, &hashicorpVaultEnv)
	if err != nil {
		log.Errorf("error in Unmarshalling hashicorpVaultEnv: %v", err)
		return &appViewXEnv, &hashicorpVaultEnv, errors.Wrap(err, "Error in Unmarshalling the HashicorpVault Environment : ")
	}
	log.Debug("Finished GetEnvironments")
	return &appViewXEnv, &hashicorpVaultEnv, nil
}

func GetInstallationPath(fileNameWithPath string) (installationPath string) {
	appviewx, _, err := GetEnvironments(fileNameWithPath)
	if err != nil {
		fmt.Println("Error in getting the environments ", err, fileNameWithPath)
	}
	return appviewx.InstallationPath
}
