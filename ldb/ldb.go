package ldb

import (
	"fmt"
	"os"
	"path/filepath"
	"vault_util/aesencdec"
	"vault_util/common"
	"vault_util/security"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/syndtr/goleveldb/leveldb"
)

//DB to hold the leveldb instance
var DB *leveldb.DB

func StartDB(installationPath string) {
	var err error

	leveldbFolderPath := filepath.Join(common.GetHome(installationPath), common.INSTALLATION_DIRECTORY_NAME, common.LEVEL_DB_FOLDER_NAME)
	DB, err = leveldb.OpenFile(leveldbFolderPath, nil)
	if err != nil {
		log.Println("Error in Opening the file for db : ", err, leveldbFolderPath)
		os.Exit(1)
	}
	// defer DB.Close()
}

//Put - to add the content to the leveldb
func Put(key, value []byte) (err error) {
	err = DB.Put(key, value, nil)
	if err != nil {
		return errors.Wrap(err, "Error while putting the key and value ")
	}
	return
}

//PutByString - to add the content to the leveldb, both key and value are string
func PutByString(key, value string) (err error) {
	err = DB.Put([]byte(key), []byte(value), nil)
	if err != nil {
		return errors.Wrap(err, "Error whilt putting the key and value as string ")
	}
	return
}

//Get - to get the contents from the leveldb both input and the output in byte array
func Get(key []byte) (output []byte, err error) {
	output, err = DB.Get(key, nil)
	if err != nil {
		err = errors.Wrap(err, "Error while getting the value for the given key")
	}
	return
}

//GetByString - to get the associated value both input and output are string
func GetByString(key string) (output string, err error) {
	outputByteArray, err := DB.Get([]byte(key), nil)
	if err != nil {
		err = errors.Wrap(err, "Error in getting the value for the given key string")
	}
	return string(outputByteArray), nil
}

//Delete - to delete the given key and its associated data
func Delete(key []byte) (err error) {
	err = DB.Delete(key, nil)
	if err != nil {
		err = errors.Wrap(err, "Error while deleting the contents from leveldb for given keys")
	}
	return
}

//DisplayDatabase - to display the leveldb database contents
func DisplayDatabase() {
	log.Println("DisplayDatabase : ")
	iter := DB.NewIterator(nil, nil)
	for iter.Next() {
		key := iter.Key()
		value, err := Get(key)
		if err != nil {
			log.Println("DisplayDatabase - error in retrieving the value for the key : ", string(key))
		}
		err = iter.Error()
		if err != nil {
			log.Println("Error in DisplayDatabase ", err)
		}
		displayKeyAndValue(key, value)
	}
}

func displayKeyAndValue(key, value []byte) {
	if string(key) == "certificate_root_hash" {
		log.Printf("Key : %s - Value : %x\n", string(key), value)
	} else {
		log.Printf("Key : %s - Value : %s\n", string(key), value)
	}
}

func PutByStringWithEncryption(key, passwordContents string) error {
	encryptedPassword, err := aesencdec.Encrypt(security.SecurityString(), passwordContents)
	if err != nil {
		log.Error("Error in encrypting the password")
		return err
	}

	err = PutByString(key, encryptedPassword)
	if err != nil {
		log.Errorf("Error in putting the appviewx_password to ldb : %v", err)
		return err
	}
	return nil
}

func GetStringWithDecryption(key string) (string, error) {
	password, err := GetByString(key)
	if err != nil {
		log.Error("Error in retrieving appviewx_password from ldb")
		return "", err
	}

	decryptedPassword, err := aesencdec.Decrypt(security.SecurityString(), password)
	if err != nil {
		log.Errorf("Error in decrypting the password : %v", err)
		return "", err
	}
	return decryptedPassword, nil
}

func GetVaultNameForToken(vaultNumber int) string {
	return fmt.Sprintf("vault_%d", vaultNumber)
}

func GetVaultNameForPassword(vaultNumber int) string {
	return fmt.Sprintf("vault_password_%d", vaultNumber)
}

func GetVaultToken(vaultNumber int) (string, error) {
	vaultName := GetVaultNameForToken(vaultNumber)
	return GetStringWithDecryption(vaultName)
}
