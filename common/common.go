//Package common provides the common interfaces and the methods can be used by all the pakcages
package common

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"sync"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

const (
	INSTALLATION_DIRECTORY_NAME = "appviewx_vault_util"
	LEVEL_DB_FOLDER_NAME        = "leveldb"
	CONFIG_FILE_NAME            = "config.json"
	LOG_FOLDER_NAME             = "logs"
	LOG_FILE_NAME               = "appviewx_vault_util.log"
)

//Vault interface for Listing and To Get Certificates
type Vault interface {
	ListCertificates() (output []string, err error)
	GetCertificate(certificateName, vaultCertificateField string) (output string, err error)
	SetToken(newToken string)
}

//AppViewX interface for Uploading the certificate
type AppViewX interface {
	Login() error
	UploadCertificate(string, string, chan int, *sync.WaitGroup) error
	CreateGroup(string) error
}

//MakePostCallAndReturnResponse - This Method is to handle the post call request
func MakePostCallAndReturnResponse(url string, payload interface{}, headers map[string]string, queryParams map[string]string) (output []byte, err error) {
	log.Debug("Starting MakePostCallAndReturnResponse")
	log.Trace("url : ", url)

	requestPayloadBytes, err := json.Marshal(payload)
	log.Trace("requestPayloadBytes : ", string(requestPayloadBytes))
	if err != nil {
		log.Error("Error in Marshalling the request Payload " + err.Error())
		return nil, errors.Wrap(err, "Error in Marshalling the request Payload")
	}

	client := http.Client{
		Transport: &http.Transport{
			DisableKeepAlives: true,
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}

	request, err := http.NewRequest("POST", url, bytes.NewBuffer(requestPayloadBytes))
	if err != nil {
		log.Error("Error in creating Post request " + err.Error())
		return nil, errors.Wrap(err, "Error in creating post request ")
	}

	log.Trace("headers : ", headers)
	log.Trace("queryParams : ", queryParams)

	q := request.URL.Query()
	for key, value := range queryParams {
		q.Add(key, value)
	}
	request.URL.RawQuery = q.Encode()

	// log.Trace("headers : ", headers)
	for key, value := range headers {
		request.Header.Set(key, value)
	}

	request.Close = true

	response, err := client.Do(request)
	if err != nil {
		log.Error("Error in making http request : " + err.Error())
		return nil, errors.Wrap(err, "Error in making http request ")
	}

	body, err := ioutil.ReadAll(response.Body)
	response.Body.Close()

	log.Trace("response : ", string(body))
	output = body
	if err != nil || len(body) <= 0 {
		log.Error("Error in reading the response : " + err.Error())
		return nil, errors.Wrap(err, "Error in reading the response")
	} else if response.StatusCode == 500 {
		err = errors.New("StatusCode: " + fmt.Sprintf("%d", response.StatusCode))
		err = errors.Wrap(err, "Status:"+response.Status)
		return output, err
	} else if !(response.StatusCode >= 200 && response.StatusCode <= 299) {
		// log.Error("Status : ", response.Status)
		return nil, errors.New("Status: " + response.Status)
	}

	log.Debug("Finished MakePostCallAndReturnResponse")
	return
}

//MakeGetCallAndReturnResponse - This Method is to handle the get call request
func MakeGetCallAndReturnResponse(url string, headers map[string]string, queryParams map[string]string) (output []byte, err error) {
	log.Debug("Starting MakeGetCallAndReturnResponse")
	log.Trace("url = ", url)
	client := http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}

	request, err := http.NewRequest("GET", url, nil)
	if err != nil {
		log.Error("Error in creating get request " + err.Error())
		return nil, errors.Wrap(err, "Error in creating get request ")
	}

	log.Trace("headers : ", headers)
	log.Trace("queryParams : ", queryParams)

	q := request.URL.Query()
	for key, value := range queryParams {
		q.Add(key, value)
	}
	request.URL.RawQuery = q.Encode()

	// log.Trace("headers : ", headers)
	for key, value := range headers {
		request.Header.Add(key, value)
	}

	request.Close = true

	response, err := client.Do(request)
	log.Trace("response.StatusCode : ", response.StatusCode)
	log.Trace("response.Status : ", response.Status)
	if err != nil {
		log.Error("Error in making http request : " + err.Error())
		return nil, errors.Wrap(err, "Error in making http request ")
	} else if !(response.StatusCode >= 200 && response.StatusCode <= 299) {
		log.Error("Status : ", response.Status)
		return nil, errors.New("Status: " + response.Status)
	}

	body, err := ioutil.ReadAll(response.Body)
	response.Body.Close()

	log.Trace("body : ", string(body))
	if err != nil || len(body) <= 0 {
		log.Error("Error in reading the response : " + err.Error())
		return nil, errors.Wrap(err, "Error in reading the response")
	}
	output = body
	log.Debug("Finished MakeGetCallAndReturnResponse")
	return
}

//GetHome - This method to get the home folder location
func GetHome(configBasePath string) (output string) {
	if configBasePath == "" {
		var err error
		output, err = os.UserHomeDir()
		if err != nil {
			fmt.Println("Error in getting the user user home directory :", err)
		}
	} else {
		output = configBasePath
	}
	return
}
