//Package vault provides the integration to the given vault environment
package vault

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"
	"vault_util/common"
	"vault_util/ldb"

	log "github.com/sirupsen/logrus"

	"github.com/pkg/errors"
)

var m1 = sync.Mutex{}
var m2 = sync.Mutex{}
var m3 = sync.Mutex{}

//HashicorpVaultEnv to contain the HashicorpVault environment details
type HashicorpVaultEnv struct {
	IsHTTPS                     bool
	Host                        string
	Port                        int
	PKIEngineName               string
	RequestPathListCertificates *string
	RequestPathGetCertificates  *string
	RequestQuery                map[string]string
	PKIEngines                  []*PKIEngine
	Vaults                      []*Vault `json:"vaults"`
	AutoDiscoverPKIEngines      bool
	VaultToken                  *string
	CurrentNamespace            *string
	CurrentVault                *Vault
	CurrentVaultNumer           int
	TokenUpdatedTime            *time.Time
	UseRootToken                bool
}

type Vault struct {
	Name                          string       `json:"name"`
	IsHTTPS                       bool         `json:"vault_is_https"`
	Host                          string       `json:"vault_host"`
	Port                          int          `json:"vault_api_port"`
	PKIEngines                    []*PKIEngine `json:"pki_engines"`
	AutoDiscoverPKIEngines        bool         `json:"auto_discover_pki_engines"`
	VaultToken                    *string      `json:"vault_token"`
	RequestPathListCertificates   *string
	RequestPathGetCertificates    *string
	RequestQuery                  map[string]string
	IsUserNameBasedAuthentication bool     `json:"is_username_based_authentication"`
	AuthPath                      string   `json:"auth_path"`
	UserName                      string   `json:"user_name"`
	ListOfNamespaces              []string `json:"list_of_namespaces"`
	UseRootToken                  bool     `json:"use_root_token"`
}

//PKIEngine to specify a PKI Engine path details
type PKIEngine struct {
	Name         string            `json:"name"`
	ListPath     string            `json:"list_path"`
	GetPath      string            `json:"get_path"`
	RequestQuery map[string]string `json:"request_query"`
}

//VaultResponse contains the common vault response details
type VaultResponse struct {
	RequestID     string      `json:"request_id"`
	LeaseID       string      `json:"request_id"`
	IsRenewable   interface{} `json:"renewable"`
	LeaseDuration int         `json:"lease_duration"`
	WrapInfo      interface{} `json:"wrap_info"`
	Warnings      interface{} `json:"warnings"`
	Auth          interface{} `json:"auth"`
}

//VaultCertListResponse contains the List response from the vault
type VaultCertListResponse struct {
	VaultResponse
	Data VaultCertListData `json:"data"`
}

//VaultCertListData to contain the list of keys in the data objects received as resonse from the vault for the list call
type VaultCertListData struct {
	Keys []string `json:"keys"`
}

//VaultGetCertificateResponse to contain the certificate response details
type VaultGetCertificateResponse struct {
	VaultResponse
	Data VaultCertificateData `json:"data"`
}

type VaultCertificateData struct {
	Alternatives interface{} `json:"alternatives"`
	Certificate  string      `json:"certificate"`
	CommonName   string      `json:"common_name"`
	CSR          string      `json:"csr"`
	PrivateKey   string      `json:"private_key"`
	SerialNumber string      `json:"serial_number"`
	Status       bool        `json:"status"`
}

type ResponseForToken struct {
	Auth struct {
		ClientToken string `json:"client_token"`
	} `json:"auth"`
}

func (vaultEnv *HashicorpVaultEnv) SetToken(newToken string) {
	vaultEnv.VaultToken = &newToken
}

func (vaultEnv *HashicorpVaultEnv) DiscoverPKIEngines() (err error) {
	log.Debug("Starting DiscoverPKIEngines")

	defer func() {
		if r := recover(); r != nil {
			log.Errorf("Recovered from Panic ListCertificates : %v", r)
			err = fmt.Errorf("recovered from panic ListCertificates : %v", r)
		}
	}()

	url, err := vaultEnv.getURLForListPKIEngines()
	if err != nil {
		log.Errorf("Error in DiscoveyPKI engine getURLForListPKIEngines : %v", err)
		return fmt.Errorf("error in DiscoveyPKI engine getURLForListPKIEngines : %v", err)
	}
	responseContents, err := common.MakeGetCallAndReturnResponse(url, vaultEnv.getHeaders(), nil)

	if err != nil {
		m1.Lock()
		log.Info("Generating new Token - DiscoverPKIEngines")
		if vaultEnv.TokenUpdatedTime == nil || time.Now().After((*vaultEnv.TokenUpdatedTime).Add(time.Minute)) {
			err = vaultEnv.SetCurrentTokenWithUserNameAndPassword()
			if err != nil {
				m1.Unlock()
				log.Errorf("Error in DiscoveryPKI engine SetCurrentTokenWithUserNameAndPassword : %v", err)
				return fmt.Errorf("error in DiscoveryPKI engine MakeGetCallAndReturnResponse : %v", err)
			}
			currentTime := time.Now()
			vaultEnv.TokenUpdatedTime = &currentTime
		}
		m1.Unlock()
		responseContents, err = common.MakeGetCallAndReturnResponse(url, vaultEnv.getHeaders(), nil)
		if err != nil {
			log.Errorf("Error in DiscoveryPKI engine MakeGetCallAndReturnResponse : %v", err)
			return fmt.Errorf("error in DiscoveryPKI engine MakeGetCallAndReturnResponse : %v", err)
		}
	}

	vaultPKIEnginesResponse := map[string]interface{}{}
	err = json.Unmarshal(responseContents, &vaultPKIEnginesResponse)
	if err != nil {
		log.Errorf("Error in Unmarshalling the response at vaultPKIEnginesResponse %s", err.Error())
		return fmt.Errorf("error in Unmarshalling the response at vaultPKIEnginesResponse %s", err.Error())
	}

	if len(vaultEnv.PKIEngines) <= 0 {
		vaultEnv.PKIEngines = []*PKIEngine{}
	}

	data, ok := vaultPKIEnginesResponse["data"]
	if !ok {
		return fmt.Errorf("Error in getting data from vaultPKIEnginesResponse %s", err.Error())
	}

	dataMapInterface, ok := data.(map[string]interface{})
	if !ok {
		return fmt.Errorf("Error in converting the map to map[string]interface{} %s", err.Error())
	}

	// for name, vaultPKIEngine := range vaultPKIEnginesResponse {
	for name, vaultPKIEngine := range dataMapInterface {
		engineMap, ok := vaultPKIEngine.(map[string]interface{})
		if !ok {
			continue
		}
		if engineType, ok := engineMap["type"]; ok && fmt.Sprintf("%s", engineType) == "pki" {
			pkiEngine := PKIEngine{}
			pkiEngine.Name = strings.Trim(name, "/")
			pkiEngine.ListPath = "certs"
			pkiEngine.GetPath = "cert"
			vaultEnv.PKIEngines = append(vaultEnv.PKIEngines, &pkiEngine)
		}
	}

	hashiCorpVaultEnvContents, err := json.Marshal(vaultEnv)
	if err != nil {
		log.Errorf("Error in Marshalling the vault : %v", err)
	}
	log.Tracef("After autoDiscoverPKIEngines hashiCorpVaultEnv : %s", string(hashiCorpVaultEnvContents))

	return nil
}

//ListCertificates method to get the list of certificates available in the vault
func (vaultEnv *HashicorpVaultEnv) ListCertificates() (output []string, err error) {
	log.Debug("Starting ListCertificates")

	defer func() {
		if r := recover(); r != nil {
			log.Errorf("Recovered from Panic ListCertificates : %v", r)
			err = fmt.Errorf("recovered from panic ListCertificates : %v", r)
		}
	}()

	url, err := vaultEnv.getURLForListCertificates()
	if err != nil {
		return nil, err
	}
	log.Tracef("url : %s", url)
	responseContents, err := common.MakeGetCallAndReturnResponse(url, vaultEnv.getHeaders(), vaultEnv.getQueryParamsForList())

	if err != nil {
		m2.Lock()
		log.Info("Generating new Token - ListCertificates")
		if vaultEnv.TokenUpdatedTime == nil || time.Now().After((*vaultEnv.TokenUpdatedTime).Add(time.Minute)) {
			err = vaultEnv.SetCurrentTokenWithUserNameAndPassword()
			if err != nil {
				m2.Unlock()
				log.Errorf("Error in List Certificates SetCurrentTokenWithUserNameAndPassword : %v", err)
				return nil, fmt.Errorf("error in  List Certificates MakeGetCallAndReturnResponse : %v", err)
			}
			currentTime := time.Now()
			vaultEnv.TokenUpdatedTime = &currentTime
		}
		m2.Unlock()
		responseContents, err = common.MakeGetCallAndReturnResponse(url, vaultEnv.getHeaders(), vaultEnv.getQueryParamsForList())
		if err != nil {
			log.Errorf("Error in List Certificates : %v : %s", err, string(responseContents))
			return nil, fmt.Errorf("error in  List Certificates MakeGetCallAndReturnResponse : %v", err)
		}
	}

	vaultCertListResponse := VaultCertListResponse{}
	err = json.Unmarshal(responseContents, &vaultCertListResponse)
	if err != nil {
		log.Error("Error in Unmarshalling the response at List Certificates ", err.Error())
		return nil, errors.Wrap(err, "Error in Unmarshalling the response at List Certificates ")
	}
	log.Debug("List of Certificate Common Names : ")
	for _, commonName := range vaultCertListResponse.Data.Keys {
		output = append(output, commonName)
	}
	log.Info("Number of Certificates In Vault: ", len(output))
	log.Debug("Finished ListCertificates")
	return
}

//GetCertificate method to get the given certificate
func (vaultEnv *HashicorpVaultEnv) GetCertificate(certificateName string) (output string, err error) {
	log.Debug("Starting GetCertificate : ", certificateName)

	defer func() {
		if r := recover(); r != nil {
			log.Errorf("Recovered from Panic GetCertificate : %v", r)
			err = fmt.Errorf("recovered from panic getcertificate : %v", r)
		}
	}()

	url, err := vaultEnv.getURLForGetCertificate()
	if err != nil {
		return "", err
	}
	url += ("/" + certificateName)

	responseContents, err := common.MakeGetCallAndReturnResponse(url, vaultEnv.getHeaders(), vaultEnv.RequestQuery)
	if err != nil {
		m3.Lock()
		log.Info("Generating new Token - GetCertificate")
		if vaultEnv.TokenUpdatedTime == nil || time.Now().After((*vaultEnv.TokenUpdatedTime).Add(time.Minute)) {
			err = vaultEnv.SetCurrentTokenWithUserNameAndPassword()
			if err != nil {
				m3.Unlock()
				log.Errorf("Error in Get Certificate SetCurrentTokenWithUserNameAndPassword : %v", err)
				return "", fmt.Errorf("error in get certificate setCurrentTokenWithUserNameAndPassword : %v", err)
			}
			currentTime := time.Now()
			vaultEnv.TokenUpdatedTime = &currentTime
		}
		m3.Unlock()
		responseContents, err = common.MakeGetCallAndReturnResponse(url, vaultEnv.getHeaders(), vaultEnv.RequestQuery)
		if err != nil {
			log.Errorf("Error in Get Certificate : %v : %s", err, string(responseContents))
			return "", fmt.Errorf("error in Get Certificate : MakeGetCallAndReturnResponse : %v", err)
		}
	}

	vaultGetCertificateResponse := VaultGetCertificateResponse{}
	err = json.Unmarshal(responseContents, &vaultGetCertificateResponse)
	if err != nil {
		log.Println("Error in Unmarshalling the response at the Get Certificate ", err.Error())
		return "", errors.Wrap(err, "Error in Unmarshalling the response at the Get Certificate")
	}
	output = vaultGetCertificateResponse.Data.Certificate
	log.Debug("Finished GetCertificate")
	return
}

func (vaultEnv *HashicorpVaultEnv) getURLForListPKIEngines() (output string, err error) {
	output, err = vaultEnv.getURL()
	if err != nil {
		return "", err
	}
	output += "/v1/sys/mounts"
	return
}

func (vaultEnv *HashicorpVaultEnv) getURLForListCertificates() (output string, err error) {
	output, err = vaultEnv.getURL()
	if err != nil {
		return "", err
	}
	output += ("/v1/" + *vaultEnv.RequestPathListCertificates)
	return
}

func (vaultEnv *HashicorpVaultEnv) getURLForGetCertificate() (output string, err error) {
	output, err = vaultEnv.getURL()
	if err != nil {
		return "", err
	}
	output += ("/v1/" + *vaultEnv.RequestPathGetCertificates)
	return output, nil
}

func (vaultEnv HashicorpVaultEnv) getURLForGetTokenWithUserNameAndPassword(vault *Vault) (string, error) {
	output, err := vaultEnv.getURL()
	if err != nil {
		return "", err
	}
	output += "/v1/auth/" + vault.AuthPath + "/login/" + vault.UserName
	return output, err
}

func (vaultEnv HashicorpVaultEnv) getURL() (output string, err error) {
	if vaultEnv.Host == "" || vaultEnv.Port == 0 {
		log.Println("Config Validation Failed ")
		log.Println("vault.Host : ", vaultEnv.Host)
		log.Println("vault.Port : ", vaultEnv.Port)
		return "", errors.New(
			"Error in Config - Vault -" +
				" vault.Host : " + vaultEnv.Host +
				" vault.Port : " + fmt.Sprintf("%d", vaultEnv.Port) +
				"vault.RequestPathListCertificates : " + *vaultEnv.RequestPathListCertificates +
				"vault.RequestPathGetCertificates : " + *vaultEnv.RequestPathGetCertificates)
	}

	if vaultEnv.IsHTTPS {
		output += "https://"
	} else {
		output += "http://"
	}
	output += (vaultEnv.Host + ":")
	output += fmt.Sprintf("%d", vaultEnv.Port)
	return
}

func (vaultEnv *HashicorpVaultEnv) getQueryParamsForList() (output map[string]string) {
	output = make(map[string]string)
	for key, value := range vaultEnv.RequestQuery {
		output[key] = value
	}
	output["list"] = "true"
	return
}

func (vaultEnv *HashicorpVaultEnv) getHeaders() (output map[string]string) {
	output = make(map[string]string)
	output["X-Vault-Token"] = *vaultEnv.VaultToken
	if *vaultEnv.CurrentNamespace != "" {
		output["X-Vault-Namespace"] = *vaultEnv.CurrentNamespace
	}
	return
}

func (vaultEnv *HashicorpVaultEnv) GetCurrentTokenWithUserNameAndPassword() (string, error) {
	url, err := vaultEnv.getURLForGetTokenWithUserNameAndPassword(vaultEnv.CurrentVault)
	if err != nil {
		log.Error("Error in GetCurrentTokenWithUserNameAndPassword - getURLForGetTokenWithUserNameAndPassword ", err)
		return "", err
	}

	password, err := ldb.GetStringWithDecryption(ldb.GetVaultNameForPassword(vaultEnv.CurrentVaultNumer))
	if err != nil {
		log.Error("GetCurrentTokenWithUserNameAndPassword - Error in getting the password for vault number ", vaultEnv.CurrentVaultNumer)
		return "", err
	}

	var headers map[string]string

	if !vaultEnv.UseRootToken {
		headers = make(map[string]string)
		headers["X-Vault-Namespace"] = *vaultEnv.CurrentNamespace
	}

	payload := map[string]string{}
	payload["password"] = password

	output, err := common.MakePostCallAndReturnResponse(url, payload, headers, nil)
	if err != nil {
		log.Error("GetCurrentTokenWithUserNameAndPassword - Error in Making Post call ", err)
		return "", err
	}

	responseForToken := &ResponseForToken{}
	err = json.Unmarshal(output, responseForToken)
	if err != nil {
		log.Error("GetCurrentTokenWithUserNameAndPassword - Error in Unmarshal ", err)
		return "", err
	}

	return responseForToken.Auth.ClientToken, nil
}

//SetCurrentTokenWithUserNameAndPassword - applicable only for username based uathentication
func (hashiCorpVaultEnv *HashicorpVaultEnv) SetCurrentTokenWithUserNameAndPassword() error {
	log.Info("Running SetCurrentTokenWithUserNameAndPassword")
	if hashiCorpVaultEnv.CurrentVault.IsUserNameBasedAuthentication {
		token, err := hashiCorpVaultEnv.GetCurrentTokenWithUserNameAndPassword()
		if err != nil {
			log.Errorf("Error in getting the currentToken Using userName and password")
			return fmt.Errorf("error in getting the currentToken using username and password")

		}
		ldb.PutByStringWithEncryption(ldb.GetVaultNameForToken(hashiCorpVaultEnv.CurrentVaultNumer), token)
	} else {
		return fmt.Errorf("SetCurrentTokenWithUserNameAndPassword - Not a user based authentication")
	}

	vaultToken, err := ldb.GetVaultToken(hashiCorpVaultEnv.CurrentVaultNumer)
	if err != nil {
		log.Errorf("Error in getting the PKIEnvines : %v", err)
		return fmt.Errorf("error in getting the PKIEnvines : %v", err)
	}

	// SetValueFromVault(hashiCorpVaultEnv, hashiCorpVaultEnv.CurrentVault, vaultToken, hashiCorpVaultEnv.CurrentVaultNumer)
	hashiCorpVaultEnv.VaultToken = &vaultToken
	hashiCorpVaultEnv.CurrentVault.VaultToken = &vaultToken

	return nil

}

func SetValueFromVault(hashiCorpVaultEnv *HashicorpVaultEnv, vault *Vault, vaultToken string, vaultNumber int) {
	hashiCorpVaultEnv.IsHTTPS = vault.IsHTTPS
	hashiCorpVaultEnv.Host = vault.Host
	hashiCorpVaultEnv.Port = vault.Port
	hashiCorpVaultEnv.PKIEngines = vault.PKIEngines
	hashiCorpVaultEnv.AutoDiscoverPKIEngines = vault.AutoDiscoverPKIEngines
	hashiCorpVaultEnv.VaultToken = &vaultToken
	hashiCorpVaultEnv.RequestPathListCertificates = vault.RequestPathListCertificates
	hashiCorpVaultEnv.RequestPathGetCertificates = vault.RequestPathGetCertificates
	hashiCorpVaultEnv.RequestQuery = vault.RequestQuery
	hashiCorpVaultEnv.CurrentVaultNumer = vaultNumber
	hashiCorpVaultEnv.CurrentVault = vault
	hashiCorpVaultEnv.UseRootToken = vault.UseRootToken
}

func AutoDiscoverPKIEngines(vault *HashicorpVaultEnv) error {
	if !vault.AutoDiscoverPKIEngines {
		return nil
	}
	return vault.DiscoverPKIEngines()
}
