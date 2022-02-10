package vault

import (
	"log"
	"testing"
)

func TestGetURLForListPKIEngines(t *testing.T) {
	vaultEnv := &HashicorpVaultEnv{Host: "localhost", Port: 100}
	url, err := vaultEnv.getURLForListPKIEngines()
	if err != nil {
		t.Fatalf("Error in getting the URL for List PKI Engines %v", err)
	}
	if url != "http://localhost:100/v1/sys/mounts" {
		t.Fatalf("Error in URL GetURLForListPKIEngines")
	}
}

func TestGetURLForListCertificates(t *testing.T) {
	list := "list"
	vaultEnv := &HashicorpVaultEnv{Host: "localhost", Port: 100, RequestPathListCertificates: &list}
	url, err := vaultEnv.getURLForListCertificates()
	if err != nil {
		t.Fatalf("Error in getting the URL for list Certificates %v", err)
	}
	if url != "http://localhost:100/v1/list" {
		log.Fatalf("Error in URL GetURLForListCertificates")
	}
}

func TestGetURLForGetCertificates(t *testing.T) {
	get := "get"
	vaultEnv := &HashicorpVaultEnv{Host: "localhost", Port: 100, RequestPathGetCertificates: &get}
	url, err := vaultEnv.getURLForGetCertificate()
	if err != nil {
		t.Fatalf("Error in getting the URL for list Certificates %v", err)
	}
	if url != "http://localhost:100/v1/get" {
		log.Fatalf("Error in URL GetURLForListCertificates")
	}
}

func TestGetURLForGetTokenWithUserNameAndPassword(t *testing.T) {
	get := "get"
	vaultEnv := HashicorpVaultEnv{Host: "localhost", Port: 100, RequestPathGetCertificates: &get}
	vault := &Vault{AuthPath: "auth", UserName: "username"}
	url, err := vaultEnv.getURLForGetTokenWithUserNameAndPassword(vault)
	if err != nil {
		t.Fatalf("Error in getting the URL for list Certificates %v", err)
	}
	if url != "http://localhost:100/v1/auth/auth/login/username" {
		log.Fatalf("Error in URL GetURLForListCertificates")
	}
}

func TestGetURL(t *testing.T) {

	tt := []struct {
		name        string
		vaultEnv    HashicorpVaultEnv
		expectedURL string
	}{
		{
			"withHttps",
			HashicorpVaultEnv{
				Host:    "localhost",
				Port:    100,
				IsHTTPS: true,
			},
			"https://localhost:100",
		},

		{
			"withHttps",
			HashicorpVaultEnv{
				Host:    "localhost",
				Port:    100,
				IsHTTPS: false,
			},
			"http://localhost:100",
		},
	}

	for _, test := range tt {
		url, err := test.vaultEnv.getURL()
		if err != nil {
			t.Fatalf("%s Error in getting URL TestGetURL : ", test.name)
		}
		if url != test.expectedURL {
			t.Fatalf("%s Error in the received URL : received : %s, expected : %s", test.name, url, test.expectedURL)
		}
	}

}

func TestGetQueryParamsForList(t *testing.T) {
	//Default
	vaultEnv := HashicorpVaultEnv{}
	params := vaultEnv.getQueryParamsForList()
	value, ok := params["list"]
	if ok {
		if value != "true" {
			log.Fatalf("Error in getting the value for list GetQueryParamsForList")
		}
	} else {
		log.Fatalf("Error in getting the value for list GetQueryParamsForList")
	}

	//RequestQuery
	vaultEnv.RequestQuery = map[string]string{"key": "value"}
	params = vaultEnv.getQueryParamsForList()
	value, ok = params["key"]
	if ok {
		if value != "value" {
			log.Fatalf("Error in getting the value for list GetQueryParamsForList - key")
		}
	} else {
		log.Fatalf("Error in getting the value for list GetQueryParamsForList key")
	}
}

func TestGetHeaders(t *testing.T) {
	vaultEnv := HashicorpVaultEnv{}

	currentNamespace := "namespace"
	vaultEnv.CurrentNamespace = &currentNamespace

	token := "testtoken"
	vaultEnv.VaultToken = &token

	headers := vaultEnv.getHeaders()
	value, ok := headers["X-Vault-Token"]
	if !ok {
		t.Fatalf("Error in get headers ")
	}
	if value != "testtoken" {
		t.Fatalf("Token doesn't match")
	}
}
