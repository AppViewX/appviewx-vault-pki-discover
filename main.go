//This Utility is to discover the certificates from the vault and upload to appviewx
package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"sync/atomic"
	"syscall"
	"time"
	"vault_util/appviewx"
	"vault_util/common"
	"vault_util/config"
	"vault_util/vault"

	"sync"

	"vault_util/ldb"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh/terminal"
)

const (
	VERSION = "v1.2 20211208"
)

var configFileNameFlag string
var vaultCertificateField string
var logLevel string
var logOutput string
var concurrentNumber int
var gitCommit string

func main() {

	formatter := log.TextFormatter{
		FullTimestamp: true,
	}
	log.SetFormatter(&formatter)

	//Setting the Logoutput by default to File
	logOutput = "file"

	var versionCmd = getVersionCommand()
	var discoveryCmd = getDiscoveryCommand()
	var listCommand = getListcommand()
	var resetCommand = getResetLocalCacheCommand()
	var install = getInstallCommand()
	var resetAppViewXPassword = resetAppViewXPasswordCommand()
	var resetVaultToken = resetVaultTokensCommand()
	var resetVaultPassword = resetVaultPasswordsCommand()

	var rootCmd = &cobra.Command{Use: "appviewx_vault_util"}
	rootCmd.AddCommand(versionCmd)
	rootCmd.AddCommand(discoveryCmd)
	rootCmd.AddCommand(listCommand)
	rootCmd.AddCommand(resetCommand)
	rootCmd.AddCommand(install)
	rootCmd.AddCommand(resetAppViewXPassword)
	rootCmd.AddCommand(resetVaultToken)
	rootCmd.AddCommand(resetVaultPassword)

	rootCmd.PersistentFlags().StringVarP(&logLevel, "log", "l", "info", "fatal error warn info debug trace - levels of logging  ")
	rootCmd.PersistentFlags().StringVarP(&configFileNameFlag, "config_file", "c", "./"+common.CONFIG_FILE_NAME, `Config file name with path  ( default "./`+common.CONFIG_FILE_NAME+`")
	
	Example1 : 
	{
		"appviewx_is_https": true,
		"appviewx_host": "<appviewx_host_name>",
		"appviewx_port": <appviewx_api_port>,
		"appviewx_username": "USER_NAME",		
		"vault_is_https": false,
		"vault_host": "<vault_host_name>",
		"vault_api_port": <vault_api_port>,
		"installation_path":"/tmp/test",
		"pki_engines":[
			{
				"name":"pki-1",
				"list_path":"certs",
				"get_path":"cert"
			},
			{
				"name":"appviewx-pki",
				"list_path":"certs",
				"get_path":"certs",
				"request_query":{
					"config":"appviewx_138"
				}
			}
		],
		"auto_discover_pki_engines":true,
		"vault_token": "s.tw7K2mSU3fgYMki8MOPDQDH0"
	}

	Example2 : 
	{
		"appviewx_is_https": true,
		"appviewx_host": "192.168.142.132",
		"appviewx_port": 5300,
		"appviewx_username": "USER_NAME",
		"installation_path":"",
		"upload_token_time_period_in_minutes":1,
		"number_of_allowed_uploads_in_token_time_period":1000,
		"vaults":[
			{
				"vault_is_https": false,
				"vault_host": "127.0.0.1",
				"vault_api_port": 5920,
				"pki_engines":[ ],
				"auto_discover_pki_engines":true,
				"is_username_based_authentication":true,
				"auth_path":"userpass",
				"user_name":"test",
				"list_of_namespaces":["namespace1","namespace2"]
			}
		],
		"log_rotation_file_count":5,
		"db_purge_dates":[24],
		"max_allowed_time_to_run_in_minutes":60,
		"concurrent_uploads_allowed":5
	}
	
`)

	discoveryCmd.Flags().StringVarP(&vaultCertificateField, "vault_certificate_field", "f", "certificate", `field name of certificate in get certificate resonse from vault`)
	install.Flags().StringVarP(&vaultCertificateField, "vault_certificate_field", "f", "certificate", `field name of certificate in get certificate resonse from vault - 
will be used during installation`)
	rootCmd.Execute()
}

func getVersionCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "version Display the version of this tool",
		Short: "version Display the version of this tool",
		Long:  "version Display the version of this tool",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println(VERSION)
			fmt.Printf("git commit hash : %s \n", gitCommit)
		},
	}
}

func getDiscoveryCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "discover Certificate From the Vault and upload to AppViewX ( Uploaded Certificate details will be cached to skip in future )",
		Short: "Discover Certificate From the Vault and upload to AppViewX ( Uploaded Certificate details will be cached to skip in future )",
		Long:  "Discover the certificates from the configured vault and upload to AppViewX ( Uploaded Certificate details will be cached to skip in future )",
		Run:   carryoutDiscovery,
	}
}

func getListcommand() *cobra.Command {
	return &cobra.Command{
		Use:   "list_from_vault lists the certificates in the vault",
		Short: "Lists the certificates in the vault based on the path given in " + common.CONFIG_FILE_NAME,
		Long:  "Lists the certificates in the vault based on the path given in " + common.CONFIG_FILE_NAME,
		Run:   displayList,
	}
}

func getResetLocalCacheCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "reset_local_cache resets the local upload details cache, After reset all certificates from vault will be uploaded to AppViewX",
		Short: "Resets the local upload details cache, After reset all certificates from vault will be uploaded to AppViewX",
		Long:  "Resets the local upload details cache, After reset all certificates from vault will be uploaded to AppViewX",
		Run:   resetLocalCache,
	}
}

func getInstallCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "install installs the utility",
		Short: "Install the utility",
		Long:  "Install the utility",
		Run:   install,
	}
}

func resetAppViewXPasswordCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "reset_appviewx_password resets the AppViewX password",
		Short: "reset_appviewx_password resets the AppViewX password",
		Long:  "reset_appviewx_password resets the AppViewX password",
		Run:   resetAppViewXPasswordCobra,
	}
}

func resetVaultTokensCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "reset_vault_token resets the Vault Token",
		Short: "reset_vault_token resets the Vault Token",
		Long:  "reset_vault_token resets the Vault Token",
		Run:   resetVaultTokensCobra,
	}
}

func resetVaultPasswordsCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "reset_vault_password resets the Vault Password",
		Short: "reset_vault_password resets the Vault Password",
		Long:  "reset_vault_password resets the Vault Password",
		Run:   resetVaultPasswordsCobra,
	}
}

func setLogLevel() (err error) {
	if logOutput == "file" {

		logFolderName := filepath.Join(common.GetHome(config.GetInstallationPath(configFileNameFlag)), common.INSTALLATION_DIRECTORY_NAME, common.LOG_FOLDER_NAME)

		if err = os.MkdirAll(logFolderName, 0777); err != nil {
			log.Printf("Error in creating the Log Folder : %s\n", logFolderName)
			return err
		}

		logFile := filepath.Join(logFolderName, common.LOG_FILE_NAME)

		//Ignoring the error from rotateLogFile
		if err = rotateLogFile(logFile); err != nil {
			log.Printf("Error in Rotating Log File : %v\n", err)
			return err
		}

		if err = removeOldLogFiles(); err != nil {
			log.Printf("Error in removeOldLogFiles : %v\n", err)
			return err
		}

		f, errInner := os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)
		log.SetOutput(f)

		if errInner != nil {
			log.Error("Error in opening the Log File : ", err)
			return errInner
		}
	}

	switch logLevel {
	case "fatal":
		log.SetLevel(log.FatalLevel)
	case "error":
		log.SetLevel(log.ErrorLevel)
	case "warn":
		log.SetLevel(log.WarnLevel)
	case "info":
		log.SetLevel(log.InfoLevel)
	case "debug":
		log.SetLevel(log.DebugLevel)
	case "trace":
		log.SetLevel(log.TraceLevel)
	}
	return
}

func removeOldLogFiles() error {

	logFolderName := filepath.Join(common.GetHome(config.GetInstallationPath(configFileNameFlag)), common.INSTALLATION_DIRECTORY_NAME, common.LOG_FOLDER_NAME)
	appViewXEnv, _, err := config.GetEnvironments(configFileNameFlag)
	if err != nil {
		return err
	}

	files, err := ioutil.ReadDir(logFolderName)
	if err != nil {
		log.Error("Error in reading the directory ", err)
		return err
	}

	sort.Slice(files, func(i, j int) bool {
		return files[i].ModTime().After(files[j].ModTime())
	})

	log.Debug(fmt.Sprintf("Number of Files : %d, keepNumbers : %d ", len(files), appViewXEnv.LogRotationFilesCount))

	if len(files) < appViewXEnv.LogRotationFilesCount {
		log.Debug("not purging")
	}

	for i := appViewXEnv.LogRotationFilesCount; i < len(files); i++ {
		log.Println("Removing the Log File : ", files[i].Name())
		err = os.Remove(filepath.Join(logFolderName, files[i].Name()))
		if err != nil {
			log.Error("Error in removing the file ")
			return err
		}
	}
	return nil
}

func rotateLogFile(logFileName string) error {
	fileInfo, err := os.Stat(logFileName)
	if err != nil {
		os.Create(logFileName)
		return nil
	}
	fileSize := fileInfo.Size()
	if fileSize/(1024*1024) >= 10 {
		dt := time.Now()
		newFileName := fmt.Sprintf("%s_%v", logFileName, dt.Format(time.RFC3339))

		err := os.Rename(logFileName, newFileName)
		if err != nil {
			fmt.Printf("Error in Renaming the log file from %s to %s \n", logFileName, newFileName)
			return err
		}
	}
	return nil
}

func install(cmd *cobra.Command, args []string) {
	//ldb.StartDB(config.GetInstallationPath(configFileNameFlag))

	err := setLogLevel()
	if err != nil {
		return
	}

	log.Info("Starting install")
	installationPath := filepath.Join(common.GetHome(config.GetInstallationPath(configFileNameFlag)), common.INSTALLATION_DIRECTORY_NAME)

	log.Info("Installation path ", installationPath)

	err = os.MkdirAll(installationPath, 0777)
	if err != nil {
		log.Error("Error in creating the installation directory : ", err)
		return
	}
	currentWorkingDirectory, err := os.Getwd()
	if err != nil {
		log.Error("Error in creating the current working directory : ", err)
		return
	}
	binaryPath := filepath.Join(currentWorkingDirectory, common.INSTALLATION_DIRECTORY_NAME)
	copyFileToInstallationDirectory(binaryPath, installationPath, common.INSTALLATION_DIRECTORY_NAME)

	// configFile := filepath.Join(currentWorkingDirectory, common.CONFIG_FILE_NAME)
	copyFileToInstallationDirectory(configFileNameFlag, installationPath, common.CONFIG_FILE_NAME)

	// installationPathWithBinary := filepath.Join(installationPath, common.INSTALLATION_DIRECTORY_NAME)
	// subCommandsAndArguments := getSubCommandsAndArguments()
	// cron.PutEntryInCron(installCronString, installationPathWithBinary, subCommandsAndArguments)

	if err := resetPassword(); err != nil {
		log.Errorf("Error in Reset Password : %v", err)
		return
	}

	if err := resetVaultTokens(false); err != nil {
		log.Errorf("Error in resetVaultTokens : %v", err)
		return
	}

	if err := resetVaultPasswords(false); err != nil {
		log.Errorf("Error in resetVaultPasswords : %v", err)
		return
	}

	log.Info("Finished install")
}

func resetVaultTokens(isVaultStartRequired bool) error {
	if isVaultStartRequired {
		ldb.StartDB(config.GetInstallationPath(configFileNameFlag))
	}
	fmt.Println("Enter resetVaultTokens : ")
	_, hashicorpVault, err := config.GetEnvironments(configFileNameFlag)
	if err != nil {
		log.Error("Error in GetEnvironments resetVaultTokens ")
		return err
	}

	for vaultNumber, currentVault := range hashicorpVault.Vaults {
		if currentVault.IsUserNameBasedAuthentication {
			continue
		}

		fmt.Printf("Enter vaultToken for the Vault %d : HostName : %s:%d\n", vaultNumber, currentVault.Host, currentVault.Port)

		fmt.Println("Enter Hashicorp Vault Token : ")
		tokenContents, err := terminal.ReadPassword(int(syscall.Stdin))
		if err != nil {
			log.Error("Error in Reading the Token")
			return err
		}

		err = ldb.PutByStringWithEncryption(ldb.GetVaultNameForToken(vaultNumber), string(tokenContents))
		if err != nil {
			log.Error("Error in PutByStringWithEncryption ", err)
			return err
		}
		fmt.Println("VaultToken updated successfully")
	}
	return nil
}

func resetVaultPasswords(isVaultStartRequired bool) error {
	if isVaultStartRequired {
		ldb.StartDB(config.GetInstallationPath(configFileNameFlag))
	}
	fmt.Println("Enter resetVaultPasswords : ")
	_, hashicorpVault, err := config.GetEnvironments(configFileNameFlag)
	if err != nil {
		log.Error("Error in GetEnvironments resetVaultPasswords ")
		return err
	}

	for vaultNumber, currentVault := range hashicorpVault.Vaults {
		if !currentVault.IsUserNameBasedAuthentication {
			continue
		}

		fmt.Printf("Enter password for the Vault %d : HostName : %s:%d\n", vaultNumber, currentVault.Host, currentVault.Port)

		fmt.Println("Enter Hashicorp Vault Password for UserName : ", currentVault.UserName)
		passwordContents, err := terminal.ReadPassword(int(syscall.Stdin))
		if err != nil {
			log.Error("Error in Reading the Password")
			return err
		}

		err = ldb.PutByStringWithEncryption(ldb.GetVaultNameForPassword(vaultNumber), string(passwordContents))
		if err != nil {
			log.Error("Error in PutByStringWithEncryption ", err)
			return err
		}
		fmt.Println("vault password updated successfully")
	}
	return nil
}

func resetPassword() error {
	ldb.StartDB(config.GetInstallationPath(configFileNameFlag))
	fmt.Println("Enter AppViewX Password : ")
	passwordContents, err := terminal.ReadPassword(int(syscall.Stdin))
	if err != nil {
		log.Error("Error in Reading the password")
		return err
	}

	err = ldb.PutByStringWithEncryption("appviewx_password", string(passwordContents))
	if err != nil {
		log.Error("Error in PutByStringWithEncryption ", err)
		return err
	}
	return nil
}

func resetVaultTokensCobra(cmd *cobra.Command, args []string) {
	log.Info("Starting resetVaultTokensCobra")
	if err := resetVaultTokens(true); err != nil {
		log.Errorf("Error in resetVaultTokenCobra : %v", err)
		return
	}

	log.Info("Finished resetVaultTokensCobra")
}

func resetVaultPasswordsCobra(cmd *cobra.Command, args []string) {
	log.Info("Starting resetVaultPasswordsCobra")
	if err := resetVaultPasswords(true); err != nil {
		log.Errorf("Error in resetVaultPasswordsCobra : %v", err)
		return
	}

	log.Info("Finished resetVaultPasswordsCobra")
}

func resetAppViewXPasswordCobra(cmd *cobra.Command, args []string) {
	log.Info("Starting resetAppviewxPassword")
	if err := resetPassword(); err != nil {
		log.Errorf("Error in Reset Password : %v", err)
		return
	}

	log.Info("Finished resetAppviewxPassword ")
}

func getSubCommandsAndArguments() (output string) {
	output += (" discover ")
	output += (" -f=" + vaultCertificateField + " ")
	output += (` -c="` + filepath.Join(common.GetHome(config.GetInstallationPath(configFileNameFlag)), common.INSTALLATION_DIRECTORY_NAME, common.CONFIG_FILE_NAME) + `" `)
	output += (" -l=" + logLevel)
	output += " -o=file "

	return
}

func copyFileToInstallationDirectory(fileNameWithPath, installationPath, targetFileName string) (err error) {

	log.Debug("Starting copyFileToInstallationDirectory")
	log.Debug("copyFileToInstallationDirectory : filePath : ", fileNameWithPath)
	log.Debug("copyFileToInstallationDirectory : installationPath : ", installationPath)

	binaryContent, err := ioutil.ReadFile(fileNameWithPath)
	if err != nil {
		log.Error("Error in Reading the Binary File from : ", fileNameWithPath, err)
		return
	}

	installationPathWithBinary := filepath.Join(installationPath, targetFileName)
	err = ioutil.WriteFile(installationPathWithBinary, binaryContent, 0777)
	if err != nil {
		log.Error("Error in Writing the Binary File at : ", installationPathWithBinary, err)
		return
	}
	log.Debug("Finished copyFileToInstallationDirectory")
	return
}

func resetLocalCache(cmd *cobra.Command, args []string) {
	log.Info("Starting resetLocalCache")
	ldb.StartDB(config.GetInstallationPath(configFileNameFlag))

	err := setLogLevel()
	if err != nil {
		return
	}

	log.Info("Starting resetLocalCache")

	leveldbFolderPath := filepath.Join(common.GetHome(config.GetInstallationPath(configFileNameFlag)), common.INSTALLATION_DIRECTORY_NAME, common.LEVEL_DB_FOLDER_NAME)
	log.Debug("FolderName for Remove : ", leveldbFolderPath)

	cache, err := getCacheLDB()
	if err != nil {
		log.Error("Error in getting cache : getCacheLDB", err)
		return
	}

	err = os.RemoveAll(leveldbFolderPath)
	log.Info("Finished resetLocalCache")
	if err != nil {
		log.Error("Error while removing the folder : ", leveldbFolderPath, err.Error())

		return
	}

	ldb.StartDB(config.GetInstallationPath(configFileNameFlag))

	for key, value := range cache {
		ldb.PutByStringWithEncryption(key, value)
	}
	log.Info("Finished resetLocalCache")
}

func getCacheLDB() (map[string]string, error) {
	fmt.Println("Starting getCacheLDB")
	cache := map[string]string{}

	//Take appviewx_password
	appviewxPassword, err := ldb.GetStringWithDecryption("appviewx_password")
	if err != nil {
		return nil, err
	}
	cache["appviewx_password"] = appviewxPassword

	//Take vault tokens
	_, hashicorpVault, err := config.GetEnvironments(configFileNameFlag)
	if err != nil {
		log.Error("Error in GetEnvironments resetVaultTokens ")
		return nil, err
	}

	//cache the existing vault tokens
	for vaultNumber, currentVault := range hashicorpVault.Vaults {

		fmt.Printf("getCacheLDB vaultToken for the Vault %d : HostName : %s:%d\n", vaultNumber, currentVault.Host, currentVault.Port)

		vaultToken, err := ldb.GetStringWithDecryption(ldb.GetVaultNameForToken(vaultNumber))
		if err != nil {
			log.Error("Error in PutByStringWithEncryption ", err)
			return nil, err
		}
		cache[ldb.GetVaultNameForToken(vaultNumber)] = vaultToken
	}

	//cache the existing vault passwords
	for vaultNumber, currentVault := range hashicorpVault.Vaults {

		fmt.Printf("getCacheLDB password for the Vault %d : HostName : %s:%d\n", vaultNumber, currentVault.Host, currentVault.Port)

		vaultPassword, err := ldb.GetStringWithDecryption(ldb.GetVaultNameForPassword(vaultNumber))
		if err != nil {
			log.Error("Error in PutByStringWithEncryption ", err)
			return nil, err
		}
		cache[ldb.GetVaultNameForPassword(vaultNumber)] = vaultPassword
	}

	return cache, nil
}

func displayList(cmd *cobra.Command, args []string) {
	ldb.StartDB(config.GetInstallationPath(configFileNameFlag))

	err := setLogLevel()
	if err != nil {
		return
	}
	log.Debug("Starting displayList")

	_, hashiCorpVaultEnv, err := config.GetEnvironments(configFileNameFlag)
	if err != nil {
		log.Printf("Error in getting the environments : %+v\n", err)
		return
	}

	for vaultNumber, currentVault := range hashiCorpVaultEnv.Vaults {
		if len(currentVault.ListOfNamespaces) <= 0 {
			currentVault.ListOfNamespaces = []string{""}
		}
		for _, currentNamespace := range currentVault.ListOfNamespaces {
			vault.SetValueFromVault(hashiCorpVaultEnv, currentVault, "", vaultNumber)
			hashiCorpVaultEnv.CurrentNamespace = &currentNamespace
			log.Info("DisplayList in namespace : ", currentNamespace)

			if currentVault.IsUserNameBasedAuthentication {
				token, err := hashiCorpVaultEnv.GetCurrentTokenWithUserNameAndPassword()
				if err != nil {
					log.Errorf("Error in getting the currentToken Using userName and password")
					continue
				}
				ldb.PutByStringWithEncryption(ldb.GetVaultNameForToken(vaultNumber), token)
			}

			vaultToken, err := ldb.GetVaultToken(vaultNumber)
			if err != nil {
				log.Errorf("Error in getting the PKIEnvines : %v", err)
				return
			}
			vault.SetValueFromVault(hashiCorpVaultEnv, currentVault, vaultToken, vaultNumber)

			log.Infof("Processing Vault Hostname : %s ", currentVault.Host)
			if err = vault.AutoDiscoverPKIEngines(hashiCorpVaultEnv); err != nil {
				log.Errorf("Error in getting the PKIEnvines : %v", err)
				return
			}

			for _, currentPKIEngine := range hashiCorpVaultEnv.PKIEngines {
				log.Infof("Processing Engine : %s", currentPKIEngine.Name)
				//set the currentPKIEngine
				setCurrentPKIEngine(currentPKIEngine, hashiCorpVaultEnv)

				listOfCertificates, err := hashiCorpVaultEnv.ListCertificates()

				for _, currentCertificate := range listOfCertificates {
					fmt.Println(currentCertificate)
				}

				if err != nil {
					log.Printf("Error in getting the certificate list : %+v ", err)
				}
			}
		}
	}
	log.Debug("Finished displayList")
	return
}

func carryoutDiscovery(cmd *cobra.Command, args []string) {

	startDB, err := dbPurge()
	if err != nil {
		log.Error("Error in dbPurge : ", err)
		return
	}
	if startDB {
		ldb.StartDB(config.GetInstallationPath(configFileNameFlag))
	}

	err = setLogLevel()
	if err != nil {
		return
	}
	log.Debug("Starting carryoutDiscovery")

	appViewXEnv, hashiCorpVaultEnv, err := config.GetEnvironments(configFileNameFlag)
	if err != nil {
		log.Errorf("Error in getting the environments : %+v\n", err)
		return
	}
	if appViewXEnv.ConcurrentUploadsAllowed <= 0 {
		concurrentNumber = 3
	} else {
		concurrentNumber = appViewXEnv.ConcurrentUploadsAllowed
	}

	//Kill the process after specified time in AppViewXEnv.MaxAllowedTimeToRunInMinutes
	if appViewXEnv.MaxAllowedTimeToRunInMinutes > 0 {
		go func() {
			timer := time.NewTimer(time.Duration(appViewXEnv.MaxAllowedTimeToRunInMinutes * int(time.Minute)))

			<-timer.C
			log.Info("MaxAllowedTimeToRunInMinutes crossed : exiting the process ", appViewXEnv.MaxAllowedTimeToRunInMinutes, " minute(s)")

			os.Exit(1)
		}()
	}

	for vaultNumber, currentVault := range hashiCorpVaultEnv.Vaults {
		if len(currentVault.ListOfNamespaces) <= 0 {
			currentVault.ListOfNamespaces = []string{""}
		}
		for _, currentNamespace := range currentVault.ListOfNamespaces {
			vault.SetValueFromVault(hashiCorpVaultEnv, currentVault, "", vaultNumber)
			hashiCorpVaultEnv.CurrentNamespace = &currentNamespace
			log.Info("Discovery in namespace : ", currentNamespace)

			if currentVault.IsUserNameBasedAuthentication {
				token, err := hashiCorpVaultEnv.GetCurrentTokenWithUserNameAndPassword()
				if err != nil {
					log.Errorf("Error in getting the currentToken Using userName and password")
					continue
				}
				ldb.PutByStringWithEncryption(ldb.GetVaultNameForToken(vaultNumber), token)
			}
			vaultToken, err := ldb.GetVaultToken(vaultNumber)
			if err != nil {
				log.Errorf("Error in getting the PKIEnvines : %v", err)
				return
			}
			vault.SetValueFromVault(hashiCorpVaultEnv, currentVault, vaultToken, vaultNumber)

			log.Infof("Processing Vault Hostname : %s ", currentVault.Host)
			if err = vault.AutoDiscoverPKIEngines(hashiCorpVaultEnv); err != nil {
				log.Errorf("Error in getting the PKIEnvines : %v", err)
				appViewXEnv.RaiseAlert(err.Error(), true, "")
				continue
			}

			var tokens int32 = 0
			go loadTokens(&tokens, appViewXEnv.UploadTokenTimePeriodInMinutes, appViewXEnv.NumberOfAllowedUploadsInTokenTimePeriod)

			var totalNumberOfUploads int32 = 0
			for _, currentPKIEngine := range hashiCorpVaultEnv.PKIEngines {

				log.Infof("Processing Engine : %s", currentPKIEngine.Name)
				//set the currentPKIEngine
				setCurrentPKIEngine(currentPKIEngine, hashiCorpVaultEnv)

				//Ensure the group exists before upload
				appViewXEnv.CreateGroup(getGroupName(currentVault.Name, *hashiCorpVaultEnv.CurrentNamespace, currentPKIEngine.Name))

				//discover for the currentPKIEngine
				totalNos, uploadedNos := doCertificateDiscovery(appViewXEnv, hashiCorpVaultEnv, &tokens, &totalNumberOfUploads, vaultNumber, currentVault.Name)

				appViewXEnv.RaiseAlert(fmt.Sprintf("Vault HostName : %s, PKI Engine : %s, Total No of Certificates : %d, Uploaded No. of Certificates : %d", currentVault.Host,
					currentPKIEngine.Name, totalNos, uploadedNos), false, currentPKIEngine.Name)
			}
			log.Printf("currentVault.Host : %s, Total Number of Certificates Uploaded : %d\n", currentVault.Host, totalNumberOfUploads)
		}
	}

}

func dbPurge() (startDB bool, err error) {
	log.Info("Checking dbPurge")

	appViewXEnv, _, err := config.GetEnvironments(configFileNameFlag)
	if err != nil {
		log.Errorf("dbPurge Error in getting the environments : %+v\n", err)
		return true, err
	}

	day := time.Now().Day()
	isPresent := false

	for _, currentDay := range appViewXEnv.DBPurgeDays {
		if currentDay == day {
			isPresent = true
			break
		}
	}

	if isPresent {
		log.Info("Starting dbPurge")
		dt := time.Now()

		installationPath := config.GetInstallationPath(configFileNameFlag)
		leveldbFolderPath := filepath.Join(common.GetHome(installationPath), common.INSTALLATION_DIRECTORY_NAME, common.LEVEL_DB_FOLDER_NAME)

		source := leveldbFolderPath
		target := fmt.Sprintf("%s_%v", filepath.Join(common.GetHome(installationPath), common.INSTALLATION_DIRECTORY_NAME, "leveldb_backup", common.LEVEL_DB_FOLDER_NAME), dt.Format(time.RFC3339))
		os.MkdirAll(target, 0777)

		fmt.Println("source : ", leveldbFolderPath)
		fmt.Println("target : ", target)

		cmd := exec.Command("cp", "-r", source, target)

		err = cmd.Run()
		if err != nil {
			log.Error("dbPurge - Error in ", err)
			return true, err
		}
		resetLocalCache(nil, nil)
	} else {
		log.Debug("No Purge : day : ", day, "purgeDays : ", appViewXEnv.DBPurgeDays)
		return true, nil
	}

	log.Info("exit dbPurge")
	return false, nil
}

func loadTokens(tokens *int32, uploadTokenTimePeriodInMinutes, numberOfAllowedUploadsInTokenTimePeriod int32) {
	log.Printf("Running loadTokens with uploadTokenTimePeriodInMinutes : %d, numberOfAllowedUploadsIn5Minutes : %d",
		uploadTokenTimePeriodInMinutes, numberOfAllowedUploadsInTokenTimePeriod)

	atomic.AddInt32(tokens, numberOfAllowedUploadsInTokenTimePeriod)

	log.Printf("Added %d Tokens at  %s", numberOfAllowedUploadsInTokenTimePeriod, time.Now().Format(time.ANSIC))

	for {
		log.Debug("loadTokens Sleep Start : ", time.Minute*time.Duration(uploadTokenTimePeriodInMinutes))
		time.Sleep(time.Minute * time.Duration(uploadTokenTimePeriodInMinutes))
		log.Debug("loadTokens Sleep End ")
		*tokens += numberOfAllowedUploadsInTokenTimePeriod
		log.Debug("Added ", numberOfAllowedUploadsInTokenTimePeriod, " Tokens at", time.Now().Format(time.ANSIC))
	}
}

func setCurrentPKIEngine(pkiEngine *vault.PKIEngine, hashiCorpVaultEnv *vault.HashicorpVaultEnv) {
	hashiCorpVaultEnv.PKIEngineName = pkiEngine.Name

	pathListCertificates := fmt.Sprintf("%s/%s", pkiEngine.Name, pkiEngine.ListPath)
	hashiCorpVaultEnv.RequestPathListCertificates = &pathListCertificates

	pathGetCertificates := fmt.Sprintf("%s/%s", pkiEngine.Name, pkiEngine.GetPath)
	hashiCorpVaultEnv.RequestPathGetCertificates = &pathGetCertificates

	hashiCorpVaultEnv.RequestQuery = pkiEngine.RequestQuery
}

func doCertificateDiscovery(appViewXEnv *appviewx.AppViewXEnv, hashiCorpVaultEnv *vault.HashicorpVaultEnv, tokens *int32, totalNumberOfUploads *int32, vaultNumber int, vaultName string) (int, int32) {
	var numberOfCurrentUpload int32
	certificateList, err := hashiCorpVaultEnv.ListCertificates()
	if err != nil {
		log.Errorf("Error in getting the list of certificates : %+v\n", err)
		return 0, 0
	}

	err = appViewXEnv.Login()
	if err != nil {
		log.Errorf("Error in Logging in to AppViewX : %+v\n", err)
		return 0, 0
	}

	var wg sync.WaitGroup
	chan1 := make(chan int, concurrentNumber)

	log.Infof("Starting Local cache check and upload process : ")
	for i, currentCertificateName := range certificateList {

		status, err := ldb.GetByString(currentCertificateName)
		if err != nil {
			log.Errorf("Error in getting the value from ldb for : %s", currentCertificateName)
			continue
		}
		if status != "" {
			log.Debugf("Skip - Upload Already Done : %s", currentCertificateName)
			continue
		}

		for *tokens < *totalNumberOfUploads {
			log.Debug(fmt.Sprintf("Sleep : 5 : tokens : %d totalNumberOfUploads : %d", *tokens, *totalNumberOfUploads))
			time.Sleep(time.Second * 5)
		}
		chan1 <- 1
		wg.Add(1)
		//TODO: - TO REMOVE
		log.Tracef("currentCertificateName : %s", currentCertificateName)

		go func(i int, currentCertificateName string, chan1 chan int, wg *sync.WaitGroup) {

			receivedCertificate, err := hashiCorpVaultEnv.GetCertificate(currentCertificateName)

			if err != nil {
				<-chan1
				wg.Done()
				log.Errorf("Error in getting the certificate : "+currentCertificateName+" %+v\n", err)
				// continue
			}

			atomic.AddInt32(totalNumberOfUploads, int32(1))

			log.Debugf("%d : Certificate Name : %s", i, currentCertificateName)
			log.Debugf(" Length = %d", len(receivedCertificate))
			if len(currentCertificateName) <= 0 {
				log.Errorf("Error in certificate length is zero %s\n", currentCertificateName)
				// continue
			}

			atomic.AddInt32(&numberOfCurrentUpload, int32(1))
			// numberOfCurrentUpload++

			appViewXEnv.UploadCertificate(getGroupName(vaultName, *hashiCorpVaultEnv.CurrentNamespace, hashiCorpVaultEnv.PKIEngineName),
				currentCertificateName, receivedCertificate, chan1, wg)

		}(i, currentCertificateName, chan1, &wg)
	}
	wg.Wait()
	log.Infof("Finished Local cache check and upload process : %v", time.Now().UnixNano())

	log.Printf("Number of Certificates to be Uploaded : %d\n", numberOfCurrentUpload)
	log.Debug("Finished carryoutDiscovery\n")
	return len(certificateList), numberOfCurrentUpload

}

func display(input interface{}) {
	contents, err := json.Marshal(input)
	if err != nil {
		log.Error("Error in Marshalling : ", err)
		return
	}
	log.Debugf("Contents : %s\n", string(contents))
}

func getGroupName(vaultName, namespaceName, pkiEngineName string) string {
	if namespaceName == "" {
		return pkiEngineName
	}
	return fmt.Sprintf("vault_%s_%s_%s", vaultName, namespaceName, pkiEngineName)
}
