package execute

import (
	"bytes"
	"os"
	"os/exec"
	"regexp"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/pkg/errors"
)

//ExecuteCommandAndGetOutputAsString -method provides execution terminal output for given input
func ExecuteCommandAndGetOutputAsString(commandString string) (output string, err error) {
	if commandString == "" {
		return output, errors.New("commandString is empty")
	}

	command := strings.Split(commandString, " ")
	cmd := exec.Command(command[0], command[1:]...)
	var outputBuffer bytes.Buffer
	cmd.Stdout = &outputBuffer

	cmd.Stderr = os.Stderr
	err = cmd.Run()
	if err != nil {
		return output, errors.Wrap(err, "Error while running the commandString : "+commandString)
	}
	return outputBuffer.String(), nil
}

//GenericCommandLineInvokerSkipError - method to invoke command skipping error
func GenericCommandLineInvokerSkipError(command string, commandName string) {
	commands := strings.Split(command, " ")
	log.Debug("Executing ", commandName)
	cmd := exec.Command(commands[0], commands[1:]...)

	log.Debug("command : ", getMaskedCommand(command))

	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err := cmd.Run()

	if err != nil {
		log.Error("Error in ", commandName, err)
		log.Error("Exiting")
	}
	log.Debug("Finished ", commandName)
}

//GenericCommandLineInvoker - method to invoke the command
func GenericCommandLineInvoker(command string, commandName string) {
	commands := strings.Split(command, " ")
	log.Debug("Executing ", commandName)
	cmd := exec.Command(commands[0], commands[1:]...)

	log.Debug("command : ", getMaskedCommand(command))

	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err := cmd.Run()

	if err != nil {
		log.Error("Error in ", commandName, err)
		log.Error("Exiting")
		os.Exit(1)
	}
	log.Debug("Finished ", commandName)
}

func getMaskedCommand(input string) string {
	var re1 = regexp.MustCompile(`pass:.*`)
	var re2 = regexp.MustCompile(`-P.*`)
	input = re1.ReplaceAllString(input, "******")
	input = re2.ReplaceAllString(input, "*******")

	return input
}

func getMaskedCommandSlice(input []string) []string {
	output := []string{}
	for _, inputElement := range input {
		output = append(output, getMaskedCommand(inputElement))
	}
	return output
}
