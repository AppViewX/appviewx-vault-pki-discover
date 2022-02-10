package main

import (
	"fmt"
	"log"
	"testing"
)

func TestGetGroupName(t *testing.T) {
	groupName := getGroupName("1", "namespace", "pkiengine")
	if groupName != fmt.Sprintf("vault_%s_%s_%s", "1", "namespace", "pkiengine") {
		log.Fatalf("Error in getting the group name")
	}
}
