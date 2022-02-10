package common

import "testing"

func TestGetHome(t *testing.T) {
	tt := []struct {
		name           string
		configBasePath string
		checkNonEmpty  bool
		expectedOutput string
	}{
		{"empty-configBasePath", "", true, ""},
		{"nonempty-configBasePath", "test", false, "test"},
	}

	for _, test := range tt {
		output := GetHome(test.configBasePath)
		if test.checkNonEmpty && output == "" {
			t.Fatalf("%s failed", test.name)
		} else if !test.checkNonEmpty && test.expectedOutput != output {
			t.Fatalf("%s Failed Exepcted : %s, Received : %s", test.name, test.expectedOutput, output)
		}
	}
}
