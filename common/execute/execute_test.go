package execute

import "testing"

func TestGetMaskedCommand(t *testing.T) {
	tt := []struct {
		name           string
		input          string
		expectedOutput string
	}{
		{"pass-type", "pass:test", "******"},
		{"-P-type", "-P:test", "*******"},
	}

	for _, test := range tt {
		output := getMaskedCommand(test.input)
		if output != test.expectedOutput {
			t.Fatalf("%s Error in getting the masked command expected : %s, received : %s", test.name, test.expectedOutput, output)
		}
	}
}
