package cmd

import "testing"

func TestValidPIIEngineModeRejectsRemovedPythonEngine(t *testing.T) {
	if validPIIEngineMode("openai-pf") {
		t.Fatal("openai-pf must remain unsupported after removing the Python engine")
	}
	for _, mode := range []string{"off", "anonymize", "openai-pf-native"} {
		if !validPIIEngineMode(mode) {
			t.Fatalf("validPIIEngineMode(%q) = false", mode)
		}
	}
}
