package cli

import (
	"strings"
	"testing"
)

// `export` prints every value in the clear, so it is guarded like `get`: an
// agent's shell is a pipe, and a pipe leads to the transcript.
func TestExportRefusesAPipeWithoutForce(t *testing.T) {
	h := newHarness(t)
	h.mustRun("the-value", "add", "TOKEN")

	code, stdout, stderr := h.run("", "export", "TOKEN")
	if code == 0 {
		t.Fatalf("export printed to a pipe: %s", stdout)
	}
	if strings.Contains(stdout+stderr, "the-value") {
		t.Error("the refusal itself leaked the value")
	}
	if !strings.Contains(stderr, "--force") || !strings.Contains(stderr, "env") {
		t.Errorf("refusal %q does not offer --force or point at env", stderr)
	}
}

// Unquoted, in declaration order: the format `docker run --env-file` reads,
// where everything after the first = is the value.
func TestExportPrintsEveryVariableAsKeyValue(t *testing.T) {
	h := newHarness(t)
	h.mustRun(`a=b$c 'd'`, "add", "cdp-es",
		"--var", "ES_ENDPOINT=https://logs.internal:9200", "--secret", "ES_API_KEY")

	got := h.mustRun("", "export", "cdp-es", "--force")
	want := "ES_ENDPOINT=https://logs.internal:9200\nES_API_KEY=a=b$c 'd'\n"
	if got != want {
		t.Errorf("export = %q, want %q", got, want)
	}

	if log := h.mustRun("", "audit"); !strings.Contains(log, "export") {
		t.Errorf("audit does not record the export: %s", log)
	}
}

// A line break would end the value early and start a line of the attacker's
// choosing, e.g. one that sets LD_PRELOAD.
func TestExportRefusesALineBreakInAValue(t *testing.T) {
	for label, value := range map[string]string{
		"newline":         "x\nLD_PRELOAD=/tmp/evil.so",
		"carriage return": "x\rLD_PRELOAD=/tmp/evil.so",
	} {
		t.Run(label, func(t *testing.T) {
			h := newHarness(t)
			h.mustRun("public", "add", "pair", "--var", "FIRST=ok", "--secret", "KEY")
			h.mustRun(value, "edit", "pair", "--set", "KEY")

			code, stdout, stderr := h.run("", "export", "pair", "--force")
			if code == 0 {
				t.Fatalf("export emitted a value with a line break: %q", stdout)
			}
			if stdout != "" {
				t.Errorf("export wrote %q before refusing; a partial file is still a file", stdout)
			}
			if !strings.Contains(stderr, "KEY") {
				t.Errorf("error %q does not name the variable", stderr)
			}
			if strings.Contains(stderr, "evil") {
				t.Errorf("error %q leaked the value", stderr)
			}
		})
	}
}
