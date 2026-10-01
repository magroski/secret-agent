package cli

import (
	"flag"
	"fmt"
	"strings"

	"github.com/magroski/secret-agent/internal/audit"
	"github.com/magroski/secret-agent/internal/vault"
)

// lineBreaks end a KEY=VALUE line wherever they appear in a value.
const lineBreaks = "\r\n"

// cmdExport prints a credential as unquoted KEY=VALUE lines, for tools that read
// env files rather than a shell:
//
//	sa-vault export pg-ro --force > .env
//	docker run --env-file <(sa-vault export pg-ro --force) app
func cmdExport(env Env, args []string) error {
	fs := flag.NewFlagSet("export", flag.ContinueOnError)
	fs.SetOutput(env.Stderr)
	force := fs.Bool("force", false,
		"print even when output is not a terminal (the values land in whatever captured it)")

	positional, err := parseFlags(fs, args)
	if err != nil {
		return err
	}
	if len(positional) != 1 {
		return fmt.Errorf("usage: %s export <name> [--force]", Bin)
	}

	// Every value in the clear: guarded like `get`, for the same reason.
	if !stdoutIsTerminal(env) && !*force {
		return fmt.Errorf("refusing to print credentials to something that is not a terminal.\n"+
			"To write an env file, pass --force.\n"+
			"To give the values to a command, use `%s env` instead — it exports the variables\n"+
			"without the values passing through your terminal or your transcript", Bin)
	}

	v, err := openVault()
	if err != nil {
		return err
	}
	bindings, err := resolveBindings(v, positional, nil, "")
	if err != nil {
		return err
	}

	// Built whole before writing, so a refusal never leaves half a file behind.
	var out strings.Builder
	for _, b := range bindings {
		if err := vault.ValidateVarName(b.Name); err != nil {
			return err
		}
		// A line break would end the value and start a line of its own choosing:
		// "x\nLD_PRELOAD=/tmp/evil.so" sets two variables.
		if strings.ContainsAny(b.Value, lineBreaks) {
			return fmt.Errorf("%s.%s contains a line break, which KEY=VALUE cannot carry; "+
				"load it with `%s env %s` instead", b.Entry, b.Var, Bin, b.Entry)
		}
		fmt.Fprintf(&out, "%s=%s\n", b.Name, b.Value)
	}
	fmt.Fprint(env.Stdout, out.String())

	audit.New(v.Dir()).Log(audit.Event{
		Tool: "export", Secret: positional[0], Field: strings.Join(exportedNames(bindings), ","),
		Decision: audit.Allowed,
	})
	return nil
}
