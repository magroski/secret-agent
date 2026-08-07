package cli

import (
	"flag"
	"fmt"
	"strings"

	"github.com/magroski/secret-agent/internal/audit"
	"github.com/magroski/secret-agent/internal/vault"
)

func cmdGet(env Env, args []string) error {
	fs := flag.NewFlagSet("get", flag.ContinueOnError)
	fs.SetOutput(env.Stderr)
	varName := fs.String("var", "", "which variable to print; defaults to the only secret one")
	force := fs.Bool("force", false,
		"print even when output is not a terminal (the value lands in whatever captured it)")

	positional, err := parseFlags(fs, args)
	if err != nil {
		return err
	}
	if len(positional) != 1 {
		return fmt.Errorf("usage: %s get <name> [--var NAME]", Bin)
	}

	// `get` prints a bare value, which is what you want when copying one into a
	// web form and never what you want inside an agent's shell. Requiring a
	// terminal does not make capture impossible — a pty defeats it — but it
	// keeps the value from being piped somewhere by accident, and makes doing so
	// a deliberate act.
	if !stdoutIsTerminal(env) && !*force {
		return fmt.Errorf("refusing to print a credential to something that is not a terminal.\n"+
			"If you meant to pipe it, pass --force.\n"+
			"To give a value to a command, use `%s env` instead — it exports the variable\n"+
			"without the value passing through your terminal or your transcript", Bin)
	}

	v, err := openVault()
	if err != nil {
		return err
	}
	entry, err := mustFind(v, positional[0])
	if err != nil {
		return err
	}

	variable, err := pickVar(entry, *varName)
	if err != nil {
		return err
	}

	value := variable.Value
	if variable.Secret {
		if value, err = v.UnsealVar(entry.Name, variable.Name); err != nil {
			return err
		}
	}

	audit.New(v.Dir()).Log(audit.Event{
		Tool: "get", Secret: entry.Name, Field: variable.Name,
		Decision: audit.Allowed, Reason: "printed at the terminal by the vault owner",
	})

	// The value alone on stdout, so `sa-vault get x --force | pbcopy` behaves.
	fmt.Fprintln(env.Stdout, value)
	return nil
}

// pickVar resolves which variable the caller meant, refusing to guess when an
// entry exports several.
func pickVar(entry *vault.Entry, name string) (vault.Var, error) {
	if name != "" {
		variable, ok := entry.Var(name)
		if !ok {
			return vault.Var{}, fmt.Errorf("%q has no variable %s; it has %s",
				entry.Name, name, strings.Join(entry.VarNames(), ", "))
		}
		return variable, nil
	}

	variable, ok := entry.PrimaryVar()
	if !ok {
		return vault.Var{}, fmt.Errorf("%q exports %s; say which you want with --var",
			entry.Name, strings.Join(entry.VarNames(), ", "))
	}
	return variable, nil
}
