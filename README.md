# sa-vault

Give a coding agent the credentials it needs without the values landing in the
transcript.

The agent loads a credential into the environment of the command it is about to
run. The command sees the value; the conversation never does.

```
you    $ sa-vault add cdp-es --var ES_ENDPOINT=https://logs.internal:9200 \
             --secret ES_API_KEY
         ES_API_KEY: ••••••••

agent  $ sa-vault ls
         NAME    VARIABLES                DESCRIPTION
         cdp-es  ES_ENDPOINT ES_API_KEY*  candidate ES cluster (read-only)

agent  $ sa-vault exec cdp-es -- python3 report.py
         sa-vault: exported ES_ENDPOINT, ES_API_KEY
         42 candidates matched.

       the answer is in the transcript. the API key never was.
```

Works as a plugin for both **Claude Code** and **Codex CLI** from the same repo,
and works just as well with no plugin at all — it is a normal command-line tool.

## Why

The usual ways to hand an agent a credential are all bad: paste it in the
prompt, drop it in a `.env` the agent reads, or let it find your `~/.pgpass`.
All of them write plaintext into `~/.claude/projects/**/*.jsonl` or
`~/.codex/sessions/` — files that are permanent, greppable, and whose contents
were sent to a model provider.

`sa-vault env` makes the convenient path the safe one. The agent gets a working
environment in one line, and never has a reason to look at the value.

## Install

**1. The binary.** On macOS, download the release — a universal build that runs
on both Apple Silicon and Intel, with no Go toolchain needed. It is a credential
store, so check the sum rather than piping a download straight into a shell:

```bash
cd "$(mktemp -d)"
base=https://github.com/magroski/secret-agent/releases/latest/download
curl -fsSLO "$base/sa-vault_darwin_universal.tar.gz"
curl -fsSLO "$base/checksums.txt"
shasum -a 256 -c checksums.txt      # sa-vault_darwin_universal.tar.gz: OK
tar -xzf sa-vault_darwin_universal.tar.gz
sudo mv sa-vault /usr/local/bin/
```

From source instead — any platform, needs Go 1.26 or newer and
`$(go env GOPATH)/bin` on your `PATH`:

```bash
go install github.com/magroski/secret-agent/cmd/sa-vault@latest
```

Then create the vault:

```bash
sa-vault init
```

`init` creates `~/.sa-vault` and the master key. On macOS that key is a Keychain
item; elsewhere, set `SA_VAULT_PASSPHRASE` or `SA_VAULT_KEK_FILE` first — see
[Where things live](#where-things-live). `sa-vault doctor` confirms what it
found.

The release binary is ad-hoc signed, not notarized. Downloading it with `curl`
as above sets no quarantine flag and it just runs; if you fetch it through a
browser instead, macOS will refuse it until you clear that flag with
`xattr -d com.apple.quarantine sa-vault`. Because the Keychain grants silent
access per-binary, macOS also prompts once after you replace `sa-vault` with a
new build — choose *Always Allow*, or avoid it entirely with
`SA_VAULT_KEK_FILE`.

**2. The agent instructions.** Both plugins ship the same skill, which teaches
the agent the `eval "$(sa-vault env …)"` pattern so it stops asking you to paste
credentials. Install whichever agents you use — the binary above is a
prerequisite for both, and neither plugin carries it.

```bash
# Claude Code
claude plugin marketplace add magroski/secret-agent
claude plugin install sa-vault@secret-agent

# Codex CLI
codex plugin marketplace add magroski/secret-agent
codex plugin add sa-vault@secret-agent
```

Inside a running Claude Code session, the same thing without leaving the REPL:

```
/plugin marketplace add magroski/secret-agent
/plugin install sa-vault@secret-agent
```

Restart the agent afterwards, then confirm the skill is loaded:

```bash
claude plugin details sa-vault    # Skills (1)  using-secrets
codex plugin list                 # sa-vault@secret-agent  installed, enabled
```

**3. Optional — make every value-printing path deliberate.** Claude Code
permission rules can stop an agent from printing values unprompted. In
`~/.claude/settings.json`, or per-project in `.claude/settings.json`:

```json
{
  "permissions": {
    "ask": ["Bash(sa-vault env:*)", "Bash(sa-vault get:*)", "Bash(sa-vault export:*)"]
  }
}
```

Neither `env` nor `exec` belongs in `allow`: run without `eval`, `env` prints
every value into the transcript, and a prefix rule for `exec` approves whatever
it wraps — `sa-vault exec pg-ro -- env` included. Left unlisted, `exec` prompts
with the full command, which is the check you want.

## Storing credentials

A credential is a **named bundle of environment variables**. Each variable is
either sealed or public — public ones are things like an endpoint URL, which
belong with the key but are not themselves secret.

```bash
# One secret, named after the variable it sets
sa-vault add STRIPE_SECRET_KEY

# A bundle: the endpoint travels with the key that opens it
sa-vault add cdp-es --secret ES_API_KEY \
  --var ES_ENDPOINT=https://logs.internal:9200 \
  --describe "Candidate ES cluster. Read-only." --tags cdp

# A connection string
sa-vault add pg-ro --secret DATABASE_URL --describe "Read-only replica"

# A .env file you already have
sa-vault import .env --as flux --public API_BASE_URL

# Rotate a value
sa-vault edit pg-ro --set DATABASE_URL
```

Values are read from the terminal without being echoed, or from stdin when
piped. They never appear in argv, which every process on this machine can read.

Running `sa-vault add <name>` with no flags asks for the description and the
variables one at a time.

## Using them

```bash
sa-vault exec cdp-es -- python3 report.py
```

`exec` runs the command with everything the credential declares in its
environment, minus `SA_VAULT_PASSPHRASE`. sa-vault itself prints nothing but the
names it loaded, to stderr, so the agent gets confirmation without the values.
To place a single value under a name of your choosing:

```bash
sa-vault exec --set DATABASE_URL=pg-ro -- ./migrate     # the entry's only secret
sa-vault exec --set ES_KEY=cdp-es.ES_API_KEY -- ./sync  # one variable of a bundle
sa-vault exec --tag cdp -- python3 report.py            # everything tagged cdp
```

No shell sits between `exec` and the command, so `$VAR` on the command line is
expanded by your shell before anything is loaded. To pass a value as an
argument, let a shell inside the new environment expand it:

```bash
sa-vault exec pg-ro -- sh -c 'psql "$DATABASE_URL"'
```

To load credentials once for several commands, `env` takes the same arguments
and prints shell that exports them:

```bash
eval "$(sa-vault env cdp-es)" && python3 extract.py && python3 report.py
```

Only ever run `env` inside `eval`: its stdout is the values, so run bare in an
agent's shell it prints them into the transcript. At a terminal it masks them
instead of splattering them across your scrollback.

Scripts should read their credentials from the environment and never from a
file:

```python
import os
key = os.environ["ES_API_KEY"]      # set by sa-vault exec, absent otherwise
```

| Command | Returns |
|---|---|
| `sa-vault ls` | names, variable names, descriptions — never a value |
| `sa-vault show <name>` | one credential, sealed values masked |
| `sa-vault exec <name> -- <cmd>` | nothing; runs `<cmd>` with the variables set |
| `sa-vault env <name>` | shell that exports the variables, for `eval` only |
| `sa-vault get <name>` | one bare value, at a terminal only |
| `sa-vault export <name>` | `KEY=VALUE` lines for an env file, at a terminal only |

## What this actually protects against

A security tool that overpromises is worse than none, so plainly:

**It prevents** plaintext landing in the LLM context, the on-disk transcript,
and the model provider's logs by accident or by default. The value goes from the
vault into one command's environment without being rendered anywhere the agent
reads. This is the real win and it is the reason to use it.

**It does not prevent** an agent that wants the value from getting it. Once a
variable is exported, `echo "$ES_API_KEY"` prints it, and `sa-vault get --force`
returns it outright. The audit log records that a credential was loaded, which
leaves a trail; it is not a wall.

**There is no scrubbing.** Anything a command prints goes to the agent verbatim.
A client that echoes its own connection string in an error message will put that
credential in the transcript. Prefer credentials that are read-only and cheap to
rotate.

If you want the harness to police this rather than trusting the agent to behave,
Claude Code permission rules are the place — see step 3 of
[Install](#install).

## Where things live

```
~/.sa-vault/
  vault.json      cleartext metadata — names, variable names, public values
  vault.sealed    encrypted values (XChaCha20-Poly1305, per-entry data keys)
  audit.log       every load, append-only. Never contains values.
```

Metadata is deliberately separate so `ls` needs no key and never prompts.

The master key is one macOS Keychain item. This binary issues exactly one
keychain query, always naming both the service and the account, and never
enumerates — `sa-vault doctor --keychain` prints exactly what it touches, and a
build-time test fails if an enumeration API appears anywhere in the tree.

Three environment variables override the defaults, most explicit first:

| Variable | Effect |
|---|---|
| `SA_VAULT_KEK_FILE` | read the master key from a 0600 file holding base64 |
| `SA_VAULT_PASSPHRASE` | derive it with argon2id; the salt sits next to the vault |
| `SA_VAULT_DIR` | put the vault somewhere other than `~/.sa-vault` |

There is no keychain outside macOS, and `sa-vault` says so rather than quietly
falling back to something weaker — on Linux and in CI, set one of the first two.

**There is no backup command.** If the Keychain item goes away, `vault.sealed`
is unrecoverable — treat the vault as a convenience cache for credentials you
can re-issue, not as the only copy of anything.

## Auditing

```bash
sa-vault audit -n 20
```

```
WHEN                 COMMAND  CREDENTIAL  VARIABLES
2026-08-06 15:05:13  env      cdp-es      ES_ENDPOINT,ES_API_KEY
2026-08-06 15:05:28  get      pg-ro       DATABASE_URL
```

## License

MIT
