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

agent  $ eval "$(sa-vault env cdp-es)" && python3 report.py
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

```bash
go install github.com/magroski/secret-agent/cmd/sa-vault@latest
sa-vault init
```

**Claude Code**

```
/plugin marketplace add magroski/secret-agent
/plugin install sa-vault@secret-agent
```

**Codex CLI**

```bash
codex plugin marketplace add https://github.com/magroski/secret-agent.git
codex plugin add sa-vault@secret-agent
```

The plugin ships a skill that teaches the agent the `eval "$(sa-vault env …)"`
pattern. Install the binary first; the plugin does not carry it.

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
eval "$(sa-vault env cdp-es)" && python3 report.py
```

Everything the credential declares is exported. To place a single value under a
name of your choosing:

```bash
eval "$(sa-vault env --set DATABASE_URL=pg-ro)"        # the entry's only secret
eval "$(sa-vault env --set ES_KEY=cdp-es.ES_API_KEY)"  # one variable of a bundle
eval "$(sa-vault env --tag cdp)"                       # everything tagged cdp
```

`env` writes shell to stdout and a summary of what it exported — names only — to
stderr, so the agent gets confirmation without the values. Run at a terminal
rather than through `eval`, it masks the values instead of splattering them
across your scrollback.

Scripts should read their credentials from the environment and never from a
file:

```python
import os
key = os.environ["ES_API_KEY"]      # exported by sa-vault env, absent otherwise
```

| Command | Returns |
|---|---|
| `sa-vault ls` | names, variable names, descriptions — never a value |
| `sa-vault show <name>` | one credential, sealed values masked |
| `sa-vault env <name>` | shell that exports the variables |
| `sa-vault get <name>` | one bare value, at a terminal only |

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

If you want the harness to police this, Claude Code permission rules are the
place — `Bash(sa-vault env:*)` on allow and `Bash(sa-vault get:*)` on ask keeps
the loading path frictionless and the plaintext path deliberate.

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
build-time test fails if an enumeration API appears anywhere in the tree. On
Linux and in CI, set `SA_VAULT_PASSPHRASE` or `SA_VAULT_KEK_FILE`.

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
