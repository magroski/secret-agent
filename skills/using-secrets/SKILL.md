---
name: using-secrets
description: Use when you need credentials to reach a real system — querying a database, hitting an internal HTTP API, searching an Elasticsearch index, or needing an API key or environment variable. Covers discovering which credentials exist and loading them into a command's environment without the values entering the conversation. Triggers on connection strings, DATABASE_URL, .env files, "I don't have credentials", authentication failures against internal services, and any request to inspect or query real data.
---

# Using stored credentials

Credentials live in a local vault, managed by `sa-vault`. You can see what
exists and use it. You do not need to see any value, and you should not.

## The loop

```bash
sa-vault ls                                   # what exists
eval "$(sa-vault env cdp-es)" && python3 report.py
```

`sa-vault ls` prints names, the variables each credential exports, and a
description. A `*` marks a sealed value. Nothing it prints is secret.

`sa-vault env <name>` prints shell that exports those variables. Evaluating it
puts the values in the environment of the command you run next, and nowhere
else. It also prints, to stderr, which variables it exported — that confirmation
is all you need.

## It has to be one command

Shell state does not survive between your tool calls, so the `eval` and the
command that uses it must be in the same invocation, joined with `&&`:

```bash
eval "$(sa-vault env cdp-es)" && python3 report.py     ✅
```
```bash
eval "$(sa-vault env cdp-es)"                          ❌ the next call won't see it
python3 report.py
```

## Loading one value under a chosen name

```bash
eval "$(sa-vault env --set DATABASE_URL=pg-ro)"        # that entry's only secret
eval "$(sa-vault env --set ES_KEY=cdp-es.ES_API_KEY)"  # one variable of a bundle
eval "$(sa-vault env --tag cdp)"                       # everything tagged cdp
```

## Code you write reads the environment

Never write a credential into a file, not even a temporary one, and never
interpolate one into a command line.

```python
# report.py
import os
key = os.environ["ES_API_KEY"]      # exported by sa-vault env, absent otherwise
```

```bash
eval "$(sa-vault env cdp-es)" && python3 report.py
```

For a program that takes a flag rather than an environment variable, pass the
variable through without expanding it yourself — `psql "$DATABASE_URL"` is fine,
because the shell substitutes it and you never see it.

## Do not read the values

```bash
echo "$ES_API_KEY"                     ❌ puts it straight in the transcript
sa-vault get cdp-es --force            ❌ same, and it is audited
sa-vault export cdp-es --force         ❌ same, every variable at once
env | grep ES_                         ❌ same
cat .env                               ❌ don't hunt for credentials elsewhere
```

There is a `sa-vault get`, and it exists for the human who owns the vault. If
you genuinely cannot proceed without a value, say so and let them run it.

## When something is missing

- **`no credential named X`** — the error lists what does exist. Use one of
  those rather than guessing again.
- **Nothing suitable in `sa-vault ls`** — ask the user to add it. Don't go
  looking through `.env` files, shell history, or `~/.pgpass`:

  ```bash
  sa-vault add <name> --secret <VARIABLE_NAME>
  ```

- **`would be set twice`** — two credentials export the same variable name. Load
  only the one you need, or use `--set` to rename.
