# secret-agent

One Go binary, `sa-vault`: a credential store whose output is meant to be
evaluated by a shell, so a value reaches a command without passing through an
agent's transcript.

## Layout

```
cmd/sa-vault/          main; dispatches to internal/cli
internal/vault/        metadata (cleartext) + sealed values, keychain
internal/cli/          every command
internal/audit/        append-only access log
```

## Rules that are not negotiable

- **`env` output is executed.** Values are wrapped in single quotes with `'`
  escaped as `'\''`; variable names are validated against the POSIX name rules
  on the way in *and* again on the way out, because a name is the one part of
  that string quoting cannot contain. `TestEnvQuotingSurvivesARealShell` runs
  the emitted shell through `/bin/sh` — extend it rather than reasoning about it.
- **Secrets never reach argv.** Not when adding them, not when using them. argv
  is readable by every process on the machine.
- **Metadata must stay free of secret material** so `ls` needs no key. A
  variable marked `Secret` may not carry a `Value`; `vault.Entry.Validate`
  enforces it and a test asserts the metadata file never contains plaintext.
- **Keychain access stays in one file, one exact-match query.** See
  `internal/vault/kek_darwin.go`; `keychain_guard_test.go` enforces it.
- **`get` requires a terminal** unless `--force`. It is the plaintext path and
  should stay awkward; `env` is the path that should be easy.

## Reading several secrets

Piped input is consumed whole so a multi-line value survives, which makes two
piped secrets ambiguous — `add` and `edit` refuse it rather than silently
handing the whole stream to the first.

At a terminal, hidden reads bypass the buffered line reader, so a command that
mixes visible and hidden prompts must share **one** `prompter` (see
`internal/cli/term.go`). Building a second one discards whatever the first had
buffered, which desynchronizes every prompt after it.

## Testing

```bash
go test ./...
```

The tests that matter most are the adversarial ones: shell escaping and variable
name validation in `internal/cli`, and AAD binding in `internal/vault`. When
changing those, add the attack you thought of before adding the feature.

`scripts/leak-test.sh` is the end-to-end claim: it runs a real agent session
against a disposable database and greps the resulting transcript for the
password in six encodings. It needs docker and the `claude` CLI.
