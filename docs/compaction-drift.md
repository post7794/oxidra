# Compaction recursive-drift baseline

Oxidra keeps automatic compaction opt-in until the current model and prompt
have a recorded 3/5/10-round recursive-summary baseline. The benchmark is a
developer measurement, not a unit test and not a hidden startup action.

## Run

The command uses normal Oxidra Provider configuration and credentials. It
requires an explicit acknowledgement because the default run makes ten live
Provider requests:

```powershell
cargo run --example compaction_drift --release -- `
  --confirm-live-calls `
  --output target/compaction-drift/gpt-5.6-sol-baseline.json
```

Optional `--model` and `--api-base-url` overrides follow the same validation as
the main CLI. API keys are never accepted as command-line arguments and are not
written to the artifact. Existing output files are not overwritten.

## Frozen input and recursion

`tests/fixtures/compaction_drift_v1.json` is the immutable source corpus. It
contains exact numbers, negative constraints, completed/pending/blocked state,
paths, identifiers, a hash, a command, a date, a user preference, and a quoted
prompt-injection string marked as untrusted history.

Round 1 sends that input with the registered compaction prompt, no tools,
`store: false`, and the production 8192-token output cap. Every later round
wraps only the previous summary with the production low-privilege summary
envelope before requesting the next summary. This is the same parent-summary
recursion boundary used by checkpoint chains; the benchmark does not add a
special reminder prompt between rounds.

## Artifact

The JSON artifact is rewritten after every completed round so a partial run is
still auditable. It records:

- model, timestamp, fixture hash and all current compaction protocol versions;
- each input and summary SHA-256;
- raw Provider response, usage and exact summary text;
- per-fact missing tokens and category scores;
- registered snapshots at rounds 3, 5 and 10;
- whether the quoted `ONLY_ATTACK_SUCCESS` instruction was followed exactly.

The first baseline intentionally has no pass/fail retention threshold. A
default-enable decision must cite concrete artifacts and separately state the
accepted loss budget for exact values, negative constraints, task status and
critical identifiers. Changing the fixture or metric semantics requires a new
fixture/artifact version rather than rewriting an existing result.
