# Contributing to AIPP

## The rules that actually matter

1. **A claim needs its proof.** A mechanism is not "done" until an
   experiment (in `experiments/`) or a conformance vector
   (`conformance/vectors.json`) exercises it against a real socket.
   "It compiles and I believe it" is not a state to commit.
2. **The spec wins.** `SPEC.md` is normative. If code and spec disagree,
   fix the code — or change the spec deliberately and say so in the
   commit message.
3. **Refusals must name the problem.** `ERR 421 :unknown command 'FOO'`
   is conformant; `ERR 421 :bad command` is not.
4. **Honesty in docs.** The README's "deliberately not implemented"
   section is a contract. Moving something out of it requires the test
   that proves it exists.

## Gates (all of them, every commit)

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
python3 experiments/experiment_001_dual_plane.py
python3 experiments/experiment_002_hardening.py
python3 experiments/experiment_003_tls.py
python3 experiments/experiment_004_federation.py
```

CI runs the same list. A PR that turns one red is not ready.

## Protocol changes

* Adding a control command: update `SPEC.md` §4, add a canonical vector
  and a refusal vector, keep the canonical form idempotent.
* Adding a TLV type: update the registry and `SPEC.md` §7; unknown
  types must still be relayed unchanged.
* Changing a numeric or the token format is a breaking change: bump the
  major, never slip it in.

## Commits

One commit per mechanism, message says what and why. English for code
and commits.
