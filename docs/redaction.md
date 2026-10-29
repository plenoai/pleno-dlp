# Detector display contract

A nonempty `Result.Raw` or `Result.RawV2` must never occur in full inside
`Result.Redacted`. The comparison uses bytes; empty secret fields are ignored.
This is a display contract, not a claim that a detector found every sensitive
value in the input.

Built-in `FromData` and `FromReader` implementations pass their result slices
through `detectors.SafeResults` before returning. Reader implementations that
delegate to `FromData` inherit the same guarantee. This preserves optional
interfaces such as `Verifier`, `Revoker`, and `ReaderDetector`.

The common policy preserves an existing safe display. An unsafe or empty
candidate receives a shared mask: at most six leading runes for a longer
secret, otherwise a marker. Both secret fields are checked again, including
whether a short secret occurs in the prefix or marker. Raw values and detector
metadata remain unchanged.

Output, audit, and revoke boundaries also use `SafeRedacted` to validate
manually constructed findings, custom detectors, and persisted spool records.
Hooks may shorten the safe display, but must not append characters that could
reconstruct a complete secret.

Detector fixtures call `internal/redactiontest.FromData` or `FromReader`.
These wrappers assert the contract on the actual returned fields without
altering them. Run the fixture suite with:

```sh
go test -race -tags=detector_unit ./pkg/detectors/...
```
