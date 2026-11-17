# Exact-copy output protection in the PoC

Output protection checks exact raw copies only. Held credentials receive an exact-byte check:
seed and derived keys, the local data key, credit account credentials, account and live session
inference keys, the held application inference key, and provider and deployment relay keys.
Provider and deployment relay keys are checked as their canonical lowercase hex text. A credential
that has been discarded has no retained output filter. Values that merely look like credentials
receive no special treatment.

Row 23 is removed from this PoC. There is no scan-reference inventory, loader, reload,
readiness barrier, synthetic producer or keyed window scanner. It returns with `place_secret`
in twr-ggw.23; a placed secret added then joins the held-credential check. Today a discarded
application inference key has no retained filter, and the rescue root password retains only
declared-field withholding.

The boundary checks original output bytes and structured string fields before serializing requests,
journal records, reports or cards, then checks the serialized bytes for exact copies introduced by
framing or escaping. Journal custody exemptions cover only credential field contents; public metadata
and framing are checked. Protocol parsing still reads response JSON and decodes the job record's
explicitly typed byte fields. Output text is never interpreted as another JSON document, an escaped
literal, hex, percent escapes or base64. Encoded, partial and transformed copies pass. The final
inference request body retains its exact held-credential check.

Matches produce visible markers. A marker collision or final serialization hit withholds output. There is no protection-work guard, decoding-depth pause, clean-record
memo or protection warm-up.

Journal writes remain version 4 and reads accept versions 2 and 4. Earlier provider-protection
fingerprint records still decode and are ignored. Existing records are neither rewritten nor
resealed. Plain file transfers and application-key placement retain their existing flows.

Successful inference replies are classified for cut-off before protection. A truncated reply is
discarded and the existing completion cap can advance from 4000 to 8000 to 16000. For complete
replies the boundary checks message content, call IDs, function names, raw argument strings and
parsed arguments. Error messages are protected before they become diagnostics. Reasoning text and
unused response metadata are discarded: they are never journaled, shown, logged or sent onward,
and receive no protection pass. Any used field with an exact held-credential copy refuses the reply.

Removing row 23 contradicts `SEC-5` and ADR-0041's placed-secret requirements. This branch claims
no specification conformance, including the separate occurrence-custody and finalizer requirements.
