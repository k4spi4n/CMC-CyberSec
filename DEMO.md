# Demo script (8–10 minutes)

Before you start: open 2 terminals in the project folder, run `.venv\Scripts\python -m mldsa_app.web` and open http://127.0.0.1:5000. Keep `REPORT.md` section 3 (the compliance table) open.

Slides: https://claude.ai/artifact/VDWUhcERMNMzVvmRcMSZ5R. Phúc presents slides 1–7, Bình slides 8–11, Luân slides 12–15, Duy slides 16–19. Each slide has speaker notes in English.

| Time | Speaker | Content | Action |
|---|---|---|---|
| 0:00–1:30 | Vũ Hoàng Phúc | **The problem:** a quantum computer running Shor's algorithm breaks RSA/ECDSA. Long-lived signatures (contracts, firmware) are at risk. NIST standardized ML-DSA (FIPS 204, Aug 2024) | Slides 1–4 |
| 1:30–2:30 | Vũ Hoàng Phúc | **How it works:** equations with noise (LWE), commit → challenge → answer, retry if the answer could leak the secret. 3 parameter sets, why ML-DSA-65 | Slides 5–7, `python -m mldsa_app info` |
| 2:30–5:00 | Đặng Thái Bình | **Web demo** (see below) | Browser, slide 11 as backup |
| 5:00–6:00 | Đặng Thái Bình | **Full CLI scenario:** hedged signing, rewritten-context attack, empty file, 20 MiB file | `python -m mldsa_app demo` |
| 6:00–7:30 | Trần Vũ Luân | **Proof:** 165/165 NIST ACVP vectors, cross-check with dilithium-py, rule → code → proof table | `python -m pytest -q` (~1 s) + slides 12–14 |
| 7:30–8:30 | Trần Vũ Luân | **Performance:** fast (< 1 ms to sign) but ~47× bigger signatures than ECDSA | `python -m mldsa_app bench -n 20` |
| 8:30–9:30 | Đinh Thế Duy | **AI usage:** how we checked AI output, what the checks caught. **Limitations:** no PKI, no trusted timestamp, web demo keeps keys in RAM | Slides 16–19 |

## Web demo steps (Đặng Thái Bình)

| # | Do this | Result | What it proves |
|---|---|---|---|
| 1 | Generate key "Alice", ML-DSA-65 | 1952-byte public key | Keys are derived from a 32-byte random seed |
| 2 | Sign "Party A transfers 100,000,000 VND to Party B." | 3309-byte signature | The signature binds file + key + context |
| 3 | Verify | **green** | Correct signatures are accepted |
| 4 | Click **Change 1 character** (100 → 900), verify | **red** | Integrity: the hash changes, so the challenge no longer matches |
| 5 | Sign again, click **Flip 1 signature bit**, verify | **red** | Strong unforgeability: a real signature cannot be tweaked into another valid one |
| 6 | Sign again, click **Change context**, verify | **red** | Domain separation: a contract signature cannot be reused as a payment signature |
| 7 | Generate key "Mallory", sign with Mallory, verify with Alice | **red** | Authenticity: only Alice's private key works with Alice's public key |

## CLI scenario (`python -m mldsa_app demo`)

| Step | What happens | Meaning |
|---|---|---|
| 1–3 | Alice makes a key, signs the contract, Bob verifies: **VALID** | The system works |
| 4 | Signing the same file twice gives two different signatures, both valid | Hedged signing (FIPS 204 §3.4): fresh randomness protects against side-channel and fault attacks. This is not a bug |
| 5 | 100,000,000 → 900,000,000: **INVALID** | Integrity |
| 6 | Flip 1 bit of the signature: **INVALID** | Strong unforgeability (SUF-CMA) |
| 7 | Mallory signs and copies Alice's fingerprint into the file: **INVALID** | Authenticity; the metadata in the file is not trusted |
| 8 | Reuse in context `payment/v1`: rejected, **even when the attacker rewrites the context field** | The context is inside μ, so the cryptography itself blocks it |
| 9 | Empty file and 20 MiB file: **VALID** | Edge inputs; big files are hashed piece by piece (external μ) |

## Likely questions

| Question | Suggested answer |
|---|---|
| Why does signing the same document twice give different signatures? | Hedged signing (§3.4): each signature mixes in 32 fresh random bytes. This protects against fault attacks. Verification accepts both. |
| What is rejection sampling for? | The answer z = y + c·s₁ could leak the secret s₁ if it is too large. In that case the signer throws it away and tries again (about 5.1 tries on average for ML-DSA-65, FIPS 204 Table 1). |
| How do you sign a 1 GB file? Do you use HashML-DSA? | No. We compute μ piece by piece (Alg. 7, line 6 allows μ to be computed in another module), then call `sign_mu`. The result is still a standard pure ML-DSA signature; the test `test_streamed_signature_is_standard_signature` proves it. |
| What does the context string protect against? | Reuse in another purpose: a signature on a "contract" cannot be used as a "payment" signature. The context is inside M′, so editing the metadata does not help. |
| Why is the private key only 32 bytes? | We store the seed ξ (§3.6.3, §4); the full 4032-byte key is rebuilt from it. The seed must be protected like the private key, so the PEM file is password-encrypted. |
| What if an attacker changes the `algorithm` field to ML-DSA-44? | The parameter set comes from the public key. A mismatching field is rejected immediately (`test_bundle_tampered_metadata`). |
| How do you know the library follows the standard? | 75/75 keyGen and 90/90 sigVer official NIST vectors match, and it interoperates with an independent implementation. |
| Is ML-DSA perfectly secure? | No. Its security rests on the MLWE/SelfTargetMSIS assumptions, and there are still side-channel and key-management risks. That is why many systems use hybrid signatures during the transition. |
