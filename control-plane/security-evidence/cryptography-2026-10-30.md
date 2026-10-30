# Cryptography exception review — 2026-10-30

## Decision and scope

Renew the three execution-path-based `not_affected` records for the exact
`cryptography==48.0.1` runtime and development locks until 2026-11-29 (30 days).
This is not a claim that 48.0.1 is patched. No lock, hash, inventory, dependency
constraint, account-write capability, or publishing setting changes.

Reviewed source baseline: `fc3908e786c318776df89a3a098333da377364be`.
The scope is first-party Python in `claude_ads_core`, `evals`, and `scripts`.

## Official advisory reconciliation

Sources retrieved on 2026-10-30; the discrepancy remains unresolved.

| Advisory | Publisher package range | GitHub Reviewed package range | Fixed version |
| --- | --- | --- | --- |
| PYSEC-2026-3552 / CVE-2026-69247 | Introduced in 44.0.0; fixed in 50.0.0 | >=44.0.0,<50.0.0 | 50.0.0 |
| PYSEC-2026-3553 / CVE-2026-69249 | <=48.0.0 | >=42.0.0,<49.0.0 | 49.0.0 |
| PYSEC-2026-3554 / CVE-2026-69248 | <=48.0.0 | >=45.0.0,<49.0.0 | 49.0.0 |

Publisher and reviewed records:

- https://github.com/pyca/cryptography/security/advisories/GHSA-g6cj-pr64-35w5
- https://github.com/advisories/GHSA-g6cj-pr64-35w5
- https://github.com/pyca/cryptography/security/advisories/GHSA-jwv3-5hgf-82ww
- https://github.com/advisories/GHSA-jwv3-5hgf-82ww
- https://github.com/pyca/cryptography/security/advisories/GHSA-m2h6-j472-rp4c
- https://github.com/advisories/GHSA-m2h6-j472-rp4c
- https://cryptography.io/en/latest/changelog/

The 48.0.1 changelog describes a wheel OpenSSL update, not either X.509 fix.
Do not infer a backport from the publisher's <=48.0.0 upper bound. Treat all
three as package-level findings for 48.0.1 and assess execution paths separately.

## Execution-path evidence

All first-party cryptography imports resolve to `cryptography.exceptions`
(`InvalidSignature`) and
`cryptography.hazmat.primitives.asymmetric.ed25519` (`Ed25519PublicKey`).

| File | Relevant call on baseline | SHA-256 of reviewed source |
| --- | --- | --- |
| evals/model_evidence_auth.py | verify_envelope, line 187: verify externally authenticated model evidence | 1472381c7c9b82a930c65db37ad070d2116f0dd9d1a5752fe65a8fd7103e2038 |
| scripts/review_evidence.py | line 442: verify independent review signature | d3403fd3f9efc06567f58530d7e9da1abc294eed5e76b133aa8926f573f16c00 |
| scripts/url_utils.py | line 403: verify egress attestation signature | 417d4cf3e52051a9f437413731be0c67a1c82c033def1a1ee63139ff36082806 |

These paths construct a raw Ed25519 public key and verify a signature over
canonical bytes. They do not decrypt PKCS7 EnvelopedData, construct an X.509
certificate store, or build/verify a certificate chain. There is no first-party
call to `pkcs7_decrypt_der`, `pkcs7_decrypt_pem`, or `pkcs7_decrypt_smime`.
The reviewed dependency inventory contains no dependency edge whose target is
cryptography; it is directly declared for verification, not pulled in by another
inventoried package.

The existing audit guard prohibits PKCS7 serialization imports for 3552 and
all `cryptography.x509` imports for 3553/3554, including parent imports and
resolvable dynamic imports. Unresolvable dynamic import dispatch fails closed.
Retain the exact package-version checks, profile consistency checks, source
scope, maximum 30-day evidence age, and audit-output matching checks.

## Why defer the upgrade

50.0.2 is a candidate that includes all three fixes, not a verified replacement
for the supported installation matrix. The official 49.0.0 changelog removes
x86_64 macOS wheel support. Publisher metadata at
https://pypi.org/pypi/cryptography/50.0.2/json confirms its macOS wheels are
arm64 only. The current locks explicitly support macOS 11 x86_64 and arm64,
CPython 3.11/3.12, with `--only-binary=:all:`. Moving the common lock to 50.x
would break the declared Intel macOS installation contract.

A later upgrade requires a deliberate target-support decision or a separately
verified artifact strategy, consistent locks/hashes/inventory/notices, and the
complete target matrix. Source builds or silently dropping Intel support are
not a compatible fix for this task.

## Verification and remaining blockers

Live `pip-audit==2.10.1` was installed using the CI hash lock. Both runtime and
development reports still identify exactly the three distinct cryptography
advisory IDs above; repeated IDs in scanner output are not extra findings.
The development profile has no other advisory IDs.

The complete dependency audit already fails on the unchanged baseline due to
additional runtime findings for brotli 1.2.0, certifi 2026.6.17, and pillow
12.3.0. Those findings are outside these three exceptions and remain unhandled;
no new suppressions are added. The full audit must remain failed until those
findings receive separate investigation. A cryptography-only report evaluation
is a scoped diagnostic, never a substitute for the complete CI audit.

Local verification on Linux CPython 3.12, with hash-checked runtime, development,
and schema-test locks installed and cryptography confirmed as 48.0.1:

- `pip check`: passed.
- `pytest -q -rs tests/scripts/test_audit_dependencies.py
  tests/scripts/test_url_utils.py tests/release/test_review_contracts.py
  tests/routing/test_model_eval_gate.py`: 169 passed, 4 skipped. All four skips
  require external DNS resolution unavailable to the test environment.
- Exception JSON schema with format checks: passed.
- Dependency inventory verifier and exception packaging integrity: passed.
- `scripts/release.py audit`: passed for tracked repository files.
- Evaluation of live reports filtered to cryptography: passed, three matched
  not-affected advisory IDs across runtime/development. This is only a scoped
  diagnostic.
- `scripts/audit_dependencies.py --as-of 2026-10-30`: failed, as on the unchanged
  baseline, on the other runtime findings described above.
- Loading the renewed ledger as of 2026-11-30: rejected as stale.

The tests cover Ed25519 success/tamper rejection, forbidden import injection,
profile/version drift, dynamic import guards, and evidence expiry. No vulnerable
PKCS7/X.509 exploit was executed; non-reachability is the disposition basis.

Limitations: the import guard is syntactic first-party analysis, not proof over
arbitrary plugins, native libraries, reflection, or all transitive execution.
The inventoried dependency graph is not a runtime trace. Cross-platform native
tests, remote CI, independent security review, and upgrade compatibility are
not established by this local review. These exceptions do not authorize release
or account writes. Reassess immediately if code paths, package versions,
dependency closure, or official advisories change, and before 2026-11-29.

Owner: security-owner. Rollback: revert this review change; the original
2026-11-06 expiry and fail-closed behavior return.
