# Security Design

## Threat model

The program is designed to limit exposure while processing sensitive records in an organizer-controlled local sandbox: raw records and identity evidence remain in process memory; sanitized output is private; raw unsupported inputs are not copied; and logs/errors should avoid source values. This does not protect against a compromised host/process, privileged memory inspection, swap or crash dumps, malicious Python/runtime dependencies, or arbitrary sensitive content the parser does not recognize.

## Secret and key handling

`RAKSHA_SECRET` is required and validated as nonblank UTF-8 with a minimum length of 16 bytes. HKDF-SHA256 derives purpose-separated keys for pseudonyms, date shifting, and AES-GCM intermediate-data encryption. The AES-256-GCM envelope uses a fresh random 12-byte nonce and authenticated ciphertext. Secret entropy is not measured; deployments must supply high-entropy secret material.

The AES-GCM helper is implemented and unit-tested, but **the live pipeline does not persist sensitive intermediates and does not call this encryption helper**. No at-rest encryption claim is made for runtime memory or host swap.

## Filesystem, logs, and errors

Input is bounded and opened without following symlinks. Output paths are checked for unsafe traversal/symlink conditions; files and directories are created with restrictive permissions. Sanitized files are staged to temporary siblings and atomically replaced. Failure paths use fixed error categories, while structured per-file logs use content hashes and statuses rather than record contents. Output validation checks for unsafe artifacts and secret bytes. Quarantine is represented in `report.json`, not copied into the sanitized release.

These controls do not guarantee secure deletion on SSDs/filesystems, Python memory zeroization, complete detection of every possible PII string, or full isolation against a compromised machine. The output tree includes hashes and aggregate processing metadata, which should still be handled as sensitive operational data.

## Validation evidence

Security unit tests cover key separation/validation, authenticated encryption and tampering, safe logging, input/output path handling, symlinks, bounded reads, cleanup, and secret/PII-safe failure behavior. The synthetic adversarial suite also checks input immutability, output identity surfaces, quarantine copying, and temporary artifacts. Passing these checks is evidence for the tested cases only.
