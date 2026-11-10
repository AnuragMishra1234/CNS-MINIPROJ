# BCS703 CNS Lab — Local CLI Hash Commands & Explanations

> **DEMO ONLY - dummy data, local files only - BCS703 CNS Lab**

All commands below operate **only** on the dummy sample files inside `cns_hash_demo/`.

---

## 1. Local Execution Status on This Machine

* **OpenSSL (`openssl`)**: **NOT INSTALLED** on this Windows 11 machine (`Get-Command openssl` found no executable). Per Safety Rule 4, nothing was downloaded or installed, and the `openssl` commands were skipped.
* **Windows PowerShell (`Get-FileHash`)**: **EXECUTED** locally on `sample.txt` and `sample_tampered.txt`. Real outputs are saved in `results/openssl_output.txt`.

---

## 2. OpenSSL Commands (Reference — Skipped Locally Because OpenSSL Was Not Installed)

Run these from inside `cns_hash_demo/` if OpenSSL is installed on your lab machine:

### Check OpenSSL version
```bash
openssl version
```
* `openssl`: Invokes the OpenSSL command-line cryptography toolkit.
* `version`: Subcommand that prints the installed OpenSSL release version and build date (useful for lab documentation).

### Compute SHA-256 of the original sample file
```bash
openssl dgst -sha256 sample.txt
```
* `openssl`: Runs the OpenSSL CLI tool.
* `dgst`: Selects the message digest (cryptographic hashing) subcommand.
* `-sha256`: Specifies the SHA-256 algorithm (256-bit digest / 64 hex characters).
* `sample.txt`: The local dummy input file to hash (read-only).

### Compute SHA-256 of the tampered copy
```bash
openssl dgst -sha256 sample_tampered.txt
```
* `openssl`: Runs the OpenSSL CLI tool.
* `dgst`: Selects the message digest subcommand.
* `-sha256`: Specifies the SHA-256 algorithm.
* `sample_tampered.txt`: The modified dummy copy (`"lab"` changed to `"Lab"`) to verify that its digest differs completely from `sample.txt`.

---

## 3. Native OS Equivalents

### A. Windows PowerShell (Executed on This Machine)
```powershell
Get-FileHash -Algorithm SHA256 sample.txt
Get-FileHash -Algorithm SHA256 sample_tampered.txt
```
* `Get-FileHash`: Built-in PowerShell cmdlet (`Microsoft.PowerShell.Utility`) that computes cryptographic file hashes locally.
* `-Algorithm SHA256`: Tells `Get-FileHash` to use SHA-256 (default is SHA256, passed explicitly here for clarity).
* `sample.txt` / `sample_tampered.txt`: Target dummy file paths inside `cns_hash_demo/`.
* *Note*: `Get-FileHash` prints uppercase hexadecimal characters (`8BB2...`), whereas Python and OpenSSL print lowercase (`8bb2...`). Hexadecimal digest comparison is case-insensitive.

### B. Linux Equivalent (`sha256sum`)
```bash
sha256sum sample.txt
sha256sum sample_tampered.txt
```
* `sha256sum`: Standard GNU coreutils utility on Linux that prints `<64-hex-digest>  <filename>` (the exact format written by `hash_demo.py` into `sample.txt.sha256`).
* `sample.txt` / `sample_tampered.txt`: Input files to hash.

### C. macOS Equivalent (`shasum`)
```bash
shasum -a 256 sample.txt
shasum -a 256 sample_tampered.txt
```
* `shasum`: Built-in Perl-based checksum utility on macOS.
* `-a 256`: Selects algorithm variant `256` (SHA-256; options include `1`, `224`, `256`, `384`, `512`).
* `sample.txt` / `sample_tampered.txt`: Input files to hash.

---

## 4. Cross-Check: OpenSSL / Native OS vs. Python (`hash_demo.py`)

SHA-256 is standardized (FIPS 180-4), so **every compliant tool—Python's `hashlib.sha256`, OpenSSL's `openssl dgst -sha256`, Windows `Get-FileHash -Algorithm SHA256`, Linux `sha256sum`, and macOS `shasum -a 256`—must produce the exact same digest** for identical input bytes.

| File | Python `hash_demo.py` Output | Windows PowerShell `Get-FileHash` Output (lowercased) | OpenSSL Status | Match? |
| :--- | :--- | :--- | :--- | :--- |
| `sample.txt` | `8bb20bacc7507165142b144e3d7c327347393548f8002884136cc0b549a3d522` | `8bb20bacc7507165142b144e3d7c327347393548f8002884136cc0b549a3d522` | Skipped (not installed) | **YES (Exact Match)** |
| `sample_tampered.txt` | `ca815d8914c5c56b550e7e572a27894b4253dcb44fc68abe3ecda042ca046c8f` | `ca815d8914c5c56b550e7e572a27894b4253dcb44fc68abe3ecda042ca046c8f` | Skipped (not installed) | **YES (Exact Match)** |
