# BCS703 CNS Lab - SHA-256 Integrity Demo Summary Table

> **DEMO ONLY - dummy data, local files only - BCS703 CNS Lab**

| Test | Input | Expected Result | Actual Result | Status |
| :--- | :--- | :--- | :--- | :--- |
| Test 1: Normal Match | `sample.txt` vs `sample_copy.txt` | Hashes match | Hashes match | **PASS** |
| Test 2: Tamper Detection | `sample.txt` vs `sample_tampered.txt` | Hashes differ | Hashes differ | **PASS** |
| Test 3: File Verification | `sample.txt.sha256` against original & tampered | Original: OK; Tampered: INTEGRITY FAILED | Original: OK; Tampered: INTEGRITY FAILED | **PASS** |
| Test 4: Avalanche Effect | 1-char / 1-bit change (`lab` -> `Lab`) | Drastic digest change (~50% bits) | 61/64 hex chars, 127/256 bits (49.61%) | **PASS** |
| Test 5: Fixed Length | `sample.txt` (25 B) vs `sample_big.txt` (5200 B) | Both 64 hex chars (256 bits) | Small: 64 chars; Big: 64 chars | **PASS** |
| Test 6: Determinism | `sample.txt` hashed 3 times | All 3 digests identical | All 3 identical | **PASS** |
| Bonus: HMAC-SHA256 | `sample.txt` & `sample_tampered.txt` + fake key | Orig matches; tampered rejected via compare_digest | Orig match=True; Tampered diff=True | **PASS** |
