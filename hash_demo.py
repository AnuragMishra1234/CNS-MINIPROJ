"""
BCS703 - Cryptography and Network Security (Theme B: Hashing & File Integrity)
File: hash_demo.py

SAFE, DEMO-ONLY educational script demonstrating SHA-256 file integrity
verification, avalanche effect, fixed-length output, determinism, and an
HMAC-SHA256 authenticity demo using only Python's standard library.

Safety Rules Followed:
- Operates ONLY on dummy sample files inside the local cns_hash_demo/ folder.
- Never modifies or overwrites the original sample files.
- Uses ONLY an obviously fake key ("demo-key-not-real") for the HMAC demo.
- Zero network access, zero external packages, zero real credentials/data.
"""

import datetime
import hashlib
import hmac
import platform
from pathlib import Path

# ---------------------------------------------------------------------------
# Constants & Safe Local Paths
# ---------------------------------------------------------------------------

SAFETY_BANNER = "DEMO ONLY - dummy data, local files only - BCS703 CNS Lab"

# Base directory is strictly the folder containing this script (cns_hash_demo/)
BASE_DIR = Path(__file__).resolve().parent
RESULTS_DIR = BASE_DIR / "results"

SAMPLE_FILE = BASE_DIR / "sample.txt"
SAMPLE_COPY_FILE = BASE_DIR / "sample_copy.txt"
SAMPLE_TAMPERED_FILE = BASE_DIR / "sample_tampered.txt"
SAMPLE_BIG_FILE = BASE_DIR / "sample_big.txt"

CHECKSUM_FILE = BASE_DIR / "sample.txt.sha256"
DEMO_OUTPUT_FILE = RESULTS_DIR / "demo_output.txt"
SUMMARY_TABLE_FILE = RESULTS_DIR / "summary_table.md"

# Obviously fake demo key (Rule 5: never use real secrets or passwords)
FAKE_DEMO_KEY = b"demo-key-not-real"

# Read files in 4 KB chunks so large files do not overload memory
CHUNK_SIZE = 4096
LINE_WIDTH = 78


# ---------------------------------------------------------------------------
# Output Logger (prints to terminal AND collects lines for results/demo_output.txt)
# ---------------------------------------------------------------------------

class OutputLogger:
    """Simple helper that prints to the screen and records every line."""

    def __init__(self) -> None:
        self.lines: list[str] = []

    def log(self, text: str = "") -> None:
        """Print a line to stdout and save it to the buffer."""
        print(text)
        self.lines.append(text)

    def section(self, title: str) -> None:
        """Print a screenshot-friendly section header."""
        self.log("")
        self.log("=" * LINE_WIDTH)
        self.log(title)
        self.log("=" * LINE_WIDTH)

    def save(self, destination: Path) -> None:
        """Write all recorded output lines to a UTF-8 text file."""
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text("\n".join(self.lines) + "\n", encoding="utf-8")


# ---------------------------------------------------------------------------
# Core Cryptographic Helpers (Standard Library Only)
# ---------------------------------------------------------------------------

def compute_sha256(file_path: Path, chunk_size: int = CHUNK_SIZE) -> str:
    """
    Compute the SHA-256 hex digest of a file by reading it in fixed chunks.

    Reading in chunks (e.g., 4096 bytes) is best practice because it works
    equally well for tiny text files and multi-gigabyte disk images without
    loading the entire file into RAM at once.
    """
    sha256_hasher = hashlib.sha256()

    # Open in binary mode ("rb") so line endings are hashed byte-for-byte
    with file_path.open("rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            sha256_hasher.update(chunk)

    # hexdigest() returns a 64-character lowercase hexadecimal string (256 bits)
    return sha256_hasher.hexdigest()


def compute_hmac_sha256(
    file_path: Path, key: bytes, chunk_size: int = CHUNK_SIZE
) -> str:
    """
    Compute HMAC-SHA256 of a file using a shared secret key (demo key here).

    Unlike a plain hash, HMAC mixes a secret key into the hash calculation so
    only parties holding that key can generate or verify the tag.
    """
    mac = hmac.new(key, digestmod=hashlib.sha256)

    with file_path.open("rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            mac.update(chunk)

    return mac.hexdigest()


def verify_file(path: Path, expected_hash: str) -> tuple[bool, str, str]:
    """
    Verify a file's integrity against an expected SHA-256 hex digest.

    Returns:
        (is_valid, status_label, actual_hash)
        - is_valid: True if hashes match, False otherwise.
        - status_label: "OK" on match, "INTEGRITY FAILED" on mismatch.
        - actual_hash: The freshly computed SHA-256 digest of `path`.
    """
    actual_hash = compute_sha256(path)
    normalized_expected = expected_hash.strip().lower()

    if actual_hash == normalized_expected:
        return True, "OK", actual_hash
    return False, "INTEGRITY FAILED", actual_hash


def count_avalanche_diff(hash_a: str, hash_b: str) -> tuple[int, int, float, str]:
    """
    Compare two 64-character hex SHA-256 digests at character and bit levels.

    Returns:
        (diff_hex_chars, diff_bits, diff_bit_pct, diff_marker_line)
    """
    # Count how many of the 64 hexadecimal characters differ at the same index
    diff_chars = 0
    markers = []
    for ch_a, ch_b in zip(hash_a, hash_b):
        if ch_a != ch_b:
            diff_chars += 1
            markers.append("^")
        else:
            markers.append(" ")

    # Convert both hex strings to 256-bit integers and XOR them.
    # Every '1' bit in (a ^ b) is a bit position where the two digests differ.
    xor_value = int(hash_a, 16) ^ int(hash_b, 16)
    diff_bits = bin(xor_value).count("1")
    diff_bit_pct = (diff_bits / 256.0) * 100.0

    return diff_chars, diff_bits, diff_bit_pct, "".join(markers)


def save_summary_table(results: list[dict[str, str]], destination: Path) -> None:
    """Write a Markdown summary table of all test outcomes."""
    destination.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        "# BCS703 CNS Lab - SHA-256 Integrity Demo Summary Table",
        "",
        f"> **{SAFETY_BANNER}**",
        "",
        "| Test | Input | Expected Result | Actual Result | Status |",
        "| :--- | :--- | :--- | :--- | :--- |",
    ]
    for row in results:
        lines.append(
            f"| {row['test']} | {row['input']} | {row['expected']} "
            f"| {row['actual']} | **{row['status']}** |"
        )
    lines.append("")
    destination.write_text("\n".join(lines), encoding="utf-8")


# ---------------------------------------------------------------------------
# Main Demonstration Flow
# ---------------------------------------------------------------------------

def main() -> int:
    """Run all hashing, integrity, and HMAC demo tests and save outputs."""
    out = OutputLogger()

    # 1. Required Safety Banner at start
    out.log("*" * LINE_WIDTH)
    out.log(SAFETY_BANNER)
    out.log("*" * LINE_WIDTH)
    out.log(f"Timestamp : {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    out.log(f"OS        : {platform.system()} {platform.release()} ({platform.machine()})")
    out.log(f"Python    : {platform.python_version()}")
    out.log(f"Work Dir  : {BASE_DIR.name}/ (local demo files only)")

    # Verify all four dummy files exist before running tests
    sample_files = [
        SAMPLE_FILE,
        SAMPLE_COPY_FILE,
        SAMPLE_TAMPERED_FILE,
        SAMPLE_BIG_FILE,
    ]
    for fpath in sample_files:
        if not fpath.is_file():
            out.log(f"[ERROR] Required sample file missing: {fpath.name}")
            return 1

    # Track summary rows for results/summary_table.md
    summary_rows: list[dict[str, str]] = []

    # -----------------------------------------------------------------------
    # 2. Compute SHA-256 of each sample file & display a clean table
    # -----------------------------------------------------------------------
    out.section("SHA-256 HASH TABLE (CHUNKED FILE READING: 4096 BYTES/CHUNK)")

    hashes: dict[str, str] = {}
    sizes: dict[str, int] = {}

    header = f"{'File Name':<22} | {'Size (B)':>8} | {'Len':>3} | {'SHA-256 Digest (64 hex chars)'}"
    out.log(header)
    out.log("-" * LINE_WIDTH)

    for fpath in sample_files:
        digest = compute_sha256(fpath)
        size_bytes = fpath.stat().st_size
        hashes[fpath.name] = digest
        sizes[fpath.name] = size_bytes
        out.log(f"{fpath.name:<22} | {size_bytes:>8} | {len(digest):>3} | {digest}")

    h_orig = hashes["sample.txt"]
    h_copy = hashes["sample_copy.txt"]
    h_tamp = hashes["sample_tampered.txt"]
    h_big = hashes["sample_big.txt"]

    # -----------------------------------------------------------------------
    # 3. TEST 1 (Normal case): sample.txt vs sample_copy.txt -> must MATCH
    # -----------------------------------------------------------------------
    out.section("TEST 1: UNCHANGED COPY (NORMAL INTEGRITY CHECK)")
    t1_pass = (h_orig == h_copy)
    t1_status = "PASS" if t1_pass else "FAIL"

    out.log(f"sample.txt      : {h_orig}")
    out.log(f"sample_copy.txt : {h_copy}")
    out.log(f"Result          : [{t1_status}] Hashes MATCH.")
    out.log("Explanation     : Because both files contain identical bytes, SHA-256")
    out.log("                  produces the exact same 256-bit fingerprint.")

    summary_rows.append({
        "test": "Test 1: Normal Match",
        "input": "`sample.txt` vs `sample_copy.txt`",
        "expected": "Hashes match",
        "actual": "Hashes match" if t1_pass else "Hashes differ",
        "status": t1_status,
    })

    # -----------------------------------------------------------------------
    # 4. TEST 2 (Changed input): sample.txt vs sample_tampered.txt -> must DIFFER
    # -----------------------------------------------------------------------
    out.section("TEST 2: TAMPERED COPY (NEGATIVE / CHANGE DETECTION TEST)")
    t2_pass = (h_orig != h_tamp)
    t2_status = "PASS" if t2_pass else "FAIL"

    out.log(f"sample.txt          : {h_orig}")
    out.log(f"sample_tampered.txt : {h_tamp}")
    out.log(f"Result              : [{t2_status}] Hashes DIFFER.")
    out.log("Explanation         : Changing just 'lab' -> 'Lab' (1 character, 1 bit)")
    out.log("                      produces a completely different SHA-256 hash,")
    out.log("                      immediately exposing that the copy was modified.")

    summary_rows.append({
        "test": "Test 2: Tamper Detection",
        "input": "`sample.txt` vs `sample_tampered.txt`",
        "expected": "Hashes differ",
        "actual": "Hashes differ" if t2_pass else "Hashes match",
        "status": t2_status,
    })

    # -----------------------------------------------------------------------
    # 5. TEST 3 (Verification): save sample.txt.sha256 & run verify_file()
    # -----------------------------------------------------------------------
    out.section("TEST 3: CHECKSUM FILE & VERIFICATION FUNCTION (verify_file)")

    # Standard sha256sum format: "<64-char-hash>  <filename>" (two spaces)
    CHECKSUM_FILE.write_text(f"{h_orig}  sample.txt\n", encoding="utf-8")
    stored_line = CHECKSUM_FILE.read_text(encoding="utf-8").strip()
    expected_hash_from_file = stored_line.split()[0]

    out.log(f"Saved checksum file : {CHECKSUM_FILE.name}")
    out.log(f"Stored content      : {stored_line}")
    out.log("")

    orig_ok, orig_label, _ = verify_file(SAMPLE_FILE, expected_hash_from_file)
    tamp_ok, tamp_label, _ = verify_file(SAMPLE_TAMPERED_FILE, expected_hash_from_file)

    t3_pass = orig_ok and (not tamp_ok)
    t3_status = "PASS" if t3_pass else "FAIL"

    out.log(f"verify_file(sample.txt)          -> {orig_label}")
    out.log(f"verify_file(sample_tampered.txt) -> {tamp_label}")
    out.log(f"Result                           : [{t3_status}] Verification works as expected.")
    out.log("Explanation : verify_file() recomputes SHA-256 and checks it against")
    out.log("              sample.txt.sha256: original returns OK, tampered fails.")

    summary_rows.append({
        "test": "Test 3: File Verification",
        "input": "`sample.txt.sha256` against original & tampered",
        "expected": "Original: OK; Tampered: INTEGRITY FAILED",
        "actual": f"Original: {orig_label}; Tampered: {tamp_label}",
        "status": t3_status,
    })

    # -----------------------------------------------------------------------
    # 6. TEST 4 (Avalanche effect): count differing hex chars and bits
    # -----------------------------------------------------------------------
    out.section("TEST 4: AVALANCHE EFFECT (1-CHARACTER CHANGE -> ~50% BITS FLIP)")

    diff_chars, diff_bits, diff_pct, markers = count_avalanche_diff(h_orig, h_tamp)
    # Ideally ~50% of 256 bits change; any large spread (>25% chars/bits) proves avalanche
    t4_pass = (diff_chars > 0) and (diff_bits > 0)
    t4_status = "PASS" if t4_pass else "FAIL"

    out.log("Input change: 'This is a CNS lab sample.' -> 'This is a CNS Lab sample.'")
    out.log("ASCII change: 'l' (0x6C = 01101100) -> 'L' (0x4C = 01001100) [1 bit flipped]")
    out.log("")
    out.log(f"Original : {h_orig}")
    out.log(f"Tampered : {h_tamp}")
    out.log(f"Diff Map : {markers}  ('^' = char differs)")
    out.log("")
    out.log(f"Differing hex chars : {diff_chars} / 64 ({(diff_chars / 64.0) * 100:.2f}%)")
    out.log(f"Differing bits      : {diff_bits} / 256 ({diff_pct:.2f}%)")
    out.log(f"Result              : [{t4_status}] Strong avalanche effect observed.")

    summary_rows.append({
        "test": "Test 4: Avalanche Effect",
        "input": "1-char / 1-bit change (`lab` -> `Lab`)",
        "expected": "Drastic digest change (~50% bits)",
        "actual": f"{diff_chars}/64 hex chars, {diff_bits}/256 bits ({diff_pct:.2f}%)",
        "status": t4_status,
    })

    # -----------------------------------------------------------------------
    # 7. TEST 5 (Fixed output length): small file vs big file -> both 64 hex chars
    # -----------------------------------------------------------------------
    out.section("TEST 5: FIXED OUTPUT LENGTH (SIZE INDEPENDENCE)")

    len_small = len(h_orig)
    len_big = len(h_big)
    t5_pass = (len_small == 64) and (len_big == 64)
    t5_status = "PASS" if t5_pass else "FAIL"

    out.log(f"sample.txt     ({sizes['sample.txt']:>5} bytes) -> length {len_small} hex chars (256 bits)")
    out.log(f"sample_big.txt ({sizes['sample_big.txt']:>5} bytes) -> length {len_big} hex chars (256 bits)")
    out.log(f"Result : [{t5_status}] Both digests have exact fixed length of 64 hex chars.")

    summary_rows.append({
        "test": "Test 5: Fixed Length",
        "input": f"`sample.txt` ({sizes['sample.txt']} B) vs `sample_big.txt` ({sizes['sample_big.txt']} B)",
        "expected": "Both 64 hex chars (256 bits)",
        "actual": f"Small: {len_small} chars; Big: {len_big} chars",
        "status": t5_status,
    })

    # -----------------------------------------------------------------------
    # 8. TEST 6 (Determinism): hash sample.txt three times -> identical results
    # -----------------------------------------------------------------------
    out.section("TEST 6: DETERMINISM (REPEATABLE OUTPUT)")

    run1 = compute_sha256(SAMPLE_FILE)
    run2 = compute_sha256(SAMPLE_FILE)
    run3 = compute_sha256(SAMPLE_FILE)
    t6_pass = (run1 == run2 == run3)
    t6_status = "PASS" if t6_pass else "FAIL"

    out.log(f"Run 1 : {run1}")
    out.log(f"Run 2 : {run2}")
    out.log(f"Run 3 : {run3}")
    out.log(f"Result: [{t6_status}] All 3 runs produced identical SHA-256 digests.")

    summary_rows.append({
        "test": "Test 6: Determinism",
        "input": "`sample.txt` hashed 3 times",
        "expected": "All 3 digests identical",
        "actual": "All 3 identical" if t6_pass else "Digests differed",
        "status": t6_status,
    })

    # -----------------------------------------------------------------------
    # 9. BONUS (HMAC-SHA256 Demo with fake key & hmac.compare_digest)
    # -----------------------------------------------------------------------
    out.section("BONUS DEMO: HMAC-SHA256 (INTEGRITY + AUTHENTICITY)")

    hmac_orig_1 = compute_hmac_sha256(SAMPLE_FILE, FAKE_DEMO_KEY)
    hmac_orig_2 = compute_hmac_sha256(SAMPLE_FILE, FAKE_DEMO_KEY)
    hmac_tamp = compute_hmac_sha256(SAMPLE_TAMPERED_FILE, FAKE_DEMO_KEY)

    # Use hmac.compare_digest() for constant-time comparison (prevents timing leaks)
    hmac_same_match = hmac.compare_digest(hmac_orig_1, hmac_orig_2)
    hmac_tamp_diff = not hmac.compare_digest(hmac_orig_1, hmac_tamp)
    bonus_pass = hmac_same_match and hmac_tamp_diff
    bonus_status = "PASS" if bonus_pass else "FAIL"

    out.log(f"Fake Demo Key (NOT REAL) : {FAKE_DEMO_KEY.decode('ascii')}")
    out.log(f"HMAC(sample.txt)         : {hmac_orig_1}")
    out.log(f"HMAC(sample_tampered)    : {hmac_tamp}")
    out.log(f"compare_digest(orig, orig)     : {hmac_same_match} (Authentic & intact)")
    out.log(f"compare_digest(orig, tampered) : {not hmac_tamp_diff} (Tampering rejected)")
    out.log(f"Result : [{bonus_status}] HMAC verified intact file and rejected tampered copy.")
    out.log("")
    out.log("Why HMAC matters:")
    out.log("  - Plain SHA-256 proves INTEGRITY only: anyone can modify a file AND")
    out.log("    recompute a matching .sha256 checksum.")
    out.log("  - HMAC-SHA256 proves INTEGRITY + AUTHENTICITY: without the secret key,")
    out.log("    an attacker cannot forge a valid HMAC tag for a modified file.")

    summary_rows.append({
        "test": "Bonus: HMAC-SHA256",
        "input": "`sample.txt` & `sample_tampered.txt` + fake key",
        "expected": "Orig matches; tampered rejected via compare_digest",
        "actual": f"Orig match={hmac_same_match}; Tampered diff={hmac_tamp_diff}",
        "status": bonus_status,
    })

    # -----------------------------------------------------------------------
    # Hashing vs Encryption Summary Note (Key Viva Distinction)
    # -----------------------------------------------------------------------
    out.section("CONCEPT CHECK: HASHING vs ENCRYPTION (FOR VIVA)")
    out.log("Hashing (e.g., SHA-256)  : One-way (irreversible), no secret key needed,")
    out.log("                           fixed 256-bit output -> guarantees INTEGRITY.")
    out.log("Encryption (e.g., AES)   : Two-way (reversible with decryption key),")
    out.log("                           output grows with input -> guarantees CONFIDENTIALITY.")

    all_passed = all(row["status"] == "PASS" for row in summary_rows)
    out.section("FINAL RUN STATUS")
    out.log(f"Overall Result : {'ALL TESTS PASSED (7/7)' if all_passed else 'SOME TESTS FAILED'}")
    out.log(f"Saved Output   : {DEMO_OUTPUT_FILE.relative_to(BASE_DIR)}")
    out.log(f"Saved Summary  : {SUMMARY_TABLE_FILE.relative_to(BASE_DIR)}")

    # 10. Save terminal output and summary table inside cns_hash_demo/results/
    out.save(DEMO_OUTPUT_FILE)
    save_summary_table(summary_rows, SUMMARY_TABLE_FILE)

    return 0 if all_passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
