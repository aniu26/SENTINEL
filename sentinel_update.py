# sentinel_update.py
# SENTINEL — Analyst Maintenance Tool
# Supports air-gap data transfer via
# export/import JSON workflow.
#
# Usage:
#   python sentinel_update.py          (menu)
#   python sentinel_update.py --export (online machine)
#   python sentinel_update.py --import sentinel_export.json
#                                      (air-gap machine)

import os
import sys
import time
import json
import hashlib
import re
import requests
from datetime import datetime, UTC
from dotenv import load_dotenv

# Load .env from the same directory as this script so db_connect() inside
# email_forensics can reach DB_HOST, DB_USER, etc. when running --import.
_script_dir = os.path.dirname(os.path.abspath(__file__))
load_dotenv(dotenv_path=os.path.join(_script_dir, ".env"))


# Official MITRE ATT&CK CTI feed (STIX 2.0 bundle, ~10 MB).
# Fetched at export time by fetch_mitre_techniques(); never contacted at import time.
MITRE_CTI_URL = (
    "https://raw.githubusercontent.com/"
    "mitre/cti/master/enterprise-attack/"
    "enterprise-attack.json"
)


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

def require_confirm(action_description):
    """Prompts the analyst to explicitly confirm a sensitive action before it runs.

    Why explicit confirmation matters in air-gap environments:
    Air-gapped machines are isolated from external networks deliberately —
    any unexpected outbound connection is a security violation that may
    trigger an incident response. This function forces the analyst to read
    a plain-language description of what is about to happen and type the
    word CONFIRM before any irreversible action (network call, database
    write, file write) is taken. This prevents two failure modes:
        1. Accidental execution — running the wrong mode flag, or pressing
           Enter too quickly through a menu, could cause an outbound API
           call on a machine that must never touch the internet.
        2. Script automation bypass — requiring a literal typed word (not
           just pressing Enter) means the confirmation cannot be satisfied
           by a non-interactive pipe or a shell script that passes empty
           input. The analyst must be physically present and aware.
    The confirmation string is case-sensitive ("CONFIRM" not "confirm") to
    make it harder to satisfy accidentally.

    Args:
        action_description: A plain-language string describing exactly what
                            is about to happen. Shown to the analyst before
                            the prompt.

    Returns:
        bool: True if the analyst typed exactly "CONFIRM", False otherwise.
    """
    # --- Input validation ---
    if not isinstance(action_description, str):
        action_description = str(action_description)
    action_description = action_description.strip()

    print(f"\n{action_description}")
    print()
    response = input("Type CONFIRM to proceed or anything else to cancel: ")
    return response == "CONFIRM"


def compute_checksum(data_dict):
    """Computes a SHA-256 checksum of a dictionary serialised to canonical JSON.

    Why checksums protect the air-gap transfer:
    When an analyst carries an export file from an online machine to an
    air-gapped machine on removable media (USB, CD), there are two integrity
    risks:
        1. Accidental corruption — filesystem errors, interrupted copies, or
           media degradation can silently alter bytes in the file.
        2. Deliberate tampering — a malicious actor with access to the media
           could modify the JSON to inject false MITRE technique IDs, bogus
           IP reputation data, or malformed values that exploit the importer.
    A SHA-256 checksum computed on the online machine and verified on the
    air-gapped machine before any data is written to the database catches
    both failure modes. SHA-256 is collision-resistant and preimage-resistant:
    an attacker cannot craft a modified file that produces the same hash.

    The checksum is computed over the "data" sub-dict only (not the whole
    export envelope) so that metadata fields like exported_at and exported_by
    can be read and displayed before verification without invalidating the
    hash. sort_keys=True ensures the serialisation is deterministic regardless
    of the Python dict insertion order on the exporting machine.

    Args:
        data_dict: A dictionary to checksum. Must be JSON-serialisable.

    Returns:
        str: Lowercase hex-encoded SHA-256 digest of the canonical JSON.

    Raises:
        TypeError: If data_dict contains values that cannot be serialised
                   to JSON (e.g. datetime objects, custom classes).
    """
    # sort_keys=True and separators without trailing spaces give a canonical,
    # whitespace-free representation that is identical on every platform.
    canonical = json.dumps(data_dict, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def fetch_mitre_techniques():
    """Downloads the MITRE ATT&CK Enterprise technique list from the official CTI feed.

    Feed format — STIX 2.0:
    The MITRE CTI repository publishes ATT&CK data in STIX 2.0 (Structured
    Threat Information eXpression) format. A STIX bundle is a JSON object
    with a top-level "objects" array containing heterogeneous records of
    different types: "attack-pattern" (techniques), "course-of-action"
    (mitigations), "intrusion-set" (groups), "malware", "tool",
    "relationship", and others. This function extracts only "attack-pattern"
    objects, which correspond to ATT&CK techniques and sub-techniques.

    Why we filter deprecated and revoked techniques:
    MITRE regularly deprecates techniques that have been superseded or
    reclassified, and revokes techniques that were created in error or
    merged into others. Including them would pollute the database with
    technique IDs that no longer appear in any ATT&CK documentation,
    confuse analysts searching for them, and cause false positives in SIEM
    correlation rules. The flags used are:
        x_mitre_deprecated: True  — technique has been deprecated by MITRE
        revoked: True             — technique has been formally revoked

    Why first sentence only for description:
    ATT&CK technique descriptions are written for human reading and can be
    several paragraphs long (sometimes 500+ words). Storing the full text
    would make the database row very wide and the import summary output
    unreadable. The first sentence provides a concise, self-contained
    summary that retains the essential meaning while staying under a
    practical VARCHAR length for most database schemas. Analysts who need
    the full description can reference the ATT&CK website using the
    technique_id.

    Feed size and timeout:
    The enterprise-attack.json bundle is approximately 10 MB and contains
    700+ techniques. A timeout of 30 seconds is used to accommodate slow
    connections without hanging indefinitely. The download is a single
    HTTPS GET to raw.githubusercontent.com — no authentication required.

    Args:
        None

    Returns:
        list of dict: Each dict contains:
            technique_id   — ATT&CK ID, e.g. "T1566.001"
            technique_name — Human-readable technique name
            tactic         — Tactic name(s), title-cased, joined with " / "
                             if a technique spans multiple tactics
            description    — First sentence of the technique description,
                             or empty string if no description is present
        Returns an empty list if the download, parsing, or extraction fails.
    """
    print("Downloading MITRE ATT&CK feed from GitHub...")

    try:
        response = requests.get(MITRE_CTI_URL, timeout=30)
        response.raise_for_status()
        bundle = response.json()
    except Exception as e:
        print(f"ERROR: Could not download MITRE feed ({type(e).__name__}).")
        return []

    # The STIX bundle wraps everything in a top-level "objects" array
    objects = bundle.get("objects", [])
    if not isinstance(objects, list):
        print("ERROR: Unexpected MITRE feed format — 'objects' is not a list.")
        return []

    techniques = []

    for obj in objects:
        if not isinstance(obj, dict):
            continue

        # Only process ATT&CK technique objects
        if obj.get("type") != "attack-pattern":
            continue

        # Skip deprecated and revoked entries — they no longer appear in
        # official ATT&CK documentation and would mislead analysts
        if obj.get("x_mitre_deprecated") is True:
            continue
        if obj.get("revoked") is True:
            continue

        # --- Extract technique_id from external_references ---
        # The ATT&CK ID (e.g. "T1566.001") is stored in the external_references
        # list, in the entry where source_name == "mitre-attack".
        technique_id = ""
        external_refs = obj.get("external_references", [])
        if isinstance(external_refs, list):
            for ref in external_refs:
                if not isinstance(ref, dict):
                    continue
                if ref.get("source_name") == "mitre-attack":
                    raw_id = ref.get("external_id", "")
                    if isinstance(raw_id, str):
                        # Strip control characters before storing
                        technique_id = re.sub(r'[\x00-\x1f\x7f]', '', raw_id.strip())
                    break

        # Technique ID is mandatory — skip the record if absent
        if not technique_id:
            continue

        # --- Extract technique_name ---
        technique_name = obj.get("name", "")
        if not isinstance(technique_name, str):
            technique_name = ""
        technique_name = re.sub(r'[\x00-\x1f\x7f]', '', technique_name.strip())

        # --- Extract tactic(s) from kill_chain_phases ---
        # A technique can belong to multiple ATT&CK tactics. We collect all
        # phase_name values where kill_chain_name == "mitre-attack", convert
        # the hyphenated phase names to title case (e.g. "initial-access" →
        # "Initial Access"), then join multiple tactics with " / ".
        tactic_names = []
        kill_chain_phases = obj.get("kill_chain_phases", [])
        if isinstance(kill_chain_phases, list):
            for phase in kill_chain_phases:
                if not isinstance(phase, dict):
                    continue
                if phase.get("kill_chain_name") != "mitre-attack":
                    continue
                phase_name = phase.get("phase_name", "")
                if isinstance(phase_name, str) and phase_name.strip():
                    # "initial-access" → "Initial Access"
                    readable = phase_name.strip().replace("-", " ").title()
                    readable = re.sub(r'[\x00-\x1f\x7f]', '', readable)
                    if readable:
                        tactic_names.append(readable)

        tactic = " / ".join(tactic_names) if tactic_names else "Unknown"

        # --- Extract description — first sentence only ---
        raw_desc = obj.get("description", "")
        if not isinstance(raw_desc, str):
            raw_desc = ""
        # Split on ". " to isolate the first sentence, then strip any
        # trailing period so the stored value is clean and consistent.
        first_sentence = raw_desc.split(". ")[0].strip()
        description = re.sub(r'[\x00-\x1f\x7f]', '', first_sentence)

        techniques.append({
            "technique_id":   technique_id,
            "technique_name": technique_name,
            "tactic":         tactic,
            "description":    description,
        })

    print(f"Extracted {len(techniques)} active techniques from MITRE ATT&CK feed.")
    return techniques


# ---------------------------------------------------------------------------
# Export
# ---------------------------------------------------------------------------

def do_export(output_path):
    """Exports SENTINEL reference data to a JSON file for air-gap transfer.

    Air-gap export/import workflow:
    SENTINEL is designed to run on machines that may have no internet access
    (air-gapped SOC workstations, isolated analysis VMs). Reference data such
    as MITRE ATT&CK technique definitions must still be kept current. The
    export/import workflow solves this without compromising the air-gap:

        Online machine (internet access):
            python sentinel_update.py --export
            → Queries APIs (future v0.6) or packages static data into a
              signed JSON file: sentinel_export.json

        Transfer:
            The analyst copies sentinel_export.json to removable media
            (USB, encrypted drive) and carries it to the air-gapped machine.

        Air-gapped machine (no internet):
            python sentinel_update.py --import sentinel_export.json
            → Verifies the SHA-256 checksum, then writes data to MySQL.
              No external connection is made.

    This version (v0.5) exports static MITRE technique definitions only.
    IP reputation feeds and domain block-lists are planned for v0.6.

    The export file structure:
        exported_at   — ISO 8601 UTC timestamp for freshness auditing
        exported_by   — tool identity string for version tracking
        checksum      — SHA-256 of the "data" sub-dict for integrity verification
        data          — the actual reference data payload

    Args:
        output_path: File path (str) to write the JSON export to.
                     Will be created or overwritten. The caller is responsible
                     for ensuring the path is writable and in an appropriate
                     location.

    Returns:
        None
    """
    # --- Input validation ---
    if not isinstance(output_path, str):
        output_path = str(output_path)
    output_path = output_path.strip()
    if not output_path:
        print("Export error: output path cannot be empty.")
        return

    if not require_confirm(
        "This export will connect to:\n"
        "  - raw.githubusercontent.com\n"
        "    (MITRE ATT&CK CTI feed ~10MB)\n"
        " No other external connections."
    ):
        print("Export cancelled.")
        return

    # --- Fetch live MITRE ATT&CK data ---
    mitre_techniques = fetch_mitre_techniques()
    if not mitre_techniques:
        print("ERROR: Could not fetch MITRE data. Export cancelled.")
        return

    # Build the data payload from the live fetch result
    data = {
        "mitre_techniques": mitre_techniques,
    }

    checksum = compute_checksum(data)

    export_doc = {
        "exported_at": datetime.now(UTC).isoformat(),
        "exported_by": "sentinel_update.py v0.5",
        "checksum":    checksum,
        "data":        data,
    }

    try:
        with open(output_path, "w", encoding="utf-8") as fh:
            json.dump(export_doc, fh, indent=2)
    except Exception as e:
        print(f"Export failed ({type(e).__name__}): could not write to '{output_path}'.")
        return

    technique_count = len(mitre_techniques)
    print(f"\n✅ Export complete → {output_path}")
    print(f"   Techniques exported : {technique_count}")
    print(f"   Exported at         : {export_doc['exported_at']}")
    print(f"   SHA-256 checksum    : {checksum}")
    print()
    print("Transfer this file to the air-gapped machine and run:")
    print(f"   python sentinel_update.py --import {output_path}")


# ---------------------------------------------------------------------------
# Import
# ---------------------------------------------------------------------------

def do_import(input_path):
    """Imports SENTINEL reference data from a JSON export file into MySQL.

    Reads the export file produced by do_export(), verifies its SHA-256
    checksum, then writes the contained reference data to the local MySQL
    database using db_connect() from email_forensics.py. No external network
    connection is made — the only outbound call is to localhost MySQL.

    Integrity verification:
    Before a single row is written, the function recomputes the SHA-256
    checksum of the "data" sub-dict and compares it to the checksum stored
    in the export envelope. A mismatch aborts the import immediately with a
    clear error message. This catches both accidental file corruption during
    transfer and any deliberate modification of the payload.

    The analyst is shown the export timestamp before being asked to confirm,
    so they can judge whether the data is fresh enough for their needs before
    committing to the database write.

    Database operation:
    Each MITRE technique is inserted with INSERT IGNORE, which silently skips
    rows whose primary key (technique_id) already exists in the table. This
    makes the import idempotent — running it twice produces the same result
    as running it once — and avoids duplicate-key errors when refreshing data.

    Args:
        input_path: File path (str) of the JSON export file to read.

    Returns:
        None
    """
    # --- Input validation ---
    if not isinstance(input_path, str):
        input_path = str(input_path)
    input_path = input_path.strip()
    if not input_path:
        print("Import error: input path cannot be empty.")
        return

    if not os.path.isfile(input_path):
        print(f"Import error: file not found: '{input_path}'")
        return

    # --- Read and parse ---
    try:
        with open(input_path, "r", encoding="utf-8") as fh:
            export_doc = json.load(fh)
    except Exception as e:
        print(f"Import failed ({type(e).__name__}): could not read '{input_path}'.")
        return

    # --- Validate required top-level fields ---
    required_fields = ["exported_at", "exported_by", "checksum", "data"]
    for field in required_fields:
        if field not in export_doc:
            print(f"Import error: export file is missing required field '{field}'. Aborting.")
            return

    exported_at  = export_doc.get("exported_at",  "unknown")
    stored_checksum = export_doc.get("checksum",  "")
    data         = export_doc.get("data",         {})

    if not isinstance(data, dict):
        print("Import error: 'data' field is not a dictionary. Aborting.")
        return

    # --- Checksum verification ---
    computed_checksum = compute_checksum(data)
    if computed_checksum != stored_checksum:
        print("❌ CHECKSUM MISMATCH — import aborted.")
        print(f"   Stored  : {stored_checksum}")
        print(f"   Computed: {computed_checksum}")
        print("The export file may have been corrupted or tampered with.")
        return

    print(f"✅ Checksum verified: {computed_checksum}")
    print(f"   Export timestamp  : {exported_at}")

    if not require_confirm(
        f"This will populate sentinel_db with data exported on {exported_at}.\n"
        " Checksum verified. No external connections — localhost MySQL only."
    ):
        print("Import cancelled.")
        return

    # --- Connect to database ---
    try:
        # Import db_connect from email_forensics, which lives in the same directory.
        # sys.path manipulation is scoped to this block so it does not pollute the
        # global path for any other imports.
        if _script_dir not in sys.path:
            sys.path.insert(0, _script_dir)
        from email_forensics import db_connect
        conn = db_connect()
    except Exception as e:
        print(f"Import failed ({type(e).__name__}): could not connect to database.")
        print("Check DB_HOST, DB_PORT, DB_NAME, DB_USER, DB_PASSWORD in your .env file.")
        return

    # --- Insert MITRE techniques ---
    mitre_techniques = data.get("mitre_techniques", [])
    if not isinstance(mitre_techniques, list):
        mitre_techniques = []

    inserted = 0
    skipped  = 0

    try:
        cursor = conn.cursor()

        sql = (
            "INSERT IGNORE INTO mitre_techniques "
            "  (technique_id, technique_name, tactic, description) "
            "VALUES (%s, %s, %s, %s)"
        )

        for entry in mitre_techniques:
            # Validate each record is a dict with the expected string fields
            if not isinstance(entry, dict):
                print(f"  ⚠️  Skipping non-dict entry: {type(entry).__name__}")
                skipped += 1
                continue

            technique_id   = entry.get("technique_id",   "")
            technique_name = entry.get("technique_name", "")
            tactic         = entry.get("tactic",         "")
            description    = entry.get("description",    "")

            # Coerce all fields to str and strip control characters —
            # same sanitisation pattern used throughout email_forensics.py
            import re as _re
            def _clean(val):
                if not isinstance(val, str):
                    val = str(val)
                return _re.sub(r'[\x00-\x1f\x7f]', '', val.strip())

            technique_id   = _clean(technique_id)
            technique_name = _clean(technique_name)
            tactic         = _clean(tactic)
            description    = _clean(description)

            if not technique_id:
                print("  ⚠️  Skipping entry with empty technique_id.")
                skipped += 1
                continue

            try:
                cursor.execute(sql, (technique_id, technique_name, tactic, description))
                if cursor.rowcount == 1:
                    print(f"  ✅ Inserted : {technique_id} — {technique_name}")
                    inserted += 1
                else:
                    print(f"  ⏭️  Skipped  : {technique_id} — already exists")
                    skipped += 1
            except Exception as e:
                print(f"  ❌ Failed   : {technique_id} ({type(e).__name__}) — skipping row.")
                skipped += 1

        conn.commit()
        cursor.close()

    except Exception as e:
        print(f"Import failed ({type(e).__name__}): database error during insert.")
        try:
            conn.rollback()
        except Exception:
            pass
        return
    finally:
        try:
            conn.close()
        except Exception:
            pass

    print()
    print(f"✅ Import complete — {inserted} inserted, {skipped} skipped.")


# ---------------------------------------------------------------------------
# Menu
# ---------------------------------------------------------------------------

def show_menu():
    """Prints the interactive maintenance menu to stdout.

    Displays all available options with brief context so an analyst who
    runs the tool without arguments immediately understands what each
    mode does and which machine it should be run on.

    Returns:
        None
    """
    print()
    print("SENTINEL — Maintenance Tool")
    print("===========================")
    print("1. Export data  (run on online machine)")
    print("2. Import data  (run on air-gap machine)")
    print("3. Exit")
    print()


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    """Parses command-line arguments and dispatches to the appropriate mode.

    Three modes are supported:

        --export
            Packages SENTINEL reference data into a JSON export file.
            Intended to be run on an internet-connected machine. In v0.5
            the data is static; v0.6 will add live API queries.

        --import <path>
            Reads a JSON export file, verifies its checksum, and populates
            the local MySQL database. Intended for air-gapped machines.
            If no path is supplied after --import, defaults to
            "sentinel_export.json" in the current directory.

        (no arguments)
            Presents an interactive numbered menu that loops until the
            analyst chooses Exit. Useful for interactive maintenance
            sessions where the analyst may want to run both export and
            import in sequence.

    Args:
        None — reads sys.argv directly.

    Returns:
        None
    """
    args = sys.argv[1:]

    if args and args[0] == "--export":
        do_export("sentinel_export.json")
        return

    if args and args[0] == "--import":
        # Accept an optional path argument after --import; default if absent
        input_path = args[1] if len(args) >= 2 else "sentinel_export.json"
        do_import(input_path)
        return

    # --- Interactive menu loop ---
    while True:
        show_menu()
        try:
            choice = input("Select option (1-3): ").strip()
        except (EOFError, KeyboardInterrupt):
            # Graceful exit on Ctrl-C or piped input exhaustion
            print("\nExiting.")
            break

        if choice == "1":
            do_export("sentinel_export.json")
        elif choice == "2":
            do_import("sentinel_export.json")
        elif choice == "3":
            print("Exiting.")
            break
        else:
            print("Invalid option.")


if __name__ == "__main__":
    main()
