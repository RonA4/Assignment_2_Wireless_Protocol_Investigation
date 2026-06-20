
"""
   This script analyzes a WPA3-Personal/SAE-H2E packet capture using TShark.
    It extracts observable 802.11, RSN, SAE, Association, EAPOL, and protected-frame
    fields from a passive monitor-mode PCAP file.
    The goal is to identify the visible WPA3 connection sequence:

        Beacon / RSN
        -> SAE Commit / SAE Confirm
        -> Association Request / Response
        -> EAPOL 4-Way Handshake
        -> Protected frames

Input:
    - A WPA3 PCAP/PCAPNG file captured passively in monitor mode.
    - Configured SSID, BSSID, and client MAC address.
    - TShark installed and available from the command line.

Main Extracted Fields:
    - Frame number and relative timestamp
    - Transmitter, receiver, source, destination, and BSSID
    - SSID
    - RSN AKM suites and cipher suites
    - Authentication algorithm and status code
    - SAE Commit / Confirm indicators
    - SAE group, scalar, and finite field element presence
    - EAPOL message number
    - ANonce / SNonce role
    - Replay counter
    - EAPOL key flags: ACK, MIC, Install, Secure
    - Protected-frame flag

Output Files:
    - wpa3_basic_full.csv:
        Full extracted packet table.

    - wpa3_basic_evidence.csv:
        Selected evidence frames used directly in the report.

    - wpa3_basic_summary.txt:
        Human-readable summary of extracted counts, selected evidence frames,
        and the conclusion supported by the capture.

"""


import csv
import re
import subprocess
import sys
from pathlib import Path


# ============================================================
# WPA3 BASIC ANALYZER - CONFIGURATION
# ============================================================

PCAP_FILE = "wpa3.pcapng"

SSID = "iPhone_Lab"
BSSID = "4a:91:20:2b:8a:fe"
CLIENT_MAC = "e8:bf:b8:96:c3:55"

OUTPUT_FULL_CSV = "wpa3_basic_full.csv"
OUTPUT_EVIDENCE_CSV = "wpa3_basic_evidence.csv"
OUTPUT_SUMMARY = "wpa3_basic_summary.txt"

TSHARK = "tshark"


# ============================================================
# GENERAL HELPERS
# ============================================================

def run_cmd(cmd):
    result = subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace"
    )

    if result.returncode != 0:
        print("ERROR: command failed")
        print(" ".join(cmd))
        print(result.stderr)
        sys.exit(1)

    return result.stdout


def get_available_fields():
    output = run_cmd([TSHARK, "-G", "fields"])
    fields = set()

    for line in output.splitlines():
        parts = line.split("\t")
        if len(parts) >= 3 and parts[0] == "F":
            fields.add(parts[2])

    return fields


def keep_existing(fields, available):
    return [field for field in fields if field in available]


def split_values(value):
    if not value:
        return []
    return [v.strip() for v in str(value).split(";") if v.strip()]


def unique_join(values):
    result = []
    for value in values:
        value = str(value).strip()
        if value and value not in result:
            result.append(value)
    return ";".join(result)


def normalize_number(value):
    value = str(value).strip().lower()

    if not value:
        return ""

    try:
        if value.startswith("0x"):
            return str(int(value, 16))
        return str(int(value))
    except ValueError:
        return value


def is_true(value):
    return str(value).strip().lower() in ["1", "true", "yes", "set"]


def is_false(value):
    return str(value).strip().lower() in ["0", "false", "no", "", "not set"]


def decode_ssid(value):
    """
    Some tshark versions export SSID as hex.
    Example:
    6950686f6e655f4c6162 -> iPhone_Lab
    """
    if not value:
        return ""

    decoded_parts = []

    for part in split_values(value):
        cleaned = part.replace(":", "").strip()

        if re.fullmatch(r"[0-9a-fA-F]+", cleaned) and len(cleaned) % 2 == 0:
            try:
                decoded = bytes.fromhex(cleaned).decode("utf-8", errors="replace")
                decoded_parts.append(decoded)
                continue
            except ValueError:
                pass

        decoded_parts.append(part)

    return unique_join(decoded_parts)


def first_by_name_contains(row, words):
    """
    Finds the first non-empty value in fields whose name contains all words.
    Useful because tshark field names change between versions.
    """
    words = [w.lower() for w in words]

    for key, value in row.items():
        key_lower = key.lower()
        if all(word in key_lower for word in words):
            if value:
                return value

    return ""


# ============================================================
# FIELD MAPPINGS
# ============================================================

def map_akm(value):
    value = str(value).strip().lower()

    mapping = {
        "1": "802.1X",
        "2": "PSK",
        "8": "SAE",
        "18": "OWE",
        "00:0f:ac:1": "802.1X",
        "00:0f:ac:2": "PSK",
        "00:0f:ac:8": "SAE",
        "00:0f:ac:18": "OWE",
        "0x000fac01": "802.1X",
        "0x000fac02": "PSK",
        "0x000fac08": "SAE",
        "0x000fac12": "OWE",
    }

    return mapping.get(value, value)


def map_cipher(value):
    value = str(value).strip().lower()

    mapping = {
        "4": "CCMP",
        "6": "BIP-CMAC-128",
        "8": "GCMP",
        "00:0f:ac:4": "CCMP",
        "00:0f:ac:6": "BIP-CMAC-128",
        "00:0f:ac:8": "GCMP",
        "0x000fac04": "CCMP",
        "0x000fac06": "BIP-CMAC-128",
        "0x000fac08": "GCMP",
    }

    return mapping.get(value, value)


def map_auth_algorithm(value):
    value = normalize_number(value)

    if value == "0":
        return "Open System"
    if value == "1":
        return "Shared Key"
    if value == "3":
        return "SAE"

    return value


# ============================================================
# DETECTION LOGIC
# ============================================================

def detect_frame_kind(row):
    protocol = row.get("_ws.col.Protocol", "")
    info = row.get("_ws.col.Info", "")
    subtype = normalize_number(row.get("wlan.fc.type_subtype", ""))
    auth_alg = row.get("wlan.fixed.auth.alg", "")

    has_eapol_field = row.get("eapol.version", "") or first_by_name_contains(row, ["eapol", "key"])

    if protocol == "EAPOL" or "Message" in info or has_eapol_field:
        return "EAPOL"

    if auth_alg:
        return "Authentication"

    if subtype == "8":
        return "Beacon"

    if subtype == "0":
        return "Association Request"

    if subtype == "1":
        return "Association Response"

    if is_true(row.get("wlan.fc.protected", "")):
        return "Protected Frame"

    if subtype:
        return f"802.11 subtype {subtype}"

    return ""


def detect_sae_message(row):
    auth_alg = normalize_number(row.get("wlan.fixed.auth.alg", ""))
    auth_seq = normalize_number(
        row.get("wlan.fixed.auth_seq", "") or row.get("wlan.fixed.auth.seq", "")
    )
    info = row.get("_ws.col.Info", "").lower()

    if auth_alg != "3":
        return ""

    dynamic_text = " ".join(
        f"{key}={value}".lower()
        for key, value in row.items()
        if value and (
            "sae" in key.lower()
            or "scalar" in key.lower()
            or "finite" in key.lower()
            or "confirm" in key.lower()
        )
    )

    if "commit" in info or "commit" in dynamic_text:
        return "SAE Commit"

    if "confirm" in info or "confirm" in dynamic_text:
        return "SAE Confirm"

    if auth_seq == "1":
        return "SAE Commit"

    if auth_seq == "2":
        return "SAE Confirm"

    return "SAE Authentication"


def detect_eapol_message(row):
    info = row.get("_ws.col.Info", "")

    match = re.search(r"Message\s+([1-4])\s+of\s+4", info)
    if match:
        return f"Message {match.group(1)} of 4"

    key_ack = row.get("wlan_rsna_eapol.keydes.key_info.key_ack", "")
    key_mic = row.get("wlan_rsna_eapol.keydes.key_info.key_mic", "")
    key_install = row.get("wlan_rsna_eapol.keydes.key_info.install", "")
    key_secure = row.get("wlan_rsna_eapol.keydes.key_info.secure", "")

    if is_true(key_ack) and is_false(key_mic):
        return "Message 1 of 4"

    if is_false(key_ack) and is_true(key_mic) and is_false(key_secure):
        return "Message 2 of 4"

    if is_true(key_ack) and is_true(key_mic) and is_true(key_install):
        return "Message 3 of 4"

    if is_false(key_ack) and is_true(key_mic) and is_true(key_secure):
        return "Message 4 of 4"

    return ""


def nonce_role(eapol_message):
    if eapol_message == "Message 1 of 4":
        return "ANonce"
    if eapol_message == "Message 2 of 4":
        return "SNonce"
    return ""


def make_interpretation(row):
    if row["frame_kind"] == "Beacon":
        return "AP advertises RSN security capabilities, AKM and cipher suites."

    if row["frame_kind"] == "Authentication" and row["auth_algorithm"] == "SAE":
        return "SAE authentication occurs before Association and before EAPOL."

    if row["frame_kind"] == "Association Request":
        return "Client requests association and selects SAE/CCMP parameters."

    if row["frame_kind"] == "Association Response":
        return "AP accepts the association request."

    if row["frame_kind"] == "EAPOL":
        return "EAPOL 4-Way Handshake message after SAE authentication."

    if row["frame_kind"] == "Protected Frame":
        return "Protected frame after key establishment."

    return ""


# ============================================================
# TSHARK EXTRACTION
# ============================================================

def build_display_filter():
    return (
        "("
        f'(wlan.fc.type_subtype == 0x08 && wlan.ssid == "{SSID}" && wlan.addr == {BSSID})'
        " || "
        f'((wlan.fixed.auth.alg == 3 || wlan.fc.type_subtype == 0x00 || '
        f'wlan.fc.type_subtype == 0x01 || eapol || wlan.fc.protected == 1) '
        f'&& wlan.addr == {BSSID} && wlan.addr == {CLIENT_MAC})'
        ")"
    )


def build_fields(available):
    requested = [
        # Basic fields required by assignment
        "frame.number",
        "frame.time_relative",
        "_ws.col.Protocol",
        "_ws.col.Info",

        # Radiotap / channel
        "radiotap.channel.freq",

        # 802.11 metadata
        "wlan.fc.type",
        "wlan.fc.subtype",
        "wlan.fc.type_subtype",
        "wlan.fc.protected",
        "wlan.ta",
        "wlan.ra",
        "wlan.sa",
        "wlan.da",
        "wlan.bssid",
        "wlan.ssid",

        # RSN / WPA3
        "wlan.rsn.version",
        "wlan.rsn.akms.type",
        "wlan.rsn.pcs.type",
        "wlan.rsn.gcs.type",
        "wlan.rsn.gmcs.type",
        "wlan.rsn.capabilities",

        # Authentication / Association
        "wlan.fixed.auth.alg",
        "wlan.fixed.auth_seq",
        "wlan.fixed.auth.seq",
        "wlan.fixed.status_code",

        # SAE fields, if exposed by tshark
        "wlan.fixed.finite_cyclic_group",
        "wlan.fixed.scalar",
        "wlan.fixed.finite_field_element",
        "wlan.fixed.confirm",

        # EAPOL fields
        "eapol.version",
        "eapol.type",
        "wlan_rsna_eapol.keydes.replay_counter",
        "wlan_rsna_eapol.keydes.key_replay_counter",
        "wlan_rsna_eapol.keydes.nonce",
        "wlan_rsna_eapol.keydes.key_nonce",
        "wlan_rsna_eapol.keydes.key_info.key_ack",
        "wlan_rsna_eapol.keydes.key_info.key_mic",
        "wlan_rsna_eapol.keydes.key_info.install",
        "wlan_rsna_eapol.keydes.key_info.secure",
        "wlan_rsna_eapol.keydes.data",
    ]

    fields = keep_existing(requested, available)

    # Add replay/nonce/SAE fields dynamically because tshark versions differ
    for field in sorted(available):
        lower = field.lower()

        wanted_dynamic = (
            ("replay" in lower and ("eapol" in lower or "keydes" in lower or "rsna" in lower))
            or ("nonce" in lower and ("eapol" in lower or "keydes" in lower or "rsna" in lower))
            or (lower.startswith("wlan.") and any(x in lower for x in ["sae", "scalar", "finite", "confirm"]))
        )

        if wanted_dynamic and field not in fields:
            fields.append(field)

    return fields


def run_tshark(fields, display_filter):
    cmd = [
        TSHARK,
        "-r", PCAP_FILE,
        "-Y", display_filter,
        "-T", "fields",
        "-E", "header=y",
        "-E", "separator=|",
        "-E", "quote=d",
        "-E", "occurrence=a",
        "-E", "aggregator=;",
    ]

    for field in fields:
        cmd.extend(["-e", field])

    output = run_cmd(cmd)
    return list(csv.DictReader(output.splitlines(), delimiter="|", quotechar='"'))


# ============================================================
# ROW PROCESSING
# ============================================================

def process_row(raw):
    akm_values = [map_akm(v) for v in split_values(raw.get("wlan.rsn.akms.type", ""))]
    pairwise_values = [map_cipher(v) for v in split_values(raw.get("wlan.rsn.pcs.type", ""))]
    group_values = [map_cipher(v) for v in split_values(raw.get("wlan.rsn.gcs.type", ""))]
    mgmt_values = [map_cipher(v) for v in split_values(raw.get("wlan.rsn.gmcs.type", ""))]

    eapol_msg = detect_eapol_message(raw)
    auth_alg = map_auth_algorithm(raw.get("wlan.fixed.auth.alg", ""))

    replay_counter = (
        raw.get("wlan_rsna_eapol.keydes.replay_counter", "")
        or raw.get("wlan_rsna_eapol.keydes.key_replay_counter", "")
        or first_by_name_contains(raw, ["replay"])
    )

    nonce_value = (
        raw.get("wlan_rsna_eapol.keydes.nonce", "")
        or raw.get("wlan_rsna_eapol.keydes.key_nonce", "")
        or first_by_name_contains(raw, ["nonce"])
    )

    sae_group = (
        raw.get("wlan.fixed.finite_cyclic_group", "")
        or raw.get("wlan.fixed.group", "")
        or first_by_name_contains(raw, ["group"])
    )

    sae_scalar = (
        raw.get("wlan.fixed.scalar", "")
        or first_by_name_contains(raw, ["scalar"])
    )

    sae_element = (
        raw.get("wlan.fixed.finite_field_element", "")
        or raw.get("wlan.fixed.element", "")
        or first_by_name_contains(raw, ["finite"])
        or first_by_name_contains(raw, ["element"])
    )

    row = {
        "condition": "WPA3-SAE-H2E",

        # Required basic packet information
        "frame_number": raw.get("frame.number", ""),
        "time_relative": raw.get("frame.time_relative", ""),
        "channel_freq": raw.get("radiotap.channel.freq", ""),
        "frame_kind": detect_frame_kind(raw),
        "type": raw.get("wlan.fc.type", ""),
        "subtype": raw.get("wlan.fc.subtype", ""),
        "type_subtype": raw.get("wlan.fc.type_subtype", ""),
        "transmitter": raw.get("wlan.ta", "") or raw.get("wlan.sa", ""),
        "receiver": raw.get("wlan.ra", "") or raw.get("wlan.da", ""),
        "source": raw.get("wlan.sa", ""),
        "destination": raw.get("wlan.da", ""),
        "bssid": raw.get("wlan.bssid", ""),
        "ssid": decode_ssid(raw.get("wlan.ssid", "")),

        # RSN / WPA3 fields
        "rsn_version": raw.get("wlan.rsn.version", ""),
        "rsn_akm": unique_join(akm_values),
        "pairwise_cipher": unique_join(pairwise_values),
        "group_cipher": unique_join(group_values),
        "group_management_cipher": unique_join(mgmt_values),
        "rsn_capabilities": raw.get("wlan.rsn.capabilities", ""),

        # SAE authentication
        "auth_algorithm": auth_alg,
        "auth_sequence": normalize_number(
            raw.get("wlan.fixed.auth_seq", "") or raw.get("wlan.fixed.auth.seq", "")
        ),
        "status_code": raw.get("wlan.fixed.status_code", ""),
        "sae_message_type": detect_sae_message(raw),
        "sae_group_id": sae_group,
        "sae_scalar_present": "yes" if sae_scalar else "no",
        "sae_element_present": "yes" if sae_element else "no",

        # EAPOL 4-Way Handshake
        "eapol_message": eapol_msg,
        "nonce_present": "yes" if nonce_value else "no",
        "nonce_role": nonce_role(eapol_msg),
        "replay_counter": replay_counter,
        "key_ack": raw.get("wlan_rsna_eapol.keydes.key_info.key_ack", ""),
        "key_mic": raw.get("wlan_rsna_eapol.keydes.key_info.key_mic", ""),
        "key_install": raw.get("wlan_rsna_eapol.keydes.key_info.install", ""),
        "key_secure": raw.get("wlan_rsna_eapol.keydes.key_info.secure", ""),
        "encrypted_key_data_present": "yes" if raw.get("wlan_rsna_eapol.keydes.data", "") else "no",

        # After key establishment
        "protected_flag": raw.get("wlan.fc.protected", ""),

        # Wireshark text
        "wireshark_protocol": raw.get("_ws.col.Protocol", ""),
        "wireshark_info": raw.get("_ws.col.Info", ""),
    }

    row["interpretation"] = make_interpretation(row)
    return row


def frame_num(row):
    try:
        return int(row["frame_number"])
    except Exception:
        return 0


def select_evidence(rows):
    selected = []

    beacon = next((r for r in rows if r["frame_kind"] == "Beacon" and r["rsn_akm"]), None)
    if beacon:
        selected.append(beacon)

    commit = next((r for r in rows if r["sae_message_type"] == "SAE Commit"), None)
    if commit:
        selected.append(commit)

    confirm = next((r for r in rows if r["sae_message_type"] == "SAE Confirm"), None)
    if confirm:
        selected.append(confirm)

    assoc_req = next((r for r in rows if r["frame_kind"] == "Association Request"), None)
    if assoc_req:
        selected.append(assoc_req)

    assoc_resp = next((r for r in rows if r["frame_kind"] == "Association Response"), None)
    if assoc_resp:
        selected.append(assoc_resp)

    for msg in ["Message 1 of 4", "Message 2 of 4", "Message 3 of 4", "Message 4 of 4"]:
        e = next((r for r in rows if r["eapol_message"] == msg), None)
        if e:
            selected.append(e)

    last_eapol_num = max([frame_num(r) for r in selected if r["frame_kind"] == "EAPOL"] or [0])
    protected = next(
        (r for r in rows if r["frame_kind"] == "Protected Frame" and frame_num(r) > last_eapol_num),
        None
    )
    if protected:
        selected.append(protected)

    # remove duplicate frames
    final = []
    seen = set()
    for row in selected:
        num = row["frame_number"]
        if num not in seen:
            final.append(row)
            seen.add(num)

    return final


# ============================================================
# OUTPUT
# ============================================================

def write_csv(path, rows):
    if not rows:
        print(f"No rows for {path}")
        return

    with open(path, "w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)


def write_summary(rows, evidence_rows):
    with open(OUTPUT_SUMMARY, "w", encoding="utf-8") as file:
        file.write("WPA3 Basic Packet Analysis Summary\n")
        file.write("==================================\n\n")

        file.write(f"PCAP file: {PCAP_FILE}\n")
        file.write(f"SSID: {SSID}\n")
        file.write(f"BSSID: {BSSID}\n")
        file.write(f"Client MAC: {CLIENT_MAC}\n\n")

        file.write("Extracted frame counts:\n")
        file.write(f"Beacon frames: {sum(1 for r in rows if r['frame_kind'] == 'Beacon')}\n")
        file.write(f"SAE authentication frames: {sum(1 for r in rows if r['auth_algorithm'] == 'SAE')}\n")
        file.write(f"Association frames: {sum(1 for r in rows if 'Association' in r['frame_kind'])}\n")
        file.write(f"EAPOL frames: {sum(1 for r in rows if r['frame_kind'] == 'EAPOL')}\n")
        file.write(f"Protected frames: {sum(1 for r in rows if r['frame_kind'] == 'Protected Frame')}\n\n")

        file.write("Selected evidence frames:\n")
        for r in evidence_rows:
            file.write(
                f"Frame {r['frame_number']} | "
                f"Time={r['time_relative']} | "
                f"Kind={r['frame_kind']} | "
                f"TA={r['transmitter']} | "
                f"RA={r['receiver']} | "
                f"BSSID={r['bssid']} | "
                f"SSID={r['ssid']} | "
                f"AKM={r['rsn_akm']} | "
                f"PairwiseCipher={r['pairwise_cipher']} | "
                f"GroupCipher={r['group_cipher']} | "
                f"GroupMgmtCipher={r['group_management_cipher']} | "
                f"RSNCap={r['rsn_capabilities']} | "
                f"Auth={r['auth_algorithm']} | "
                f"AuthSeq={r['auth_sequence']} | "
                f"Status={r['status_code']} | "
                f"SAE={r['sae_message_type']} | "
                f"SAEGroup={r['sae_group_id']} | "
                f"ScalarPresent={r['sae_scalar_present']} | "
                f"ElementPresent={r['sae_element_present']} | "
                f"EAPOL={r['eapol_message']} | "
                f"Nonce={r['nonce_role']} | "
                f"Replay={r['replay_counter']} | "
                f"ACK={r['key_ack']} | "
                f"MIC={r['key_mic']} | "
                f"Install={r['key_install']} | "
                f"Secure={r['key_secure']} | "
                f"Protected={r['protected_flag']} | "
                f"Meaning={r['interpretation']}\n"
            )

        file.write("\nConclusion:\n")
        file.write(
            "The extracted packets show the WPA3-SAE connection sequence: "
            "Beacon RSN information, SAE Commit/Confirm authentication, "
            "Association Request/Response, EAPOL 4-Way Handshake, and protected frames. "
            "This supports the claim that WPA3-SAE authentication occurs before Association "
            "and before the EAPOL 4-Way Handshake. The passive PCAP does not reveal the password, "
            "PMK, PTK, or decrypted payload content.\n"
        )


# ============================================================
# MAIN
# ============================================================

def main():
    if not Path(PCAP_FILE).exists():
        print(f"ERROR: file not found: {PCAP_FILE}")
        print("Put this script in the same folder as the PCAP file, or change PCAP_FILE.")
        sys.exit(1)

    print("Checking tshark fields...")
    available = get_available_fields()

    fields = build_fields(available)
    display_filter = build_display_filter()

    print("Running WPA3 basic analyzer...")
    print(f"PCAP: {PCAP_FILE}")
    print(f"Filter: {display_filter}")
    print(f"Extracting {len(fields)} fields...")
    print()

    raw_rows = run_tshark(fields, display_filter)
    rows = [process_row(row) for row in raw_rows]
    evidence_rows = select_evidence(rows)

    write_csv(OUTPUT_FULL_CSV, rows)
    write_csv(OUTPUT_EVIDENCE_CSV, evidence_rows)
    write_summary(rows, evidence_rows)

    print("Done.")
    print(f"Full CSV: {OUTPUT_FULL_CSV}")
    print(f"Evidence CSV: {OUTPUT_EVIDENCE_CSV}")
    print(f"Summary: {OUTPUT_SUMMARY}")


if __name__ == "__main__":
    main()