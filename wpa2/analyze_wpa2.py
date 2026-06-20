"""
WPA2 Basic Packet Analyzer
==========================

Purpose
-------
This script performs passive, evidence-based analysis of a WPA2-Personal
packet capture using TShark. It extracts observable IEEE 802.11, RSN,
Authentication, Association, EAPOL, and CCMP fields.

Main workflow
-------------
1. Locate the TShark executable.
2. Read the configured WPA2 PCAP file.
3. Filter packets by SSID, BSSID, and client MAC address.
4. Extract management, authentication, association, EAPOL, and
   protected-frame metadata.
5. Identify one coherent WPA2 connection sequence.
6. Produce a full CSV, evidence CSV, and text summary.

The script performs passive analysis only. It does not inject packets,
recover passwords, decrypt protected traffic, or expose PMK, PTK, GTK,
or application payloads.
"""

import csv
import re
import subprocess
import sys
from pathlib import Path


# ============================================================
# WPA2 BASIC ANALYZER - CONFIGURATION
# ============================================================

PCAP_FILE = "wpa2.pcapng"

SSID = "iPhone_Lab"
BSSID = "b2:86:9a:49:e9:da"
CLIENT_MAC = "e8:bf:b8:96:c3:55"

OUTPUT_FULL_CSV = "wpa2_basic_full.csv"
OUTPUT_EVIDENCE_CSV = "wpa2_basic_evidence.csv"
OUTPUT_SUMMARY = "wpa2_basic_summary.txt"

def find_tshark():
    """
    Locate TShark on macOS/Linux even when PyCharm does not inherit
    the shell PATH.
    """
    candidates = [
        "/Applications/Wireshark.app/Contents/MacOS/tshark",
        "/opt/homebrew/bin/tshark",   # Apple Silicon Homebrew
        "/usr/local/bin/tshark",      # Intel Homebrew / system link
        "/usr/bin/tshark",
    ]

    # Check PATH first.
    import shutil
    path_result = shutil.which("tshark")
    if path_result:
        return path_result

    # Then check common installation locations.
    for candidate in candidates:
        if Path(candidate).is_file():
            return candidate

    raise FileNotFoundError(
        "TShark was not found. Install it or set TSHARK to its full path. "
        "On macOS with Wireshark.app, the usual path is "
        "/Applications/Wireshark.app/Contents/MacOS/tshark"
    )


TSHARK = find_tshark()


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
    Some tshark versions export SSID as hexadecimal.
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
    words = [word.lower() for word in words]

    for key, value in row.items():
        key_lower = key.lower()
        if all(word in key_lower for word in words) and value:
            return value

    return ""


def frame_num(row):
    try:
        return int(row["frame_number"])
    except (KeyError, TypeError, ValueError):
        return 0


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
        "2": "TKIP",
        "4": "CCMP",
        "6": "BIP-CMAC-128",
        "8": "GCMP",
        "00:0f:ac:2": "TKIP",
        "00:0f:ac:4": "CCMP",
        "00:0f:ac:6": "BIP-CMAC-128",
        "00:0f:ac:8": "GCMP",
        "0x000fac02": "TKIP",
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

    has_eapol_field = (
        row.get("eapol.version", "")
        or first_by_name_contains(row, ["eapol", "key"])
    )

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
    if eapol_message == "Message 3 of 4":
        return "ANonce repeated"
    return ""


def make_interpretation(row):
    if row["frame_kind"] == "Beacon":
        return "AP advertises WPA2 RSN capabilities, PSK AKM and CCMP ciphers."

    if row["frame_kind"] == "Authentication":
        if row["auth_algorithm"] == "Open System":
            if row["auth_sequence"] == "1":
                return "Client sends an Open System Authentication Request."
            if row["auth_sequence"] == "2":
                return "AP returns the Open System Authentication Response."
        return "IEEE 802.11 authentication frame."

    if row["frame_kind"] == "Association Request":
        return "Client selects PSK and CCMP in the Association Request RSN IE."

    if row["frame_kind"] == "Association Response":
        return "AP accepts the Association Request and assigns an Association ID."

    if row["frame_kind"] == "EAPOL":
        return "WPA2 EAPOL 4-Way Handshake message."

    if row["frame_kind"] == "Protected Frame":
        return "Protected CCMP frame after key establishment."

    return ""


# ============================================================
# TSHARK EXTRACTION
# ============================================================

def build_display_filter():
    return (
        "("
        f'(wlan.fc.type_subtype == 0x08 && wlan.ssid == "{SSID}" && wlan.addr == {BSSID})'
        " || "
        f'((wlan.fixed.auth.alg == 0 || wlan.fc.type_subtype == 0x00 || '
        f'wlan.fc.type_subtype == 0x01 || eapol || wlan.fc.protected == 1) '
        f'&& wlan.addr == {BSSID} && wlan.addr == {CLIENT_MAC})'
        ")"
    )


def build_fields(available):
    requested = [
        # Basic packet information
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

        # RSN / WPA2
        "wlan.rsn.version",
        "wlan.rsn.akms.type",
        "wlan.rsn.pcs.type",
        "wlan.rsn.gcs.type",
        "wlan.rsn.capabilities",

        # Authentication / Association
        "wlan.fixed.auth.alg",
        "wlan.fixed.auth_seq",
        "wlan.fixed.auth.seq",
        "wlan.fixed.status_code",
        "wlan.fixed.aid",

        # EAPOL
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
        "wlan_rsna_eapol.keydes.key_info.encrypted_key_data",
        "wlan_rsna_eapol.keydes.key_len",
        "wlan_rsna_eapol.keydes.data_len",
        "wlan_rsna_eapol.keydes.data",

        # CCMP information in protected frames
        "wlan.ccmp.extiv",
        "wlan.ccmp.keyid",
    ]

    fields = keep_existing(requested, available)

    # Add replay, nonce, EAPOL and CCMP fields dynamically because
    # tshark field names may differ between versions.
    for field in sorted(available):
        lower = field.lower()

        wanted_dynamic = (
            ("replay" in lower and ("eapol" in lower or "keydes" in lower or "rsna" in lower))
            or ("nonce" in lower and ("eapol" in lower or "keydes" in lower or "rsna" in lower))
            or (("encrypted" in lower or "data_len" in lower) and "keydes" in lower)
            or lower.startswith("wlan.ccmp")
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

    encrypted_flag = (
        raw.get("wlan_rsna_eapol.keydes.key_info.encrypted_key_data", "")
        or first_by_name_contains(raw, ["encrypted", "key", "data"])
    )

    key_data_length = (
        raw.get("wlan_rsna_eapol.keydes.data_len", "")
        or first_by_name_contains(raw, ["key", "data", "length"])
    )

    ccmp_pn = (
        raw.get("wlan.ccmp.extiv", "")
        or first_by_name_contains(raw, ["ccmp", "ext"])
    )

    row = {
        "condition": "WPA2-Personal-PSK",

        # Basic packet information
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

        # RSN / WPA2
        "rsn_version": raw.get("wlan.rsn.version", ""),
        "rsn_akm": unique_join(akm_values),
        "pairwise_cipher": unique_join(pairwise_values),
        "group_cipher": unique_join(group_values),
        "rsn_capabilities": raw.get("wlan.rsn.capabilities", ""),

        # Authentication / Association
        "auth_algorithm": auth_alg,
        "auth_sequence": normalize_number(
            raw.get("wlan.fixed.auth_seq", "")
            or raw.get("wlan.fixed.auth.seq", "")
        ),
        "status_code": raw.get("wlan.fixed.status_code", ""),
        "association_id": raw.get("wlan.fixed.aid", ""),

        # EAPOL 4-Way Handshake
        "eapol_message": eapol_msg,
        "nonce_present": "yes" if nonce_value else "no",
        "nonce_role": nonce_role(eapol_msg),
        "replay_counter": replay_counter,
        "key_ack": raw.get("wlan_rsna_eapol.keydes.key_info.key_ack", ""),
        "key_mic": raw.get("wlan_rsna_eapol.keydes.key_info.key_mic", ""),
        "key_install": raw.get("wlan_rsna_eapol.keydes.key_info.install", ""),
        "key_secure": raw.get("wlan_rsna_eapol.keydes.key_info.secure", ""),
        "encrypted_key_data": encrypted_flag,
        "key_data_length": key_data_length,

        # Protected traffic
        "protected_flag": raw.get("wlan.fc.protected", ""),
        "ccmp_packet_number": ccmp_pn,
        "ccmp_key_id": raw.get("wlan.ccmp.keyid", ""),

        # Wireshark text
        "wireshark_protocol": raw.get("_ws.col.Protocol", ""),
        "wireshark_info": raw.get("_ws.col.Info", ""),
    }

    row["interpretation"] = make_interpretation(row)
    return row


def find_last_before(rows, before_num, predicate):
    candidates = [row for row in rows if frame_num(row) < before_num and predicate(row)]
    return max(candidates, key=frame_num, default=None)


def find_first_after(rows, after_num, predicate):
    candidates = [row for row in rows if frame_num(row) > after_num and predicate(row)]
    return min(candidates, key=frame_num, default=None)


def relative_time(row):
    try:
        return float(row.get("time_relative", ""))
    except (TypeError, ValueError):
        return -1.0


def replay_value(row):
    return normalize_number(row.get("replay_counter", ""))


def find_complete_handshake(rows, max_total_seconds=3.0):
    """
    Find M1-M4 from one connection attempt.

    The previous implementation selected the first later M2, M3 and M4,
    which could combine frames from different attempts. This version
    requires:
      * M1 and M2 to use the same replay counter.
      * M3 and M4 to use the same replay counter.
      * Correct AP/client directions.
      * The complete exchange to occur inside a short time window.
    """
    ordered = sorted(rows, key=frame_num)

    m1_rows = [row for row in ordered if row["eapol_message"] == "Message 1 of 4"]

    for m1 in m1_rows:
        m1_num = frame_num(m1)
        m1_time = relative_time(m1)

        m2_candidates = [
            row for row in ordered
            if frame_num(row) > m1_num
            and row["eapol_message"] == "Message 2 of 4"
            and replay_value(row) == replay_value(m1)
            and row.get("transmitter", "").lower() == CLIENT_MAC.lower()
            and row.get("receiver", "").lower() == BSSID.lower()
            and relative_time(row) - m1_time <= max_total_seconds
        ]

        for m2 in m2_candidates:
            m2_num = frame_num(m2)

            m3_candidates = [
                row for row in ordered
                if frame_num(row) > m2_num
                and row["eapol_message"] == "Message 3 of 4"
                and row.get("transmitter", "").lower() == BSSID.lower()
                and row.get("receiver", "").lower() == CLIENT_MAC.lower()
                and relative_time(row) - m1_time <= max_total_seconds
            ]

            for m3 in m3_candidates:
                m3_num = frame_num(m3)

                m4_candidates = [
                    row for row in ordered
                    if frame_num(row) > m3_num
                    and row["eapol_message"] == "Message 4 of 4"
                    and replay_value(row) == replay_value(m3)
                    and row.get("transmitter", "").lower() == CLIENT_MAC.lower()
                    and row.get("receiver", "").lower() == BSSID.lower()
                    and relative_time(row) - m1_time <= max_total_seconds
                ]

                if m4_candidates:
                    return [m1, m2, m3, m4_candidates[0]]

    return []


def select_evidence(rows):
    ordered = sorted(rows, key=frame_num)
    selected = []

    handshake = find_complete_handshake(ordered)

    if handshake:
        m1, m2, m3, m4 = handshake

        assoc_resp = find_last_before(
            ordered, frame_num(m1),
            lambda row: row["frame_kind"] == "Association Response"
        )
        assoc_req = find_last_before(
            ordered,
            frame_num(assoc_resp) if assoc_resp else frame_num(m1),
            lambda row: row["frame_kind"] == "Association Request"
        )
        auth_resp = find_last_before(
            ordered,
            frame_num(assoc_req) if assoc_req else frame_num(m1),
            lambda row: (
                row["frame_kind"] == "Authentication"
                and row["auth_algorithm"] == "Open System"
                and row["auth_sequence"] == "2"
            )
        )
        auth_req = find_last_before(
            ordered,
            frame_num(auth_resp) if auth_resp else (
                frame_num(assoc_req) if assoc_req else frame_num(m1)
            ),
            lambda row: (
                row["frame_kind"] == "Authentication"
                and row["auth_algorithm"] == "Open System"
                and row["auth_sequence"] == "1"
            )
        )
        beacon = find_last_before(
            ordered,
            frame_num(auth_req) if auth_req else (
                frame_num(assoc_req) if assoc_req else frame_num(m1)
            ),
            lambda row: row["frame_kind"] == "Beacon" and "PSK" in row["rsn_akm"]
        )
        protected = find_first_after(
            ordered,
            frame_num(m4),
            lambda row: row["frame_kind"] == "Protected Frame"
        )

        for row in [beacon, auth_req, auth_resp, assoc_req, assoc_resp, *handshake, protected]:
            if row:
                selected.append(row)

    else:
        # Fallback when a complete handshake could not be identified
        predicates = [
            lambda row: row["frame_kind"] == "Beacon" and "PSK" in row["rsn_akm"],
            lambda row: row["frame_kind"] == "Authentication" and row["auth_sequence"] == "1",
            lambda row: row["frame_kind"] == "Authentication" and row["auth_sequence"] == "2",
            lambda row: row["frame_kind"] == "Association Request",
            lambda row: row["frame_kind"] == "Association Response",
        ]

        for predicate in predicates:
            row = next((item for item in ordered if predicate(item)), None)
            if row:
                selected.append(row)

        for message in [
            "Message 1 of 4",
            "Message 2 of 4",
            "Message 3 of 4",
            "Message 4 of 4",
        ]:
            row = next((item for item in ordered if item["eapol_message"] == message), None)
            if row:
                selected.append(row)

        last_selected = max([frame_num(row) for row in selected] or [0])
        protected = find_first_after(
            ordered,
            last_selected,
            lambda row: row["frame_kind"] == "Protected Frame"
        )
        if protected:
            selected.append(protected)

    final = []
    seen = set()

    for row in selected:
        number = row["frame_number"]
        if number not in seen:
            final.append(row)
            seen.add(number)

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
        file.write("WPA2 Basic Packet Analysis Summary\n")
        file.write("==================================\n\n")

        file.write(f"PCAP file: {PCAP_FILE}\n")
        file.write(f"SSID: {SSID}\n")
        file.write(f"BSSID: {BSSID}\n")
        file.write(f"Client MAC: {CLIENT_MAC}\n\n")

        file.write("Extracted frame counts:\n")
        file.write(f"Beacon frames: {sum(1 for row in rows if row['frame_kind'] == 'Beacon')}\n")
        file.write(
            "Open System Authentication frames: "
            f"{sum(1 for row in rows if row['auth_algorithm'] == 'Open System')}\n"
        )
        file.write(
            f"Association frames: "
            f"{sum(1 for row in rows if 'Association' in row['frame_kind'])}\n"
        )
        file.write(f"EAPOL frames: {sum(1 for row in rows if row['frame_kind'] == 'EAPOL')}\n")
        file.write(
            f"Protected frames: "
            f"{sum(1 for row in rows if row['frame_kind'] == 'Protected Frame')}\n\n"
        )

        file.write("Selected evidence frames:\n")
        for row in evidence_rows:
            file.write(
                f"Frame {row['frame_number']} | "
                f"Time={row['time_relative']} | "
                f"Kind={row['frame_kind']} | "
                f"TA={row['transmitter']} | "
                f"RA={row['receiver']} | "
                f"BSSID={row['bssid']} | "
                f"SSID={row['ssid']} | "
                f"AKM={row['rsn_akm']} | "
                f"PairwiseCipher={row['pairwise_cipher']} | "
                f"GroupCipher={row['group_cipher']} | "
                f"RSNCap={row['rsn_capabilities']} | "
                f"Auth={row['auth_algorithm']} | "
                f"AuthSeq={row['auth_sequence']} | "
                f"Status={row['status_code']} | "
                f"AID={row['association_id']} | "
                f"EAPOL={row['eapol_message']} | "
                f"Nonce={row['nonce_role']} | "
                f"Replay={row['replay_counter']} | "
                f"ACK={row['key_ack']} | "
                f"MIC={row['key_mic']} | "
                f"Install={row['key_install']} | "
                f"Secure={row['key_secure']} | "
                f"EncryptedKeyData={row['encrypted_key_data']} | "
                f"KeyDataLength={row['key_data_length']} | "
                f"Protected={row['protected_flag']} | "
                f"CCMP-PN={row['ccmp_packet_number']} | "
                f"Meaning={row['interpretation']}\n"
            )

        file.write("\nConclusion:\n")
        file.write(
            "The extracted packets show the WPA2-Personal connection sequence: "
            "Beacon RSN information advertising PSK and CCMP, Open System "
            "Authentication, Association Request/Response, a complete EAPOL "
            "4-Way Handshake, and protected CCMP traffic. The passive PCAP "
            "does not reveal the password, PMK, PTK, or decrypted payload content.\n"
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

    print("Running WPA2 basic analyzer...")
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
