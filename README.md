
# Assignment 2 - Wireless Protocol Investigation Lab

## Wireless and Mobile Network Security  
### Track 2: WPA2/WPA3/OWE Handshake Autopsy

## Group Members

- Ron Amsalem - 326029600
- Fadi Nujedat - 214766339

## Project Overview

This repository contains the submission for Assignment 2 in the Wireless and Mobile Network Security course.

The assignment focuses on evidence-based 802.11 protocol investigation. Instead of building an attack tool, the goal is to capture real wireless traffic, analyze protocol fields, and prove a precise security claim using packet-level evidence.

Our selected track is:

**Track 2: WPA2/WPA3/OWE Handshake Autopsy**

In this project, we compare the visible connection sequence of:

- WPA2-Personal / PSK
- WPA3-Personal / SAE-H2E

The experiment was performed in a mobile hotspot scenario using the same physical iPhone Personal Hotspot once in WPA2 mode and once in WPA3 mode.

---

## Investigative Claim

We demonstrate that when the same physical iPhone Hotspot is used once in WPA2-Personal/PSK mode and once in WPA3-Personal/SAE-H2E mode, the visible password-based authentication and key-establishment sequence changes at the 802.11 frame level.

In the WPA2-Personal capture, the client performs:

```text
Beacon / RSN
-> Open System Authentication
-> Association Request / Response
-> EAPOL 4-Way Handshake
-> Protected traffic
````

In the WPA3-Personal/SAE-H2E capture, the client performs:

```text
Beacon / RSN
-> SAE Commit / SAE Confirm
-> Association Request / Response
-> EAPOL 4-Way Handshake
-> Protected frames
```

This shows that WPA3-SAE adds an earlier password-authenticated exchange before Association and before the EAPOL 4-Way Handshake.

The investigation is based only on passive packet captures. We do not decrypt traffic, recover the Wi-Fi password, recover PMK/PTK/GTK values, inject packets, or perform any active attack.

---

## Lab Setup

### Access Point

* Device: iPhone Personal Hotspot
* SSID: `iPhone_Lab`
* Tested modes:

  * WPA2-Personal / PSK
  * WPA3-Personal / SAE-H2E

### Client Device

* Device: Windows laptop
* Wireless adapter: Intel(R) Wi-Fi 6E AX211 160MHz


### Capture Device

* Capture OS: DragonOS Linux VM
* Virtualization: Oracle VirtualBox
* Capture adapter: USB Wi-Fi monitor adapter
* Monitor-mode interface: `wlxe84e06aed7ca`

### Analysis Tools

* Wireshark
* TShark
* Python 3
* tcpdump
* iw
* iwconfig
* Windows `netsh wlan show interfaces`

---
## Submitted Files

### Report

The final report is located in:

```text
report/Assignment_2.pdf
```

The report includes:

* Title page
* Investigation goal
* Original claim
* Threat model
* Evidence plan
* Controlled Wi-Fi lab setup
* Experiment design
* WPA2 packet analysis
* WPA3 packet analysis
* Parser output
* WPA2/WPA3 comparison
* Protocol sequence diagrams
* Claim-to-evidence evaluation
* Required Track 2 security-analysis questions
* Limitations
* Ethics and authorized scope
* References

### Packet Captures

The raw packet captures are located in:

```text
captures/WPA2.pcapng
captures/WPA3.pcapng
```

The examiner can open these PCAPNG files in Wireshark and verify the frame numbers cited in the report.

### Parser Scripts

The analysis scripts are located in:

```text
wpa2/analyze_wpa2.py
wpa3/analyze_wpa3.py
```

The scripts use TShark to extract relevant 802.11, RSN, Authentication, Association, EAPOL, SAE, and protected-frame fields.

### Parser Output Files

The generated output files are located in:

```text
outputs/
```

Each parser produces:

* A full CSV with all extracted rows
* An evidence CSV with selected important frames
* A summary text file used in the report

---


## Main WPA2 Evidence

The WPA2 capture shows the following selected sequence:

```text
Beacon / RSN
-> Open System Authentication
-> Association Request / Response
-> EAPOL Message 1
-> EAPOL Message 2
-> EAPOL Message 3
-> EAPOL Message 4
-> Protected QoS Data
```

Important WPA2 evidence frames include:

| Stage                   | Frame |
| ----------------------- | ----- |
| Beacon / RSN            | 1363  |
| Authentication Request  | 1364  |
| Authentication Response | 1366  |
| Association Request     | 1368  |
| Association Response    | 1370  |
| EAPOL Message 1         | 1374  |
| EAPOL Message 2         | 1376  |
| EAPOL Message 3         | 1378  |
| EAPOL Message 4         | 1382  |
| Protected frame         | 1394  |

The WPA2 capture shows that the client uses Open System Authentication before Association. The meaningful proof of compatible key material occurs later through the MIC-protected EAPOL 4-Way Handshake.

---

## Main WPA3 Evidence

The WPA3 capture shows the following selected sequence:

```text
Beacon / RSN
-> SAE Commit
-> SAE Confirm
-> Association Request / Response
-> EAPOL Message 1
-> EAPOL Message 2
-> EAPOL Message 3
-> EAPOL Message 4
-> Protected frame
```

Important WPA3 evidence frames include:

| Stage                | Frame |
| -------------------- | ----- |
| Beacon / RSN         | 1     |
| SAE Commit           | 181   |
| SAE Confirm          | 186   |
| Association Request  | 1809  |
| Association Response | 1811  |
| EAPOL Message 1      | 1813  |
| EAPOL Message 2      | 1815  |
| EAPOL Message 3      | 1818  |
| EAPOL Message 4      | 1820  |
| Protected frame      | 1822  |

The WPA3 capture shows that SAE Commit and SAE Confirm occur before Association and before the EAPOL 4-Way Handshake.

---

## Fields Extracted by the Parsers

The scripts extract fields such as:

* Frame number
* Relative timestamp
* Frame type and subtype
* Transmitter address
* Receiver address
* Source address
* Destination address
* BSSID
* SSID
* RSN version
* AKM suite
* Cipher suite
* Authentication algorithm
* Authentication sequence
* Status code
* SAE message type
* SAE group
* SAE scalar presence
* SAE finite field element presence
* EAPOL message number
* ANonce / SNonce role
* Replay counter
* Key ACK flag
* Key MIC flag
* Install flag
* Secure flag
* Protected-frame flag

---

## Security Analysis Summary

The packet evidence supports the following conclusions:

1. WPA2-Personal uses Open System Authentication before Association.
2. WPA3-Personal/SAE-H2E uses SAE Commit and SAE Confirm before Association.
3. Both WPA2 and WPA3 still use the EAPOL 4-Way Handshake after Association.
4. ANonce appears in EAPOL Message 1.
5. SNonce appears in EAPOL Message 2.
6. MIC fields provide evidence of possession of compatible key material.
7. Replay counters help track handshake freshness and message ordering.
8. Protected frames appear after key establishment.
9. A passive monitor can observe protocol metadata.
10. A passive monitor cannot recover the Wi-Fi password, PMK, PTK, GTK, or decrypted payload content.

---
## Limitations

The results are limited to the specific controlled lab environment:

* One iPhone Personal Hotspot
* One Windows client
* One USB monitor-mode adapter
* DragonOS inside VirtualBox
* Two selected captures: WPA2 and WPA3
* One coherent connection sequence selected from each capture

Other APs, clients, drivers, operating systems, or Wi-Fi configurations may show different timing, retransmissions, optional fields, or implementation-specific behavior.

The capture was passive. Missing frames may be caused by channel switching, driver behavior, VM/USB overhead, interference, or frames transmitted before the monitor interface was ready.

---

## Ethical Scope

All experiments were performed only on devices and networks owned by the group or used with permission.

The capture was limited to the controlled lab SSID, BSSID, and client MAC address. Any unrelated traffic that appeared during capture was treated as out of scope and was not used in the analysis.

No attempt was made to recover credentials, decrypt user data, disrupt third-party networks, or analyze traffic from uninvolved devices.

---
