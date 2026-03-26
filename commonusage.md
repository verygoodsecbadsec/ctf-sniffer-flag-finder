# ctf-sniffer-flag-finder — Usage Examples

Practical walkthroughs for the most common CTF scenarios.

---

## Table of Contents

- [Quick start](#quick-start)
- [Scenario 1 — Live capture on a CTF network](#scenario-1--live-capture-on-a-ctf-network)
- [Scenario 2 — Analyze a challenge pcap file](#scenario-2--analyze-a-challenge-pcap-file)
- [Scenario 3 — Regex search for unknown flag format](#scenario-3--regex-search-for-unknown-flag-format)
- [Scenario 4 — Narrow capture with BPF filter](#scenario-4--narrow-capture-with-bpf-filter)
- [Scenario 5 — Export and re-analyze in Wireshark](#scenario-5--export-and-re-analyze-in-wireshark)
- [Scenario 6 — Interactive mode for multiple searches](#scenario-6--interactive-mode-for-multiple-searches)
- [Scenario 7 — Timed capture with auto-stop](#scenario-7--timed-capture-with-auto-stop)
- [Scenario 8 — Quiet mode for scripting](#scenario-8--quiet-mode-for-scripting)
- [Cheat sheet](#cheat-sheet)

---

## Quick Start

```bash
# On a live interface
sudo ./ctf-sniffer-flag-finder.sh -i eth0 -p "CTF{"

# On an existing pcap
./ctf-sniffer-flag-finder.sh -F challenge.pcap -p "CTF{"
```

---

## Scenario 1 — Live Capture on a CTF Network

**Situation:** You are on a CTF jeopardy or attack-defence network. Services are running and you want to catch any flag that crosses the wire.

```bash
sudo ./ctf-sniffer-flag-finder.sh -i eth0 -p "CTF{"
```

The script starts `tshark` on `eth0`, saves traffic to `capture_YYYYMMDD_HHMMSS.pcap`, and waits. Press `Ctrl+C` when you want to stop. The search runs automatically on the saved pcap.

**Expected output:**

```
[*] Interface: eth0
[*] Traffic will be saved to: capture_20240812_143022.pcap
[*] Starting tshark on eth0 (all traffic)
[*] Capturing... (Ctrl+C to stop)
^C
[*] Stopping capture...
[*] Capture saved to capture_20240812_143022.pcap
[*] String search: CTF{
[*] Found 2 matching packet(s):
34    TCP    10.0.0.5    10.0.0.1    4444    80
112   HTTP   10.0.0.5    10.0.0.1    4444    80
```

Open the capture in Wireshark to read the full flag payload:

```bash
wireshark capture_20240812_143022.pcap
```

Or use verbose mode to see payload fields directly in the terminal:

```bash
sudo ./ctf-sniffer-flag-finder.sh -i eth0 -p "CTF{" -v
```

---

## Scenario 2 — Analyze a Challenge pcap File

**Situation:** The CTF gives you a `.pcap` or `.pcapng` file as a forensics challenge. You need to find the flag inside it.

```bash
./ctf-sniffer-flag-finder.sh -F challenge.pcap -p "flag{"
```

No root required. The script reads the file and searches immediately.

**Trying multiple common flag formats:**

```bash
./ctf-sniffer-flag-finder.sh -F challenge.pcap -p "CTF{"
./ctf-sniffer-flag-finder.sh -F challenge.pcap -p "flag{"
./ctf-sniffer-flag-finder.sh -F challenge.pcap -p "FLAG{"
./ctf-sniffer-flag-finder.sh -F challenge.pcap -p "picoCTF{"
```

Or use interactive mode to try all of them without re-typing the file path each time — see [Scenario 6](#scenario-6--interactive-mode-for-multiple-searches).

**Verbose output to see the payload directly:**

```bash
./ctf-sniffer-flag-finder.sh -F challenge.pcap -p "CTF{" -v
```

```
[*] String search: CTF{
[*] Found 1 matching packet(s):
47   HTTP   192.168.1.10   192.168.1.1   52341   80   CTF{s0me_fl4g_here}
```

---

## Scenario 3 — Regex Search for Unknown Flag Format

**Situation:** You don't know the exact flag prefix, or the flag could appear in different casing. Use regex to cast a wider net.

```bash
./ctf-sniffer-flag-finder.sh -F challenge.pcap -r -p "(CTF|flag|FLAG)\{[A-Za-z0-9_!@#]+\}"
```

The `-r` flag enables Wireshark display filter regex (POSIX ERE). Character classes, alternation, and quantifiers all work.

**Other useful regex patterns:**

```bash
# Any hex string inside braces (common flag format)
-r -p "[a-fA-F0-9]{32}"

# Base64-looking string in a response
-r -p "Authorization: Basic [A-Za-z0-9+/]+=*"

# Flag with a numeric suffix
-r -p "CTF\{[a-z_]+[0-9]+\}"

# Any word that starts with "flag" case-insensitively
-r -p "[Ff][Ll][Aa][Gg]\{.*\}"
```

> **Note:** Wireshark regex is not PCRE. Lookaheads like `(?=...)` do not work. Test your pattern in Wireshark's display filter bar first if unsure.

---

## Scenario 4 — Narrow Capture with BPF Filter

**Situation:** You know the flag service runs on a specific port. Capturing all traffic wastes disk space and makes searching slower. Use a BPF filter to record only what matters.

```bash
# Only capture traffic on port 1337
sudo ./ctf-sniffer-flag-finder.sh -i eth0 -f "tcp port 1337" -p "CTF{"

# Only capture from a specific target machine
sudo ./ctf-sniffer-flag-finder.sh -i eth0 -f "host 10.0.0.5" -p "CTF{"

# Capture only HTTP traffic
sudo ./ctf-sniffer-flag-finder.sh -i eth0 -f "tcp port 80 or tcp port 8080" -p "CTF{"

# Capture only UDP (common in custom CTF services)
sudo ./ctf-sniffer-flag-finder.sh -i eth0 -f "udp" -p "flag{"
```

**Combining BPF filter with a timeout:**

```bash
# Watch port 1337 for exactly 2 minutes
sudo ./ctf-sniffer-flag-finder.sh -i eth0 -f "tcp port 1337" -t 120 -p "CTF{"
```

**Useful BPF filter reference:**

| Filter | Captures |
|--------|----------|
| `tcp port 80` | HTTP |
| `tcp port 443` | HTTPS (encrypted — flags won't be visible) |
| `host 10.0.0.5` | All traffic to/from one IP |
| `net 10.0.0.0/24` | All traffic on a subnet |
| `udp` | All UDP datagrams |
| `not arp` | Everything except ARP noise |
| `tcp portrange 1024-9999` | High port range (custom services) |

---

## Scenario 5 — Export and Re-analyze in Wireshark

**Situation:** You found matching packets and want to inspect the full conversation in Wireshark, or share the relevant subset with a teammate.

```bash
./ctf-sniffer-flag-finder.sh -F challenge.pcap -p "CTF{" -e matches.pcap
```

This writes only the packets that matched into `matches.pcap`. Open it in Wireshark:

```bash
wireshark matches.pcap
```

**Follow the TCP stream in Wireshark to read the full flag in context:**

1. Right-click a matching packet
2. Select `Follow → TCP Stream`
3. The full conversation appears as plaintext

**Re-run a second search on the exported file:**

```bash
# First pass — find packets containing the flag prefix
./ctf-sniffer-flag-finder.sh -F challenge.pcap -p "CTF{" -e pass1.pcap

# Second pass — narrow down to a specific protocol inside those packets
./ctf-sniffer-flag-finder.sh -F pass1.pcap -p "HTTP/1.1 200" -v
```

**Exporting during capture mode:**

```bash
sudo ./ctf-sniffer-flag-finder.sh -i eth0 -p "CTF{" -e live_flags.pcap
```

Both the full capture (`capture_*.pcap`) and the filtered export (`live_flags.pcap`) are saved.

---

## Scenario 6 — Interactive Mode for Multiple Searches

**Situation:** You have a large pcap and want to try several different patterns, flag formats, and regex searches without re-invoking the script each time.

Omit the `-p` flag entirely:

```bash
./ctf-sniffer-flag-finder.sh -F challenge.pcap
```

The script enters a search loop:

```
=========================================
   INTERACTIVE FLAG SEARCH
=========================================

Flag pattern to search (or 'q' to quit): CTF{
Use regex? (y/n): n
Export to file? (filename or Enter to skip):
[*] String search: CTF{
[*] Found 0 matching packet(s).

Flag pattern to search (or 'q' to quit): flag{
Use regex? (y/n): n
Export to file? (filename or Enter to skip):
[*] String search: flag{
[*] Found 1 matching packet(s):
47   HTTP   192.168.1.10   192.168.1.1   52341   80

Flag pattern to search (or 'q' to quit): (flag|FLAG)\{.*\}
Use regex? (y/n): y
Export to file? (filename or Enter to skip): matches.pcap
[*] Regex search: (flag|FLAG)\{.*\}
[*] Found 1 matching packet(s):
47   HTTP   192.168.1.10   192.168.1.1   52341   80
[*] Exporting matches to matches.pcap
[*] Export successful.

Flag pattern to search (or 'q' to quit): q
```

**Pre-set a default export file for the whole interactive session:**

```bash
./ctf-sniffer-flag-finder.sh -F challenge.pcap -e session_matches.pcap
# Each search will offer to export to session_matches.pcap by default
```

---

## Scenario 7 — Timed Capture with Auto-stop

**Situation:** You want to capture traffic for a fixed window — for example, during a specific challenge phase — without having to manually press Ctrl+C.

```bash
# Capture for 5 minutes, then search for the flag
sudo ./ctf-sniffer-flag-finder.sh -i eth0 -t 300 -p "CTF{"
```

The capture stops automatically after 300 seconds and the search runs immediately.

**Timed capture with export:**

```bash
sudo ./ctf-sniffer-flag-finder.sh -i eth0 -t 120 -f "tcp port 1337" -p "CTF{" -e round1.pcap
```

This captures for 2 minutes on port 1337, searches for `CTF{`, and exports any matches to `round1.pcap`.

**Repeat for multiple rounds in a script:**

```bash
for round in 1 2 3; do
    sudo ./ctf-sniffer-flag-finder.sh -i eth0 -t 60 -p "CTF{" -e "round${round}_flags.pcap" -q
    echo "Round $round done."
done
```

---

## Scenario 8 — Quiet Mode for Scripting

**Situation:** You are running the script as part of a larger automation pipeline and want clean output.

```bash
# Quiet mode — only errors are printed
./ctf-sniffer-flag-finder.sh -F challenge.pcap -p "CTF{" -e found.pcap -q
echo "Exit code: $?"
```

Exit codes:

| Code | Meaning |
|------|---------|
| `0` | Script completed successfully (does not mean flags were found) |
| `1` | Runtime error (file not found, tshark failed, export failed) |
| `2` | Argument error (bad option, conflicting flags) |

Check whether the export file was populated to determine if flags were found:

```bash
./ctf-sniffer-flag-finder.sh -F challenge.pcap -p "CTF{" -e found.pcap -q
if [ -s found.pcap ]; then
    echo "Flags found! Open found.pcap in Wireshark."
else
    echo "No matches."
fi
```

---

## Cheat Sheet

```bash
# Live capture, search for flag, stop with Ctrl+C
sudo ./ctf-sniffer-flag-finder.sh -i eth0 -p "CTF{"

# Live capture for 60 seconds, then search
sudo ./ctf-sniffer-flag-finder.sh -i eth0 -t 60 -p "CTF{"

# Live capture on specific port only
sudo ./ctf-sniffer-flag-finder.sh -i eth0 -f "tcp port 1337" -p "CTF{"

# Analyze existing pcap
./ctf-sniffer-flag-finder.sh -F challenge.pcap -p "flag{"

# Verbose output (show payloads)
./ctf-sniffer-flag-finder.sh -F challenge.pcap -p "CTF{" -v

# Regex search
./ctf-sniffer-flag-finder.sh -F challenge.pcap -r -p "(CTF|flag)\{[A-Za-z0-9_]+\}"

# Export matches to new pcap
./ctf-sniffer-flag-finder.sh -F challenge.pcap -p "CTF{" -e matches.pcap

# Full pipeline: capture, filter port, timed, search, export
sudo ./ctf-sniffer-flag-finder.sh -i eth0 -f "tcp port 1337" -t 120 -p "CTF{" -e found.pcap

# Interactive mode (multiple searches on same file)
./ctf-sniffer-flag-finder.sh -F challenge.pcap

# Quiet mode for scripting
./ctf-sniffer-flag-finder.sh -F challenge.pcap -p "CTF{" -e found.pcap -q

# Check if export has content (flag found)
[ -s found.pcap ] && echo "Flag found" || echo "No match"
```
