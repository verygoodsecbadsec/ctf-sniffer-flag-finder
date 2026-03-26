# ctf-sniffer-flag-finder

> **Capture live traffic or read a pcap file and hunt for CTF flags in seconds.**

In CTF competitions, flags often travel over the wire in plaintext — HTTP responses, UDP datagrams, custom TCP services. This script wraps `tshark` with a clean interface for capturing traffic on a live interface, or reading an existing pcap, and searching it for any flag pattern. Matches can be exported to a new pcap for deeper analysis in Wireshark.

```
$ sudo ./ctf-sniffer-flag-finder.sh -i eth0 -p "CTF{" -t 60 -e found.pcap

[*] Interface: eth0
[*] Traffic will be saved to: capture_20240812_143022.pcap
[*] Starting tshark on eth0 (all traffic)
[*] Capture will stop after 60 seconds.
[*] Capturing... (Ctrl+C to stop)
[*] Stopping capture...
[*] Capture saved to capture_20240812_143022.pcap
[*] String search: CTF{
[*] Found 3 matching packet(s):
12   TCP   10.0.0.5   10.0.0.1   54321   80
47   HTTP  10.0.0.5   10.0.0.1   54321   80
91   UDP   10.0.0.8   10.0.0.1   1337    1337
[*] Exporting matches to found.pcap
[*] Export successful.
```

---

## How It Works

The script operates in one of two modes:

**Capture mode** (`-i`) starts a live `tshark` capture on a network interface, saves it to a timestamped pcap file, then searches the recorded traffic when capture ends. Requires root.

**File mode** (`-F`) reads an existing pcap directly, skipping capture entirely.

In both cases, the search uses tshark display filters — either `frame contains` for plaintext string matching, or `frame matches` for Wireshark-style regex. Results are printed to stdout and optionally exported as a filtered pcap containing only the matching packets.

---

## Installation

### Dependencies

The script requires only `tshark` (the CLI component of Wireshark).

```bash
# Debian / Ubuntu
sudo apt install tshark


# Arch Linux
sudo pacman -S wireshark-cli
```

Verify the installation:

```bash
tshark --version
```

### Script setup

```bash
git clone https://github.com/verygoodsecbadsec/ctf-sniffer-flag-finder.git
cd ctf-sniffer-flag-finder
chmod +x ctf-sniffer-flag-finder.sh
```

---

## Usage

```
Capture mode:  sudo ./ctf-sniffer-flag-finder.sh -i <interface> [options]
File mode:          ./ctf-sniffer-flag-finder.sh -F <pcap_file> [options]
```

### Options

| Flag | Argument | Description |
|------|----------|-------------|
| `-i` | `<iface>` | Network interface to capture on (requires root) |
| `-F` | `<file>` | Existing pcap file to search |
| `-p` | `<pattern>` | Flag pattern to search — plaintext or regex |
| `-r` | — | Enable regex matching (Wireshark display filter syntax) |
| `-e` | `<file>` | Export matching packets to a new pcap file |
| `-f` | `<filter>` | BPF capture filter, e.g. `tcp port 80` (capture mode only) |
| `-t` | `<seconds>` | Auto-stop capture after N seconds (capture mode only) |
| `-v` | — | Verbose — show full packet details including payload |
| `-q` | — | Quiet — suppress informational output |
| `-h` | — | Show help |

---

## Modes

### Capture mode

Records live traffic on a network interface. Requires `sudo`. The capture runs until you press `Ctrl+C` or the `-t` timeout expires. The pcap is saved as `capture_YYYYMMDD_HHMMSS.pcap` in the current directory, then searched automatically.

```bash
sudo ./ctf-sniffer-flag-finder.sh -i eth0 -p "CTF{"
```

### File mode

Reads an existing pcap file. Does not require root. Useful when you already have a capture from Wireshark, `tcpdump`, or a challenge download.

```bash
./ctf-sniffer-flag-finder.sh -F challenge.pcap -p "CTF{"
```

### Interactive mode

If you omit `-p`, the script enters an interactive loop after capture or file load. You can search for multiple patterns in sequence, toggle regex per search, and optionally export each match set to a different file — without re-reading the pcap each time.

```bash
./ctf-sniffer-flag-finder.sh -F challenge.pcap
# prompts you for patterns interactively
# type 'q' to quit
```

---

## Search Syntax

### Plaintext search (default)

Searches for the literal string anywhere in a packet frame. Case-sensitive.

```bash
-p "CTF{"
-p "flag{"
-p "password="
```

### Regex search (`-r`)

Uses Wireshark display filter regex syntax (POSIX ERE, not PCRE). Anchors, character classes, and alternation are supported. Lookaheads are not.

```bash
-r -p "CTF\{[A-Za-z0-9_]+\}"
-r -p "(flag|FLAG)\{.*\}"
-r -p "Authorization: Basic [A-Za-z0-9+/]+"
```

---

## Output

Matching packets are printed as a table showing:

| Column | Field |
|--------|-------|
| Frame number | `frame.number` |
| Protocol | `_ws.col.Protocol` |
| Source IP | `ip.src` |
| Destination IP | `ip.dst` |
| Source port | `tcp.srcport` |
| Destination port | `tcp.dstport` |

Up to 50 matching packets are shown. If there are more, the count is displayed.

In verbose mode (`-v`), the full `data.text` and `tcp.payload` fields are included in the output.

---

## Export

The `-e` flag writes all matching packets to a new pcap file. This file can be opened in Wireshark for deeper inspection, used as input for a second pass with a different pattern, or shared with teammates.

```bash
./ctf-sniffer-flag-finder.sh -F challenge.pcap -p "CTF{" -e matches.pcap
```

If the export file already exists, it is overwritten with a warning.

---

## Verbosity Levels

| Flag | Level | Output |
|------|-------|--------|
| `-q` | 0 | Errors only |
| (default) | 1 | Info messages + packet table |
| `-v` | 2 | Full packet details including payload fields |

---

## Why Using This Script

 - No,the real question is,when you are in an engadgement,do you search for flags?

 - Of course,no CTF or challenge(this script will be very useful in Web CTFs) is an engadgement,but treating it as one will be the exact path on compromising the target = finding the vulnerability.

 - By using this script,your focus shifts from trying to just pop-up a flag to following your methodology and notes in a normal way,and not worrying about flags.

 - By doing this,you practice but also capture flags as you go(the real idea behind it was to shift the mentality from a flag hunter to a vulnerability hunter).



---

## Limitations

- **Regex syntax** is Wireshark display filter regex, not PCRE. Features like lookaheads (`(?=...)`) and non-greedy quantifiers do not work. Test patterns in Wireshark first if unsure.
- **Encrypted traffic** (TLS without a key log) will not yield plaintext flags. For TLS, you need the session key log file and Wireshark's TLS decryption support — this script does not handle decryption.
- **Large pcap files** may produce slow search results since `tshark` re-reads the entire file per query in interactive mode.
- **Live capture disk usage** — large captures fill disk quickly. Use `-f` to apply a BPF filter at capture time to limit scope, and `-t` to bound the capture duration.
- The script is intended for **authorized use in CTF competitions and controlled lab environments only**.

---

## Legal Notice

This tool is intended for authorized use in CTF competitions, security research, and controlled test environments only. Capturing traffic on networks you do not own or have explicit permission to monitor is illegal in most jurisdictions. The author accepts no liability for unauthorized use.

---

## License
 - This project is licensed under the MIT License – see the [LICENSE](LICENSE) file for details.
