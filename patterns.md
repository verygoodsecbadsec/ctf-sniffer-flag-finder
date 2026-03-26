# Flag patterns for `ctf-sniffer-flag-finder.sh`

This file collects flag formats commonly used in CTFs.
Use them with the `-p` option (or interactively) to scan captured traffic.

---

## 🔤 Plain text patterns (string search)

| CTF / Platform | Plain pattern        | Example flag              |
|----------------|----------------------|---------------------------|
| TryHackMe      | `THM{`              | `THM{example_flag}`       |
| HackTheBox     | `HTB{`              | `HTB{some_value}`         |
| Generic CTF    | `flag{`             | `flag{abc123}`            |
| CTFtime        | `CTF{`              | `CTF{leet-speak}`         |
| PicoCTF        | `picoCTF{`          | `picoCTF{just_a_test}`    |
| CyberChef      | `CYBER{`            | `CYBER{recipe}`           |
| Root‑Me        | `FLAG{`             | `FLAG{uppercase}`         |
| OverTheWire    | `password:`         | often followed by the answer |

**Usage:**
```bash
sudo ./ctf-sniffer-flag-finder.sh -i eth0 -p "flag{"
