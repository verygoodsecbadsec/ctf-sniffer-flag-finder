#!/bin/bash

# ============================================================================
# ctf-sniffer-flag-finder.sh
#
# A simple script that:
#   1. Records traffic on a chosen interface, OR
#      reads an existing .pcap file (with -F)
#   2. Searches the traffic for a flag pattern (string or regex)
#   3. Can export matching packets to a separate file
# ============================================================================

set -o pipefail
set -u

# ---------- colors ----------
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NO_COLOR='\033[0m'

print_info()    { echo -e "${GREEN}[*]${NO_COLOR} $1"; }
print_warning() { echo -e "${YELLOW}[!]${NO_COLOR} $1"; }
print_error()   { echo -e "${RED}[ERROR]${NO_COLOR} $1"; }

show_help() {
    cat <<EOF
Usage:
  Capture mode:  sudo $0 -i <interface> [options]
  File mode:            $0 -F <pcap_file> [options]

Required (choose one):
  -i <iface>      Network interface to capture on
  -F <file>       Existing pcap file to search

Common options:
  -p <pattern>    Flag pattern to search (plain text, or regex with -r)
  -r              Enable regex matching (Wireshark display filter regex, not PCRE)
  -e <file>       Export matching packets to a new pcap
  -f <filter>     BPF capture filter (only with -i)
  -t <seconds>    Stop capture after N seconds (only with -i)
  -v              Verbose mode – show full packet details
  -q              Quiet mode – minimal output
  -h              This help message
EOF
    exit 0
}

# ---------- defaults ----------
VERBOSE=1
INTERFACE=""
PATTERN=""
REGEX_MODE=false
EXPORT_FILE=""
CAPTURE_FILTER=""
TIMEOUT=0
PCAP_FILE=""
MODE=""
TSHARK_PID=""
TIMEOUT_PID=""
CAPTURE_FINISHED=false

# ---------- parse arguments ----------
if [ $# -eq 0 ]; then show_help; fi

while getopts ":i:p:re:f:t:F:vqh" opt; do
    case "$opt" in
        i) INTERFACE="$OPTARG" ;;
        p) PATTERN="$OPTARG" ;;
        r) REGEX_MODE=true ;;
        e) EXPORT_FILE="$OPTARG" ;;
        f) CAPTURE_FILTER="$OPTARG" ;;
        t) TIMEOUT="$OPTARG" ;;
        F) PCAP_FILE="$OPTARG" ;;
        v) VERBOSE=2 ;;
        q) VERBOSE=0 ;;
        h) show_help ;;
        \?) print_error "Unknown option: -$OPTARG"; exit 2 ;;
        :)  print_error "Option -$OPTARG needs an argument."; exit 2 ;;
    esac
done

# empty pattern detection
if [ -n "${PATTERN+isset}" ] && [ -z "$PATTERN" ]; then
    print_error "Empty pattern not allowed. Provide a non-empty search string when using -p."
    exit 2
fi

# forbid both modes
if [ -n "$INTERFACE" ] && [ -n "$PCAP_FILE" ]; then
    print_error "Use either -i (capture mode) OR -F (file mode), not both."
    exit 2
fi

# require one mode
if [ -z "$INTERFACE" ] && [ -z "$PCAP_FILE" ]; then
    print_error "You must specify either -i (capture) or -F (pcap file)."
    exit 2
fi

MODE="capture"
[ -n "$PCAP_FILE" ] && MODE="file"

# ---------- file mode ----------
if [ "$MODE" = "file" ]; then
    if [ ! -f "$PCAP_FILE" ] || [ ! -r "$PCAP_FILE" ]; then
        print_error "File '$PCAP_FILE' does not exist or is not readable."
        exit 1
    fi
    print_info "Analyzing existing file: $PCAP_FILE"
else
    # ---------- capture mode ----------
    if [ "$EUID" -ne 0 ]; then
        print_error "Capture mode requires root. Please use sudo."
        exit 1
    fi

    if command -v ip >/dev/null 2>&1; then
        if ! ip link show "$INTERFACE" >/dev/null 2>&1; then
            print_error "Interface '$INTERFACE' does not exist."; exit 1
        fi
    else
        [ -d "/sys/class/net/$INTERFACE" ] || { print_error "Interface '$INTERFACE' does not exist."; exit 1; }
    fi

    print_info "Interface: $INTERFACE"

    if [ -n "$TIMEOUT" ] && ! [[ "$TIMEOUT" =~ ^[0-9]+$ ]]; then
        print_error "Timeout must be a positive integer."; exit 2
    fi

    TIMESTAMP=$(date +%Y%m%d_%H%M%S)
    PCAP_FILE="capture_${TIMESTAMP}.pcap"
    [ $VERBOSE -ge 1 ] && print_info "Traffic will be saved to: $PCAP_FILE"
    [ $VERBOSE -ge 1 ] && print_warning "Large captures can fill your disk."

    if [ -n "$CAPTURE_FILTER" ]; then
        [ $VERBOSE -ge 1 ] && print_info "Starting tshark with filter: $CAPTURE_FILTER"
        tshark -i "$INTERFACE" -f "$CAPTURE_FILTER" -w "$PCAP_FILE" &
    else
        [ $VERBOSE -ge 1 ] && print_info "Starting tshark on $INTERFACE (all traffic)"
        tshark -i "$INTERFACE" -w "$PCAP_FILE" &
    fi
    TSHARK_PID=$!

    sleep 2
    if ! kill -0 "$TSHARK_PID" 2>/dev/null; then
        print_error "tshark could not start. Check permissions/interface."
        exit 1
    fi

    CAPTURE_FINISHED=false
    stop_capture_now() {
        echo ""
        print_info "Stopping capture..."
        kill -TERM "$TSHARK_PID" 2>/dev/null
        wait "$TSHARK_PID" 2>/dev/null
        # kill the timeout background process (if any)
        [ -n "${TIMEOUT_PID:-}" ] && kill -TERM "$TIMEOUT_PID" 2>/dev/null
        CAPTURE_FINISHED=true
        print_info "Capture saved to $PCAP_FILE"
    }
    trap stop_capture_now INT

    if [ "$TIMEOUT" -gt 0 ]; then
        [ $VERBOSE -ge 1 ] && print_info "Capture will stop after $TIMEOUT seconds."
        ( sleep "$TIMEOUT"; kill -INT "$PPID" 2>/dev/null ) &
        TIMEOUT_PID=$!
    fi

    [ $VERBOSE -ge 1 ] && print_info "Capturing... (Ctrl+C to stop)"
    while [ "$CAPTURE_FINISHED" = false ]; do sleep 1; done
    trap - INT
    # safely kill timer if still alive (e.g. user Ctrl+C before timeout)
    [ -n "${TIMEOUT_PID:-}" ] && kill -TERM "$TIMEOUT_PID" 2>/dev/null
fi

# ============================================================================
# SEARCH FUNCTION
# ============================================================================
search_traffic() {
    local pattern="$1"
    local regex="$2"
    local export_file="$3"

    local filter
    local safe_pattern="${pattern//\"/\\\"}"

    if [ "$regex" = true ]; then
        filter="frame matches \"$safe_pattern\""
        [ $VERBOSE -ge 1 ] && print_info "Regex search: $pattern"
    else
        filter="frame contains \"$safe_pattern\""
        [ $VERBOSE -ge 1 ] && print_info "String search: $pattern"
    fi

    local tmp_err
    tmp_err=$(mktemp) || { print_error "Cannot create temp file."; return 1; }

    local tshark_output
    tshark_output=$(tshark -r "$PCAP_FILE" -Y "$filter" \
        -T fields -e frame.number -e _ws.col.Protocol -e ip.src -e ip.dst \
        -e tcp.srcport -e tcp.dstport -e data.text -e tcp.payload 2>"$tmp_err")

    local tshark_error=$(<"$tmp_err")
    rm -f "$tmp_err"

    [ -n "$tshark_error" ] && { print_warning "tshark: $tshark_error"; return 1; }

    local match_count
    if [ -z "$tshark_output" ]; then
        match_count=0
    else
        match_count=$(grep -c . <<< "$tshark_output")
    fi

    if [ $match_count -eq 0 ]; then
        [ $VERBOSE -ge 1 ] && print_info "No packets matched."
    else
        [ $VERBOSE -ge 1 ] && print_info "Found $match_count matching packet(s):"
        if [ $VERBOSE -ge 2 ]; then
            if command -v column >/dev/null 2>&1; then
                printf '%s\n' "$tshark_output" | head -n 50 | column -t
            else
                printf '%s\n' "$tshark_output" | head -n 50
            fi
            [ $match_count -gt 50 ] && echo "... and $((match_count-50)) more."
        else
            local packets
            packets=$(awk '{print $1}' <<< "$tshark_output")
            if command -v column >/dev/null 2>&1; then
                printf '%s\n' "$packets" | head -n 50 | column -t
            else
                printf '%s\n' "$packets" | head -n 50
            fi
            [ $match_count -gt 50 ] && echo "... showing first 50."
        fi
    fi

    if [ -n "$export_file" ]; then
        [ -f "$export_file" ] && print_warning "File $export_file exists – overwriting."
        [ $VERBOSE -ge 1 ] && print_info "Exporting matches to $export_file"
        tshark -r "$PCAP_FILE" -Y "$filter" -w "$export_file" 2>/dev/null
        [ $? -eq 0 ] && print_info "Export successful." || { print_error "Export failed."; return 1; }
    fi
}

# ============================================================================
# DECIDE HOW TO SEARCH
# ============================================================================

if [ -n "$PATTERN" ]; then
    search_traffic "$PATTERN" "$REGEX_MODE" "$EXPORT_FILE"
else
    [ $VERBOSE -ge 1 ] && printf '\n=========================================\n   INTERACTIVE FLAG SEARCH\n=========================================\n'
    while true; do
        echo ""
        read -r -p "Flag pattern to search (or 'q' to quit): " user_pattern
        [ "$user_pattern" = "q" ] && break
        [ -z "$user_pattern" ] && continue

        read -r -p "Use regex? (y/n): " use_regex_answer
        [[ "$use_regex_answer" =~ ^[Yy] ]] && regex_choice=true || regex_choice=false

        export_choice=""
        if [ -n "$EXPORT_FILE" ]; then
            echo "Default export file: $EXPORT_FILE"
            read -r -p "Press Enter to use it, or type new name / blank to skip: " export_answer
            [ -z "$export_answer" ] && export_choice="$EXPORT_FILE" || export_choice="$export_answer"
        else
            read -r -p "Export to file? (filename or Enter to skip): " export_answer
            [ -n "$export_answer" ] && export_choice="$export_answer"
        fi

        search_traffic "$user_pattern" "$regex_choice" "$export_choice"
    done
fi

# ---------- final summary ----------
if [ $VERBOSE -ge 1 ]; then
    echo ""
    echo "=============================="
    if [ "$MODE" = "capture" ]; then
        print_info "Capture saved to: $PCAP_FILE"
    else
        print_info "Analyzed file: $PCAP_FILE"
    fi
    print_info "Happy hunting!"
fi

exit 0
