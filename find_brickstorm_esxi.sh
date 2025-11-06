#!/bin/sh

# Copyright 2025 Google LLC
# Refactored for ESXi/BusyBox Compatibility
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Usage: ./find_brickstorm_esxi.sh -o logfile.txt /directory/to/scan/

# --- Definitions ---
HEX_PATTERN="488b05.{8}48890424e8.{8}48b8.{16}48890424.{0,10}e8.{8}eb.{2}"
LONG_NUM="115792089210356248762697446949407573529996955224135760342422259061068512044369115792089210356248762697446949407573530086143415290314195533631308867097853951"
LOG_FILE=""

# --- Functions ---
build_wide_pattern() {
    printf "%s" "$1" | sed 's/./&./g'
}

check_file() {
    TARGET_FILE="$1"
    
    # Accessibility check
    if [ ! -f "$TARGET_FILE" ] || [ ! -r "$TARGET_FILE" ]; then return; fi

    # 1. ELF Header Check (reliable hexdump)
    FILE_HEADER=$(hexdump -n 2 -ve '1/1 "%.2x"' "$TARGET_FILE" 2>/dev/null)
    if [ "$FILE_HEADER" != "7f45" ]; then return; fi

    grep_str() {
        S_ASCII="$1"
        S_WIDE=$(build_wide_pattern "$1")
        # Separated flags for safety: grep -a -i -E -q
        if ! grep -a -i -E -q -e "$S_ASCII|$S_WIDE" "$TARGET_FILE"; then return 1; fi
        return 0
    }

    if ! grep_str "regex"; then return; fi
    if ! grep_str "mime"; then return; fi
    if ! grep_str "decompress"; then return; fi
    if ! grep_str "MIMEHeader"; then return; fi
    if ! grep_str "ResolveReference"; then return; fi
    if ! grep_str "$LONG_NUM"; then return; fi

    # 3. Hex Pattern Check
    if ! hexdump -ve '1/1 "%.2x"' "$TARGET_FILE" 2>/dev/null | grep -i -q -E -e "$HEX_PATTERN"; then
        return
    fi

    # --- Match Found ---
    MSG="MATCH: $TARGET_FILE"
    echo "$MSG"
    if [ -n "$LOG_FILE" ]; then echo "$MSG" >> "$LOG_FILE"; fi
}

# --- Main Execution ---

while getopts "o:" opt; do
    case $opt in
        o) LOG_FILE="$OPTARG" ;;
        *) echo "Usage: $0 [-o logfile] <paths>" >&2; exit 1 ;;
    esac
done
shift $((OPTIND-1))

if [ "$#" -eq 0 ]; then
    echo "Usage: $0 [-o logfile] <directory_to_scan>"
    echo "Example: $0 -o results.log /vmfs/volumes/datastore1/"
    exit 1
fi

# Initialize log file if specified
if [ -n "$LOG_FILE" ]; then
    : > "$LOG_FILE" # Truncate or create
    if [ ! -w "$LOG_FILE" ]; then
        echo "Error: Cannot write to log file $LOG_FILE"
        exit 1
    fi
fi

echo "Starting scan on ESXi host. This may be slow."
echo "Targets: $@"
COUNT=0

# Scan only files (-type f), attempt to skip huge files (-size -50000k = roughly 50MB limit to be safe on ESXi)
    find "$@" -type f -size -50000k 2>/dev/null | while read -r FILE; do
    # Basic manual exclusions for safety if user scanned root '/'
    case "$FILE" in
        /proc/*|/dev/*|/sys/*) continue ;;
    esac
    check_file "$FILE"
    COUNT=$((COUNT + 1))
    if [ $((COUNT % 100)) -eq 0 ]; then
        # Print to stderr so it doesn't mess up piped output if you use it later
        printf "Scanned %d files...\r" "$COUNT" >&2
    fi
    done

echo ""
echo "Scan complete."
