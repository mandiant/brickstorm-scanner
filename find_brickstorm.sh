#!/bin/bash

# Copyright 2025 Google LLC
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

# This script attempts to replicate the YARA rule G_APT_Backdoor_BRICKSTORM_3
# on systems without YARA installed.
#
# It checks for:
# 1. ELF file header (from `uint16(0) == 0x457F`)
# 2. A set of required strings (from `$str2` - `$str7`)
# 3. A specific hex pattern (from `$str1`)
#
# The condition is "all of them", so all checks must pass to flag a file.
#
# Usage: ./find_brickstorm.sh -o logfile.txt /directory/to/scan/

#
# Detect OS to set the correct flags for `find`
if [ "$(uname -s)" = "Linux" ]; then
    # GNU/Linux `find`
    FIND_OPTS="-P"                         # -P to never follow symbolic links (avoids filesystem loops)
    REGEX_EXPR="-regextype posix-extended" # Use -regextype as an expression
else
    # Assume BSD `find` (like on macOS/Darwin)
    FIND_OPTS="-PE"        # -P to never follow symbolic links, -E to enable extended regex
    REGEX_EXPR=""          # No separate expression is needed
fi

# Check if GNU `timeout` command is available
if command -v timeout &>/dev/null; then
    TIMEOUT_CMD="timeout 1s"
else
    TIMEOUT_CMD="" # No timeout command, check will run without a timeout
fi


# --- Centralized Exclusions Function ---
# This is now the ONE place to edit all `find` exclusions.
# This function takes the standard `find` command arguments and appends
# the common exclusion list to them. It's safer and cleaner than using `eval`.
run_find_with_exclusions() {
    # The arguments passed to this function (e.g., find, path, -type f)
    # are represented by "$@". We append our exclusions to those arguments.
    # Patterns start with '.*' to match regardless of the starting directory.
    find "$@" \( \
        -not -regex "/proc/.*" \
        -and -not -regex "/tmp/[0-9]{10}/.*" \
        -and -not -regex "/var(/crash)?/nsproflog/newproflog.*" \
        -and -not -regex "/var(/crash)?/log/notice.log" \
    \) 2>/dev/null
}

# --- YARA Rule Definitions ---

# This regex corresponds to the hex string $str1.
# { 48 8B 05 ?? ?? ?? ?? 48 89 04 24 E8 ?? ?? ?? ?? 48 B8 ?? ?? ?? ?? ?? ?? ?? ?? 48 89 04 24 [0-5] E8 ?? ?? ?? ?? EB ?? }
# The [0-5] means a 0-to-5 byte gap. In our hex dump, one
# byte is two characters ('..'). So, we use the regex (..){0,5}
hex_pattern="488b05........48890424e8........48b8................48890424(..){0,5}e8........eb.."

# This is $str7 ($long_num)
long_num="115792089210356248762697446949407573529996955224135760342422259061068512044369115792089210356248762697446949407573530086143415290314195533631308867097853951"
# --- End of Definitions ---

foundHits=false

# Function to dynamically create a UTF-16LE (wide) regex pattern
# Usage: build_wide_pattern "text" -> "t\x00e\x00x\x00t\x00"
build_wide_pattern() {
    # sed: for each character (.), replace it with itself (&) followed by \x00
    echo -n "$1" | sed 's/./&\\x00/g'
}

# Function to show progress
show_progress() {
    local current="$1"
    local total="$2"
    local phase="$3"
    
    if [ "$total" -eq 0 ]; then
        return
    fi
    
    local percentage=$((current * 100 / total))
    local bar_length=50
    local filled_length=$((current * bar_length / total))
    
    # Create progress bar
    local bar=""
    local i=0
    while [ $i -lt $bar_length ]; do
        if [ $i -lt $filled_length ]; then
            bar="${bar}█"
        else
            bar="${bar}░"
        fi
        i=$((i + 1))
    done
    
    # Print progress with carriage return to overwrite previous line
    printf "\r%s [%s] %d%% (%d/%d files)" "$phase" "$bar" "$percentage" "$current" "$total"
    
    # If we're done, add a newline
    if [ "$current" -eq "$total" ]; then
        echo
    fi
}

# Function to check a single file
check_file() {
    local file="$1"
    
    # Ensure it's a file we can read (metadata check)
    if [ ! -f "$file" ] || [ ! -r "$file" ]; then
        return
    fi

    # --- NEW CHECK: Attempt a timed read to detect locked files ---
    # $TIMEOUT_CMD will be "timeout 1s" if available, or empty otherwise.
    # This attempts to read one byte. If it fails (e.g., timeout), we skip.
    if ! $TIMEOUT_CMD head -c 1 "$file" &>/dev/null; then
        # File is locked, timed out, or unreadable. Skip.
        return
    fi

    # --- Condition 1: Check ELF Header ---
    # uint16(0) == 0x457F checks for the first two bytes being 0x7F 0x45
    # (little-endian), which is the start of an ELF file magic number.
    if command -v xxd >/dev/null 2>&1; then
        file_header=$(xxd -l 2 -p "$file" 2>/dev/null)
    else
        file_header=$(hexdump -n 2 -v -e '/1 "%02x"' "$file" 2>/dev/null)
    fi
    if [ "$file_header" != "7f45" ]; then
        # Not an ELF file, so it cannot match.
        return
    fi

    # --- Condition 2: Check for all strings ($str2 - $str7) ---
    # We use `grep -iaPq` to search the binary (-a) case-insensitively (-i)
    # with Perl regex (-P) and stop on first match (-q).
    # We search for the ASCII string OR (|) the WIDE string.

    # $str2 "regex"
    str2="regex"
    str2_wide=$(build_wide_pattern "$str2")
    if ! grep -iaEq "$str2|$str2_wide" "$file"; then return; fi

    # $str3 "mime"
    str3="mime"
    str3_wide=$(build_wide_pattern "$str3")
    if ! grep -iaEq "$str3|$str3_wide" "$file"; then return; fi

    # $str4 "decompress"
    str4="decompress"
    str4_wide=$(build_wide_pattern "$str4")
    if ! grep -iaEq "$str4|$str4_wide" "$file"; then return; fi

    # $str5 "MIMEHeader"
    str5="MIMEHeader"
    str5_wide=$(build_wide_pattern "$str5")
    if ! grep -iaEq "$str5|$str5_wide" "$file"; then return; fi

    # $str6 "ResolveReference"
    str6="ResolveReference"
    str6_wide=$(build_wide_pattern "$str6")
    if ! grep -iaEq "$str6|$str6_wide" "$file"; then return; fi
    
    # $str7 (long_num)
    str7_wide=$(build_wide_pattern "$long_num")
    # -i is fine, even though it's numbers
    if ! grep -iaEq "$long_num|$str7_wide" "$file"; then return; fi

    # --- Condition 3: Check for hex string ($str1) ---
    # This is the most expensive check. We hex-dump the entire file,
    # remove newlines, and grep the resulting single line of hex.
    # We use grep -Eq for Extended regex to support (..){0,5}
    if command -v xxd >/dev/null 2>&1; then
        if ! xxd -p "$file" 2>/dev/null | tr -d '\n' | grep -Eq "$hex_pattern"; then
            return
        fi
    else
        if ! hexdump -v -e '/1 "%02x"' "$file" 2>/dev/null | grep -Eq "$hex_pattern"; then
            return
        fi
    fi

    # --- All conditions met ---
    foundHits=true
    if [ -n "$LOG_FILE" ]; then
        # If log file is set, tee output to both stdout and log file
        {
            echo ''
            echo "MATCH: $file"
            echo "Found evidence of potential BRICKSTORM compromise."
            echo "You should consider performing a forensic investigation of the system."
            echo 
        } | tee -a "$LOG_FILE"
    else
        # Otherwise, just echo to stdout
        echo ''
        echo "MATCH: $file"
        echo "Found evidence of potential BRICKSTORM compromise."
        echo "You should consider performing a forensic investigation of the system."
        echo 
    fi
}

# --- Main script execution ---

LOG_FILE=""

# Parse command-line options
while getopts ":o:" opt; do
  case $opt in
    o)
      LOG_FILE="$OPTARG"
      ;;
    \?)
      echo "Invalid option: -$OPTARG" >&2
    exit 1
      ;;
    :)
      echo "Option -$OPTARG requires an argument." >&2
      exit 1
      ;;
  esac
done

# Shift processed options away
shift $((OPTIND-1))

if [ "$#" -eq 0 ]; then
    echo "Usage: $0 [-o /path/to/logfile] <file_or_directory1> [file_or_directory2] ..."
    echo "Checks files for strings and byte sequences present in the BRICKSTORM backdoor."
    exit 1
fi

# Check if log file is writable
if [ -n "$LOG_FILE" ]; then
    touch "$LOG_FILE" 2>/dev/null
    if [ $? -ne 0 ]; then
        echo "Error: Cannot write to log file: $LOG_FILE" >&2
        exit 1
    fi
    echo "Logging hits to: $LOG_FILE"
fi

# Export functions and variables that might be used in subshells (less critical now, but good practice)
export -f check_file
export -f build_wide_pattern
export long_num
export hex_pattern
export LOG_FILE
export TIMEOUT_CMD
export foundHits

# Record start time
start_time=$(date +%s)

# --- REFACTORED File Discovery and Processing ---

# Create a temporary file to store the list of files to scan
file_list_tmp=$(mktemp)
# Ensure the temp file is cleaned up when the script exits for any reason
trap 'rm -f "$file_list_tmp"' EXIT

echo "Discovering and filtering files to scan (this may take a moment)..." >&2
# Find all files across all targets and save them to the temp file
for target in "$@"; do
    if [ -d "$target" ]; then
        # Find files within the directory and append to our list
        run_find_with_exclusions $FIND_OPTS "$target" $REGEX_EXPR -type f -size -10M >> "$file_list_tmp"
    elif [ -f "$target" ]; then
        # If it's a file, just add it to the list
        echo "$target" >> "$file_list_tmp"
    else
        echo "Warning: '$target' is not a valid file or directory. Skipping." >&2
    fi
done

# Get the total count of files to be scanned
total_files=$(wc -l < "$file_list_tmp")
# wc -l adds leading whitespace, remove it
total_files=$(echo "$total_files" | tr -d ' ') 

if [ "$total_files" -eq 0 ]; then
    echo "No files to scan after applying exclusions."
    if [ -n "$LOG_FILE" ]; then
        echo "No files to scan after applying exclusions." >> "$LOG_FILE"
    fi
    exit 0
fi

echo "Found $total_files files to scan." >&2
echo >&2

# Process the generated list of files with a simple, efficient loop
processed_files=0
while IFS= read -r file_to_check; do
    processed_files=$((processed_files + 1))
    # Send progress bar to stderr to keep stdout clean for results
    show_progress "$processed_files" "$total_files" "Processing files" >&2
    check_file "$file_to_check"
done < "$file_list_tmp"

# --- END REFACTOR ---

# Record end time and calculate duration
end_time=$(date +%s)
end_timestamp=$(date)
duration=$((end_time - start_time))

# Format duration into human-readable format
if [ $duration -lt 60 ]; then
    duration_str="${duration}s"
elif [ $duration -lt 3600 ]; then
    minutes=$((duration / 60))
    seconds=$((duration % 60))
    duration_str="${minutes}m ${seconds}s"
else
    hours=$((duration / 3600))
    minutes=$(((duration % 3600) / 60))
    seconds=$((duration % 60))
    duration_str="${hours}h ${minutes}m ${seconds}s"
fi

if [ "$foundHits" = false ]; then
    local_message="Scan complete. No BRICKSTORM malware signatures found."
    if [ -n "$LOG_FILE" ]; then
        # Log to both stdout and file
        echo "$local_message" | tee -a "$LOG_FILE"
    else
        # Log to stdout only
        echo "$local_message"
    fi
fi

echo
echo "Scan completed at: $end_timestamp"
echo "Total scan time: $duration_str"
