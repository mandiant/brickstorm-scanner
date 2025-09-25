# BRICKSTORM Indicator of Compromise Scanner

This repository contains a utility for detecting potential BRICKSTORM backdoor
compromises on Linux and BSD-based appliances and systems.

This script is designed to replicate the logic of a specific YARA rule on
systems where YARA is not available or practical to run. To learn more about the
BRICKSTORM campaign, UNC5221, and closely related suspected China-nexus threat clusters, please read our full blog
post:
https://cloud.google.com/blog/topics/threat-intelligence/brickstorm-espionage-campaign

In summary, the utility will:

- Do a best-effort job at identifying files that match a known BRICKSTORM signature.
- Scan specified files or recursively scan entire directories.

It will not:

- Identify a compromise 100% of the time.
- Detect _all_ variants of BRICKSTORM (it is specific to one YARA rule).
- Tell you if a device is vulnerable to exploitation.
- Scan for other IOCs like logs, processes, or persistence mechanisms.

With community feedback, the tool may become more thorough in its detection.
Please [open an issue](https://github.com/mandiant/brickstorm-scanner/issues), or [submit a PR](https://github.com/mandiant/brickstorm-scanner/pulls), if you
have problems, ideas, or feedback.

If you believe you have a true positive match, you can contact Mandiant at investigations at mandiant dot com for more assistance. 

## Features

This scanner replicates the YARA rule `G_APT_Backdoor_BRICKSTORM_3`
by checking for three conditions in a given file. A file is only flagged as a
"MATCH" if **all** conditions are met:

1. **ELF File Header**: Checks that the file is a valid ELF binary.
1. **Required Strings**: Greps the binary for a set of required ASCII and wide
  (UTF-16LE) strings, including `regex, mime, decompress, MIMEHeader, ResolveReference`, and a specific large number.
1. **Hex Pattern**: Performs a hex dump (`xxd`) and searches for a specific 25-byte hex pattern associated with the malware.

## Details

The Indicator of Compromise (IoC) Scanner for BRICKSTORM was developed by
Mandiant based on knowledge gleaned from incident response engagements. The goal
of the scanner is to analyze files for evidence of this specific malware. There
are limitations in what the tool will be able to accomplish, and therefore,
executing the tool should not be considered a guarantee that a system is free of
compromise. For example, an attacker may have tampered with the system, or
deployed a variant not covered by this specific rule.

This tool is not guaranteed to find all evidence of compromise, or all evidence
of compromise related to BRICKSTORM. If indications of compromise are identified
on systems, organizations should perform a forensic examination of the
compromised system to determine the scope and extent of the incident. This
software is provided as-is, without warranty or representation for any use or
purpose.

## Usage

You can download the standalone Bash script (`brickstorm_scanner.sh`) directly
from this repository.

The IoC Scanner can be run directly on a Linux or BSD-based appliance or system. The
tool writes diagnostic messages to STDERR and results (matches) to STDOUT. In
typical usage, you should redirect STDOUT to a file for review. The tool must be
run with execute permissions.

**1. Make the script executable**:
```
chmod +x ./find_brickstorm.sh
```

**2. Scan an entire directory recursively**: The script will use `find` to scan
all files within the specified directory. BRICKSTORM has been deployed to a variety of locations on appliances and Mandiant recommends a thorough review of the entire file system.
**note:** This script will traverse all mounted filesystems. If you are running this script on a device with large datastore volumes, take care to specify paths that exclude them. 

```
./find_brickstorm.sh / > "/tmp/results-vmware-$(date +%F).txt"
```

### Interpreting Results

The tool will output `MATCH: <filepath>` to STDOUT for any file that meets all
three criteria. The output will be the full path to the file.

**Example Output**:

```
MATCH: /usr/bin/vami-lighttp
MATCH: /tmp/pg_update
```

If the scanner identifies a potential match, organizations should
perform a forensic examination of the compromised system to determine the scope
and extent of the incident. Contact investigations at mandiant dot com if you have questions or need assistance.

### Design

We provide this tool as a Bash script because it's a common denominator across
many Linux-based appliances (from vendors like VMware, Ivanti, and others) that
may not have YARA or other security tools installed. It uses common, built-in
utilities like `grep, xxd, head, sed`, and `find` to perform its checks.

### Further Reading

For additional information from Mandiant and Google Threat Intelligence Group (GTIG) regarding BRICKSTORM and in-the-wild
exploitation, please see:

- https://cloud.google.com/blog/topics/threat-intelligence/brickstorm-espionage-campaign - Published on September 24, 2025
