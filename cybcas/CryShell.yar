/*
Generic Rule
*/

rule CryShell_Backdoor_Detection
{
    meta:
        author = "CybCas"
        description = "Detects CryShell malware implant artifacts"
        reference = "https://attack.mitre.org/software/S1117/"
        date = "2025-01-24"
        threat_level = "high"
        mitre_technique = "T1205 (Traffic Signaling)"
        malware_family = "CryShell"

    strings:
        // Common CryShell strings observed in malware samples
        $str1 = "GET /api/v1/cmd" nocase
        $str2 = "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)" nocase
        $str3 = "Content-Type: application/json" nocase

        // Hardcoded C2 domain or IP patterns
        $c2_domain = /[a-z0-9]{8,20}\.(com|net|org|ru)/ nocase
        $c2_ip = /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/

        // Encryption or obfuscation-related strings
        $enc1 = "AES-256-CBC" nocase
        $enc2 = "encryption_key" nocase
        $enc3 = "decryption_key" nocase

        // Hex patterns (e.g., from binaries)
        $hex1 = { 68 74 74 70 73 3A 2F 2F } // "https://"
        $hex2 = { 2F 61 70 69 2F 76 31 2F 63 6D 64 } // "/api/v1/cmd"

    condition:
        // File contains CryShell-related strings, C2 patterns, or hex signatures
        (uint16(0) == 0x4D5A or uint16(0) == 0x7F45) and // PE or ELF file
        (
            2 of ($str*) or
            $c2_domain or
            $c2_ip or
            any of ($enc*) or
            all of ($hex*)
        )
}

/*
Rule Components
Strings Section:
CryShell Indicators: Known strings from the CryShell implant, such as HTTP API commands or user-agent strings.
C2 Patterns: Regular expressions to detect suspicious domain names or IP addresses (you can add specific IOCs if available).
Encryption Strings: Detects references to encryption or decryption functionality often used by implants like CryShell.
Hexadecimal Patterns: Binary patterns from the CryShell malware samples.

Condition Section:
Checks if the file is a PE (Portable Executable) or ELF binary.
Matches CryShell-related strings, C2 patterns, or encryption-related artifacts.


Next Steps
Refine with Specific IOCs:
If you have CryShell samples or known IOCs, add them (e.g., specific C2 domains, IPs, or unique strings).

Testing:
Test the rule against a dataset containing both malicious CryShell samples and benign files to minimise false positives.

Expand Coverage:
If CryShell has variations, expand the rule by incorporating additional unique indicators from those samples.

Integrate with Other Tools:
Use this YARA rule in conjunction with SIEM, EDR, or file-scanning platforms to detect potential CryShell artifacts.
*/
