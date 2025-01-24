/*
I don't know if this is something that is allowed - but I'm doing it anyway, in case it helps for the future. This is a generic rule for detecting traffic signalling.
*/
rule Traffic_Signaling_T1205
{
    meta:
        author = "Your Name"
        description = "Detects artifacts of malicious traffic signaling (T1205)"
        reference = "https://attack.mitre.org/techniques/T1205/"
        date = "2025-01-24"
        threat_level = "high"
        mitre_technique = "Traffic Signaling (T1205)"

    strings:
        // Known malicious proxy tools or configurations
        $proxy_tool_1 = "3proxy" nocase
        $proxy_tool_2 = "TinyProxy" nocase
        $proxy_tool_3 = "SOCKS5 proxy" nocase

        // Potentially suspicious domain or URL patterns
        $domain_pattern_1 = /[a-z0-9]{10,20}\.onion/i
        $domain_pattern_2 = /[a-z0-9]{8,16}\.(tk|ga|ml|cf|gq)/i
        $malicious_url = "http://malicious-proxy.example.com" // Replace with real C2 URLs if known

        // Known strings used in malicious configurations
        $config_1 = "ListenAddress" nocase
        $config_2 = "AllowCONNECT" nocase
        $config_3 = "remote-control" nocase
        $config_4 = "upstream-proxy" nocase

        // Binary patterns commonly found in traffic redirection malware
        $hex1 = { 48 89 E5 41 57 41 56 41 55 } // Replace with malware-specific patterns
        $hex2 = { 68 74 74 70 3A 2F 2F }      // "http://"

    condition:
        // File is PE, ELF, or contains traffic signaling artifacts
        (uint16(0) == 0x4d5a or uint32(0) == 0x7f454c46) and // PE or ELF file check
        (
            2 of ($proxy_tool_*) or
            1 of ($domain_pattern_*) or
            1 of ($malicious_url*) or
            2 of ($config_*) or
            any of ($hex*)
        )
}

/*
Explanation
Strings Section:
Proxy Tools: Includes strings that may appear in traffic signaling or proxy tools, such as "3proxy" or "TinyProxy."
Domain Patterns: Matches suspicious domain patterns like .onion for Tor or free TLDs like .tk, .ga, and .ml.
Configuration Keywords: Matches strings commonly found in malicious traffic signaling tools or proxy configurations.
Binary Patterns: Includes specific byte sequences or hex patterns identified in malicious samples.

Condition Section:
Detects if the file is a Portable Executable (PE) or ELF binary.
Triggers if:
At least two proxy-related strings match.
Any suspicious domain pattern matches.
Two configuration strings are found.
Any of the binary patterns match.


Next Steps
Add Specific Indicators:
Replace placeholders (e.g., http://malicious-proxy.example.com) with known malicious domains, URLs, or configurations if available.
Include specific hex signatures or strings from tools/malware known to use T1205.

Test the Rule:
Test against known malicious samples using traffic signaling.
Ensure minimal false positives by validating against benign files and configurations.

Context-Specific Refinements:
Adjust the rule to align with specific environments, focusing on tools, protocols, or behaviors observed in your threat landscape.
*/
