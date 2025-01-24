/* Generic rule for BUSHWALK
*/
rule BUSHWALK_Malware
{
    meta:
        author = "CybCas"
        description = "Detects BUSHWALK malware"
        reference = "https://attack.mitre.org/software/S1118/"
        date = "2025-01-23"
        threat_level = "high"
        mitre_technique = "TTPs related to BUSHWALK"

    strings:
        // Add strings known to be unique to BUSHWALK
        $s1 = "bushwalk.dll" nocase
        $s2 = "Task_Scheduler_Create" nocase
        $s3 = "WMI_Command_Execution" nocase
        $s4 = "Admin\\System32\\cmd.exe" nocase
        $s5 = "User-Agent: BUSHWALK" nocase
        $s6 = "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\BUSHWALK" nocase
        
        // Placeholder for possible C2 URLs or domains
        $malicious_url = "http://malicious-bushwalk.example.com" // Replace with real C2 if known
        $malicious_domain = "bushwalk-malware.com" // Replace with real domain if known

        // Binary patterns or hex signatures (example)
        $hex1 = { 50 53 48 41 57 4B 5F 41 50 49 } // Replace with specific hex patterns from samples

    condition:
        (uint16(0) == 0x4d5a or uint32(0) == 0x7f454c46) and // PE or ELF file check
        (
            3 of ($s*) or
            any of ($malicious_url, $malicious_domain) or
            $hex1
        )
}

/*
Explanation
Strings Section: Contains textual and binary patterns that are POTENTIALLY unique to BUSHWALK. 
Strings can include:
Filenames like bushwalk.dll or paths related to BUSHWALK's behavior.
Execution commands or registry modifications.
Known malicious URLs or domains used for command and control (C2).
Binary patterns or hexadecimal strings derived from static analysis.

Condition Section:
Checks if the file is a Windows Portable Executable (PE) or an ELF binary, using uint16(0) == 0x4d5a (for PE files) or uint32(0) == 0x7f454c46 (for ELF binaries).
Triggers the rule if:
Three or more of the specified strings match.
Any malicious URL, domain, or hex pattern matches.


Next Steps:
Refine Indicators:
Include specific strings, domains, or hex patterns if available.
Replace placeholders with actual C2 domains or known malicious strings from intelligence reports or BUSHWALK samples.

Testing:
Ensure the rule doesn’t produce false positives on benign files.
Adapt to Context:
Modify the condition to align with your  environment (e.g., focus on certain file types, network artifacts, or execution patterns).

*/
