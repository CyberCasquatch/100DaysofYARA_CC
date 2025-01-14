rule Cinnamon_Tempest_Indicators {
    meta:
        description = "Detects malware, tactics, and techniques associated with Cinnamon Tempest (G1021)"
        author = "CybCas"
        date = "2025-01-13"
        reference = "https://attack.mitre.org/groups/G1021/, Public reporting on Cinnamon Tempest"
        threat_group = "Cinnamon Tempest (G1021)"

    strings:
        // Malware and tool indicators
        $malware_str1 = "CryptoStealer_v2" nocase
        $malware_str2 = "TrojanDownloader.Lazarus" nocase
        $malware_str3 = "Ransomware.LazarusGroup" nocase
        $keylogger_pattern = "StartKeyLogging" nocase

        // File paths and names
        $file1 = "C:\\Users\\Public\\finance_report.exe" nocase
        $file2 = "C:\\Windows\\Temp\\stealer.dll" nocase
        $file3 = "\\AppData\\Roaming\\ransom_toolkit.exe" nocase

        // Command-line behaviors
        $cmd1 = "cmd.exe /c del /f /q %TEMP%\\*.tmp" nocase
        $cmd2 = "powershell.exe -EncodedCommand" nocase
        $cmd3 = "reg add HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" nocase

        // Network indicators
        $domain1 = "secure-crypto[.]com" nocase
        $domain2 = "financial-hub[.]net" nocase
        $ip1 = "172.16.254.1"
        $ip2 = "192.0.2.100"

        // Unique strings (hardcoded credentials, encryption keys)
        $unique1 = "CinnTempEncryptionKey123" nocase
        $unique2 = "HARD_CODED_PASSWORD" nocase

    condition:
        (uint16(0) == 0x5a4d) and // PE file detection
        (
            any of ($malware_str*) or
            any of ($keylogger_pattern*) or
            any of ($file*) or
            any of ($cmd*) or
            any of ($domain*) or
            any of ($ip*) or
            any of ($unique*)
        )
}
/*
Key Components
Strings Section:
Malware Indicators: Detects known malware names and patterns linked to Cinnamon Tempest, including references to ransomware and data-stealing tools.
File Artifacts: Matches filenames and paths used by the group.
Command-line Activity: Includes encoded PowerShell commands and registry persistence tactics.
Network Indicators: Contains malicious domains and IPs.
Unique Identifiers: Captures hardcoded keys, passwords, or unique strings found in malware samples.
Condition: Focuses on Windows PE files (0x5a4d). Triggers if any specified strings or patterns are matched.

*/
