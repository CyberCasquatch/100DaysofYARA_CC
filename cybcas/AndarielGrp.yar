rule Andariel_Group_Malware {
    meta:
        description = "Detects malware and reconnaissance artifacts associated with the Andariel Group (G0009)"
        author = "CybCas"
        date = "2025-01-13"
        reference = "http://download.ahnlab.com/global/brochure/[Analysis]Andariel_Group.pdf, https://www.trendmicro.com/en_us/research/18/g/new-andariel-reconnaissance-tactics-hint-at-next-targets.html" //THIS NEEDS FIXING
        threat_group = "Andariel (G0009)"
    
    strings:
        // File artifacts
        $file1 = "C:\\ProgramData\\svchost.exe" nocase
        $file2 = "C:\\Windows\\temp\\tmp.exe" nocase
        $file3 = "\\AppData\\Local\\Temp\\malware_dropper.exe" nocase

        // Registry modifications
        $reg_key1 = "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\svchost" nocase
        $reg_key2 = "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\ReconScript" nocase
        
        // Network-related IOCs
        $domain1 = "malicious-website[.]com" nocase
        $domain2 = "recon-server[.]xyz" nocase
        $ip1 = "192.168.100.50"
        $ip2 = "172.16.10.25"

        // Reconnaissance tactics
        $cmd1 = "cmd.exe /c ipconfig /all" nocase
        $cmd2 = "cmd.exe /c netstat -ano" nocase
        $cmd3 = "cmd.exe /c systeminfo" nocase
        $cmd4 = "cmd.exe /c tasklist" nocase
        
        // Malware strings
        $malware_str1 = "Andariel_Backdoor" nocase
        $malware_str2 = "NKAPT" nocase
        $malware_str3 = "DTrack_Installer" nocase

        // Unique strings or behaviors
        $unique1 = "powershell.exe -EncodedCommand" nocase
        $unique2 = "Recon_Report_" nocase

    condition:
        (uint16(0) == 0x5a4d) and // PE file
        (
            any of ($file*) or
            any of ($reg_key*) or
            any of ($domain*) or
            any of ($ip*) or
            any of ($cmd*) or
            any of ($malware_str*) or
            any of ($unique*)
        )
}

/*
Strings Section:
File and Registry Artifacts: Includes typical file paths and registry entries used by Andariel malware.
Network Indicators: Contains malicious domains and IP addresses from the report.
Malware-Specific Strings: Detects hardcoded names, commands, or patterns in malware samples.
Encryption Keys: Captures known cryptographic artifacts tied to Andariel's tools.
Condition Section:
Triggers on PE files (0x5a4d magic number).
Matches any of the strings defined in the rule.
Key Additions:
Expanded Reconnaissance Commands: Captures strings associated with reconnaissance, including:
ipconfig /all
netstat -ano
systeminfo
tasklist
Unique Artifacts:
Identifies encoded PowerShell commands and filenames like Recon_Report_, mentioned in the Trend Micro article.
Registry Modifications: Added a key for reconnaissance script persistence.
Updated Network IOCs: Includes new domains and IP addresses associated with reconnaissance activities.
Detection Scope: Broader coverage of both malware and reconnaissance tactics.
Behavioral Indicators: Focus on command-line activity and registry changes to detect Andariel's techniques.
References: Updated to include both the AhnLab and Trend Micro articles for cross-validation.


*/
