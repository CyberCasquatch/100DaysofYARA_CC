/* Generic Rule
*/
rule WarzoneRAT_Detection {
    meta:
        description = "Detects the presence of Warzone RAT malware."
        author = "CybCas"
        date = "2025-01-26"
        reference = "https://attack.mitre.org/software/S0670/"
        version = "1.0"
        malware_family = "Warzone RAT"

    strings:
        // Common indicators associated with Warzone RAT
        $str1 = "Warzone" nocase
        $str2 = "WarzoneRAT" nocase
        $str3 = "RemoteAccess" nocase
        $str4 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide ascii
        $str5 = "cmd.exe /c start" wide ascii
        $str6 = "keylogger" nocase
        $str7 = "connection.php" nocase
        $str8 = "/gate.php" nocase

        // Known IP address patterns or URL fragments
        $network1 = "http://warzonepanel" nocase
        $network2 = "/socket.io/" nocase
        $network3 = "/webhook/" nocase

        // File indicators (may need to adjust based on observed behavior)
        $file1 = "warzoneclient.exe" nocase
        $file2 = "payload.dll" nocase
        $file3 = "dropper.exe" nocase

    condition:
        // Trigger if three or more strings match in a sample
        (uint16(0) == 0x5A4D) and (filesize < 5MB) and 
        (3 of ($str*) or 2 of ($network*) or 2 of ($file*))
}

/*
Explanation of the Rule
Strings Section: Includes specific strings that are commonly seen in Warzone RAT samples (e.g., registry entries, file names, URLs, and other textual artifacts).
Condition Section: Combines conditions to limit false positives:
Checks if the file starts with the MZ header (0x5A4D) to target executables.
Limits the file size to under 5MB for practicality.
Matches against at least three of the strings defined.

Customization
You can add more specific indicators or adjust the thresholds based on your detection needs.
If you have access to Warzone RAT samples, analyse them with tools like PEStudio, strings, or sandbox environments to extract unique artifacts for the rule.
*/
