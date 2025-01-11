rule Detect_Carbanak_Malware
{
    meta:
        description = "Detects potential artifacts related to Carbanak malware"
        author = "YCybCas"
        reference = "https://attack.mitre.org/groups/G0008/"
        date = "2025-01-10"
        version = "1.0"
        threat_actor = "Carbanak (FIN7)"
    
    strings:
        // Known Carbanak strings
        $carbanak_cmd_1 = "cmd.exe /c ping -n 1 127.0.0.1 > nul & del" // Command for self-deletion
        $carbanak_cmd_2 = "schtasks.exe /create /tn"                   // Used for persistence
        $carbanak_keyword_1 = "CarbanakConnect"                       // String from Carbanak modules
        $carbanak_keyword_2 = "CarbanakLoader"                        // Malware loader reference
        $carbanak_c2_1 = /https?:\/\/[a-z0-9\-\.]+\/news\/[a-z]+/     // Example C2 pattern
        $carbanak_ip = /172\.(16|31)\.\d{1,3}\.\d{1,3}/               // Example internal IP ranges

        // Suspicious API calls
        $api_virtualalloc = "VirtualAlloc"                            // Memory allocation
        $api_writeprocessmemory = "WriteProcessMemory"               // Injection technique
        $api_createremotethread = "CreateRemoteThread"                // Remote execution

        // File paths and artifacts
        $file_path_temp = "C:\\Windows\\Temp\\*.exe"                  // Malware often placed in Temp
        $file_path_appdata = "C:\\Users\\*\\AppData\\Roaming\\*.exe"  // Malware in Roaming directory

        // Known filenames
        $file_name_1 = "svchost.exe"                                  // Legitimate name often abused
        $file_name_2 = "explorer.exe"                                 // Legitimate name often abused

    condition:
        any of ($carbanak_cmd_1, $carbanak_cmd_2, $carbanak_keyword_1, $carbanak_keyword_2) or
        any of ($carbanak_c2_1, $carbanak_ip) or
        any of ($api_virtualalloc, $api_writeprocessmemory, $api_createremotethread) or
        any of ($file_path_temp, $file_path_appdata, $file_name_1, $file_name_2)
}

/*
Key Features of This Rule:
Carbanak-Specific Commands:
Detects suspicious commands like self-deletion via cmd.exe or task scheduling with schtasks.exe.
Known Strings:
Includes keywords directly tied to Carbanak's malware modules (e.g., "CarbanakConnect").
Network Indicators:
Matches HTTP/HTTPS patterns and known IP ranges for command-and-control (C2) communication.
API Calls:
Detects API functions commonly used by Carbanak for process injection and memory manipulation.
File Artifacts:
Monitors for suspicious file paths (e.g., Temp and AppData) and abused legitimate filenames.
How to Use:
Deploy this rule to scan memory dumps, logs, or binary files in your environment.
Use with tools like YARA on endpoints, in malware sandboxes, or on network traffic logs.
Update the rule as new indicators of compromise (IoCs) or TTPs related to Carbanak emerge.
*/
