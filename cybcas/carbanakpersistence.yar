rule Detect_Carbanak_Persistence
{
    meta:
        description = "Detects potential persistence techniques used by Carbanak malware"
        author = "CybCas"
        reference = "https://attack.mitre.org/groups/G0008/"
        date = "2025-01-12"
        version = "1.0"
        threat_actor = "Carbanak (FIN7)"
    
    strings:
        // Scheduled tasks and registry-based persistence
        $schtasks_create = "schtasks.exe /create /tn"             // Task scheduling for persistence
        $reg_run_key = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" // Common Run key
        $reg_value = "svchost"                                   // Example malware registry value

        // File-based persistence artifacts
        $file_temp = "C:\\Windows\\Temp\\*.exe"                  // Droppers or executables in Temp
        $file_appdata = "C:\\Users\\*\\AppData\\Roaming\\*.exe"  // Files in Roaming directory
        $file_programdata = "C:\\ProgramData\\*.exe"             // Malware in ProgramData directory

        // Abused system binaries for persistence
        $abused_binary_1 = "svchost.exe"                         // Legitimate name used maliciously
        $abused_binary_2 = "explorer.exe"                        // Another common impersonation name

    condition:
        any of ($schtasks_create, $reg_run_key, $reg_value, $file_temp, $file_appdata, $file_programdata, $abused_binary_1, $abused_binary_2)
}

/*
Key Features of Rule:
Identifies persistence techniques, such as:
Use of schtasks.exe for creating scheduled tasks.
Modifications to registry Run keys for auto-start on boot.
Placement of executables in Temp, Roaming, or ProgramData.
Abused system binary names (svchost.exe, explorer.exe) for disguise.

How to Use:
Scan disk images, registry hives, or live systems for persistence artifacts.
Integrate into endpoint detection and response (EDR) tools for automated scans.
*/
