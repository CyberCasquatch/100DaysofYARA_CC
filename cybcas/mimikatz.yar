rule Mimikatz_Detection
{
    meta:
        author = "CybCas"
        description = "Detects presence of Mimikatz on a compromised system"
        reference = "https://github.com/gentilkiwi/mimikatz"
        date = "2025-01-08"
        version = "1.0"

    strings:
        // Common filenames associated with Mimikatz
        $filename1 = "mimikatz.exe" nocase
        $filename2 = "mimikatz64.exe" nocase
        $filename3 = "mimilib.dll" nocase

        // Strings related to Mimikatz functionality
        $string1 = "sekurlsa::logonpasswords" nocase
        $string2 = "kerberos::tickets" nocase
        $string3 = "lsadump::sam" nocase
        $string4 = "sekurlsa::wdigest" nocase
        $string5 = "privilege::debug" nocase
        $string6 = "sekurlsa::msv" nocase

        // Mimikatz specific outputs
        $output1 = "Authentication Id :" nocase
        $output2 = "UserName : " nocase
        $output3 = "NTLM :" nocase
        $output4 = "Password : " nocase

        // Memory dump functionality
        $string7 = "sekurlsa::minidump" nocase
        $string8 = "sekurlsa::dpapi" nocase

        // Hardcoded directory paths
        $path1 = "C:\\Windows\\System32\\mimikatz.exe" nocase
        $path2 = "C:\\Users\\Public\\Downloads\\mimikatz.exe" nocase

    condition:
        // Match any of the known strings, filenames, or paths
        any of ($filename*) or
        any of ($string*) or
        any of ($output*) or
        any of ($path*)
}


/* 
Key Features:
File Names:
Recognises common file names associated with Mimikatz, such as mimikatz.exe and its DLL files.
Strings:
Detects specific commands and modules used by Mimikatz (sekurlsa::logonpasswords, kerberos::tickets, etc.).
Includes outputs produced by Mimikatz when extracting credentials (e.g., "NTLM", "Authentication Id").
Hardcoded Paths:
Identifies common directory paths where Mimikatz might be stored or executed.
Condition:
Triggers if any known file names, command strings, or hardcoded paths associated with Mimikatz are detected.
*/
