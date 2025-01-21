rule DarkTortilla_Crypter
{
    meta:
        description = "Detects DarkTortilla .NET-based crypter"
        author = "CybCas"
        reference = "https://attack.mitre.org/software/S1066/"
        date = "2025-01-21"
        version = "1.0"

    strings:
        $string1 = "EncryptedPayload" wide ascii nocase
        $string2 = "Microsoft.Win32.Registry" wide ascii nocase
        $string3 = "System.Management" wide ascii nocase
        $string4 = "System.IO.Compression" wide ascii nocase
        $string5 = "DarkTortilla" wide ascii nocase
        $string6 = { E8 ?? ?? ?? ?? 5D C3 55 8B EC } // Example of common obfuscation patterns

    condition:
        uint16(0) == 0x5A4D and // PE file
        any of ($string*) and
        filesize < 5MB
}

/*
Creating a YARA rule for detecting the .NET-based crypter DarkTortilla requires understanding its unique characteristics, including known file patterns, strings, behaviors, or metadata. DarkTortilla is often used to obfuscate malicious payloads and evade detection.

Explanation of Rule Components:
Strings Section: 
Includes known strings related to DarkTortilla, such as registry usage, system management references, and obfuscation techniques.
Added wide and ascii modifiers to cover different encoding schemes.
Included a sample byte sequence ($string6) for a known obfuscation pattern.
Condition Section:
Checks that the file is a PE file (uint16(0) == 0x5A4D).
Matches any defined string.
Limits the file size to <5MB, which is typical for DarkTortilla samples.

Customisation:
Analyze Specific Samples:
Use tools like IDA Pro, Ghidra, or strings to extract additional indicators unique to DarkTortilla samples.
Test and Validate:
Test the rule against known DarkTortilla samples and benign .NET applications to minimize false positives.
Enhance Indicators:
Incorporate additional known strings, imports, or behaviors from threat intelligence or sandbox reports.
*/
