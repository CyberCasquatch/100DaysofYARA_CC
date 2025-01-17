rule Detect_Hide_Artifacts
{
    meta:
        description = "Detects techniques used to hide artifacts, aligned with MITRE ATT&CK T1564"
        author = "YourName"
        date = "2025-01-18"
        reference = "https://attack.mitre.org/techniques/T1564/"
        version = "1.0"

    strings:
        // Windows-specific indicators
        $attrib_hidden = "attrib +h" nocase
        $timestomp_pattern = "SetFileTime" nocase
        $hidden_registry = "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Hidden"

        // macOS/Linux-specific indicators
        $chflags_hidden = "chflags hidden" nocase
        $dotfile_creation = "/.[a-zA-Z0-9]+" nocase
        $hide_process = "/proc/self" nocase

        // General obfuscation patterns
        $base64_encoded = /[A-Za-z0-9\/+=]{50,}/
        $hex_encoded = /\\x[a-fA-F0-9]{2}/
        $unicode_escape = /\\u[a-fA-F0-9]{4}/

    condition:
        2 of ($attrib_hidden, $timestomp_pattern, $hidden_registry, $chflags_hidden, $dotfile_creation, $hide_process, $base64_encoded, $hex_encoded, $unicode_escape)
}
/*
Explanation

Windows Indicators:
$attrib_hidden, Looks for the use of attrib to hide files.
$timestomp_pattern, Detects API calls like SetFileTime used to modify timestamps.
$hidden_registry, Identifies registry keys related to hidden files.

macOS/Linux Indicators:
$chflags_hidden, Matches the chflags hidden command on macOS.
$dotfile_creation, Detects creation of hidden dotfiles.
$hide_process, Matches /proc/self references, often used to hide processes.

General Obfuscation:
$base64_encoded, Matches large blocks of Base64-encoded data.
$hex_encoded and $unicode_escape, Detect obfuscated strings in scripts or binaries.

Condition:
The rule triggers if two or more strings are detected, providing flexibility while minimizing false positives.

Platform-Specific Variations
For Windows: Expand with additional techniques, like searching for specific PowerShell commands (Set-ItemProperty).
For macOS/Linux: Add patterns for common hiding commands like lsattr, rmattr, or manipulating /etc/rc.local.
*/
