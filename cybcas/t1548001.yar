rule Detect_Setuid_Setgid_Privilege_Escalation
{
    meta:
        description = "Detects potential privilege escalation via Setuid and Setgid bits"
        author = "Your Name"
        reference = "https://attack.mitre.org/techniques/T1548/001/"
        date = "2025-01-09"
        version = "1.0"

    strings:
        $chmod_suid = /chmod\s(\+|4|u\+|g\+)s/  // Detect chmod commands setting SUID/SGID bits
        $setuid_function = "setuid"            // Common function call in exploits
        $setgid_function = "setgid"            // Common function call in exploits
        $common_suid_binary = /\/bin\/su|\/bin\/bash|\/usr\/bin\/sudo|\/usr\/bin\/pkexec/  // Common binaries exploited

    condition:
        any of ($chmod_suid, $setuid_function, $setgid_function) or
        $common_suid_binary
}

/*
Strings:
$chmod_suid: Regex pattern to detect chmod commands adding setuid or setgid bits.
$setuid_function and $setgid_function: Detects the presence of setuid and setgid functions in binaries, which are often abused.
$common_suid_binary: Matches well-known binaries that commonly have setuid or setgid bits set and are abused in attacks.

Condition:
Triggers if any of the specified patterns are found in a file or process.

*/
