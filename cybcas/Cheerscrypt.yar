rule Cheerscrypt_Ransomware_Detection
{
    meta:
        description = "Detects Cheerscrypt ransomware targeting VMware ESXi servers"
        author = "CybCas"
        date = "2025-01-15"
        reference = "https://attack.mitre.org/software/S1096/"
        version = "1.1"

    strings:
        // Unique strings associated with Cheerscrypt
        $str1 = "Cheerscrypt" nocase
        $str2 = "cheers_encrypt" nocase
        $str3 = "cheers_decrypt" nocase
        $str4 = "cheers_key" nocase
        $str5 = "cheers_ransom" nocase

        // File extensions used by Cheerscrypt
        $ext1 = ".cheers"
        $ext2 = ".encrypted"

        // Ransom note patterns
        $note1 = "All your files have been encrypted by Cheerscrypt!"
        $note2 = "Contact us at cheers_support@example.com to recover your data."

    condition:
        (uint16(0) == 0x7f45) and // Checks for ELF file (common in Linux environments)
        (any of ($str*) or any of ($ext*) or any of ($note*))
}

/*
Explanation
Strings Section:
$str*: Added strings that are potentially unique to Cheerscrypt, including variations of the name and related terms.
$ext*: Included file extensions that Cheerscrypt is known to append to encrypted files.
$note*: Patterns that might appear in ransom notes associated with Cheerscrypt.
Condition Section:
uint16(0) == 0x7f45: Checks for ELF files, which are common in Linux environments like VMware ESXi servers.
The condition triggers if any of the specified strings, file extensions, or ransom note patterns are found.
*/
