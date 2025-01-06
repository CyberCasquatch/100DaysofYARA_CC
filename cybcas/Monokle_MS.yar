rule Monokle_Mobile_Surveillanceware
{
    meta:
        author = "CyberCasquatch"
        description = "Detects Monokle mobile surveillanceware"
        reference = "https://attack.mitre.org/software/S0407/"
        date = "2025-01-06"
        version = "1.0"

    strings:
        $str1 = "Monokle" nocase
        $str2 = "KeyloggerService" nocase
        $str3 = "/system/bin/monokle.so"
        $str4 = "com.monokle.services"
        $str5 = "monokle.settings" nocase
        $network1 = "https://api.monokle.[domain]" wide

        // Add more strings based on observed indicators, file paths, or constants

    condition:
        any of ($str*) or $network1
}
