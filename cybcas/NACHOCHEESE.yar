rule NachoCheese_Tunneler_Detection
{
    meta:
        description = "Detects NachoCheese tunneler with detailed strings and indicators"
        author = "CybCas"
        date = "2025-01-15"
        reference = "FireEye NachoCheese Malware Profile"
        version = "2.0"

    strings:
        // Command-line parameters and keywords
        $cmd1 = "-proxy" nocase
        $cmd2 = "-forward" nocase
        $cmd3 = "-tunnel" nocase
        $cmd4 = "-config" nocase
        $cmd5 = "-listen" nocase
        $cmd6 = "|proxy_username:password" nocase
        $cmd7 = "C&C address|endpoint address|proxy address" nocase

        // Hardcoded strings in the malware
        $string1 = "kliyent2podklyuchit" // "client to connect"
        $string2 = "Nachalo" // "beginning"
        $string3 = "Dazdrav$958478Zohsf9q@%5555ahshdnZXniohs"
        $string4 = "poluchit" // "to receive"
        $string5 = "vykhodit" // "to exit"
        $string6 = "ssylka" // "link"

        // Python-based encoding artifacts
        $py1 = "bytearray(sys.argv[1])"
        $py2 = "key = bytearray(\"cEzQfoPw\")"
        $py3 = "byte ^= k"

        // File characteristics and behaviors
        $file1 = "nachocheese.conf" nocase
        $file2 = "proxy_settings.json" nocase

    condition:
        (uint16(0) == 0x4D5A or uint16(0) == 0x7f45) and // PE or ELF file check
        (any of ($cmd*) or any of ($string*) or any of ($py*) or any of ($file*))
}

/*
Explanation..
Strings Section:
Command-Line Parameters: Includes NachoCheese tunneling options (-proxy, -forward, etc.) and C&C argument formats (e.g., proxy_username:password).
Hardcoded Strings: Contains unique Russian-language strings (e.g., kliyent2podklyuchit, Dazdrav...) used for communication and false flags.
Python Encoding Snippets: Targets key parts of NachoCheese’s encoding algorithm, such as XOR operations with keys like cEzQfoPw.
File Names: Matches potential configuration files like nachocheese.conf.
Condition Section:
PE or ELF Check: Ensures the file is a Windows or Linux executable.
Triggering: Activates if any specified command-line options, strings, Python artifacts, or file names are found.
This rule aims to detect NachoCheese malware using static signatures from known characteristics.
*/
