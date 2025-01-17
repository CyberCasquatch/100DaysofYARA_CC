rule Detect_MacSpy
{
    meta:
        description = "Detects MacSpy spyware for macOS"
        author = "CybCas"
        date = "2025-01-18"
        reference = "https://attack.mitre.org/software/S0282/"
        version = "1.0"

    strings:
        $malicious_url = "macspy.io" nocase
        $screenshot_function = "screencapture -x" nocase
        $audio_capture = "afplay" nocase
        $keylogger_pattern = "CGEventTapCreate"
        $encrypted_data = "AES-256-CBC" nocase
        $plist_persistence = "com.apple.loginitems"
        $path = "/Users/Shared/.macspy/"
        $c2_server = /https?:\/\/[a-z0-9\-\.]+\/macspy/ nocase

    condition:
        any of ($malicious_url, $screenshot_function, $audio_capture, $keylogger_pattern, $encrypted_data, $plist_persistence, $path, $c2_server)
}

/*
Key Features
$malicious_url: Detects potential references to known MacSpy domains.
$screenshot_function: Targets MacSpy's use of screencapture to take screenshots.
$audio_capture: Matches the afplay utility used for audio capture.
$keylogger_pattern: Identifies use of CoreGraphics APIs for keylogging.
$encrypted_data: Matches references to encryption methods like AES-256-CBC, used for data exfiltration.
$plist_persistence: Detects references to macOS login items for persistence.
$path: Targets known installation directories for MacSpy.
$c2_server: Matches C2 server URLs associated with MacSpy.
Condition, Triggers if any of the specified strings are found, ensuring broad coverage.
*/
