rule Lowball_Malware
{
    meta:
        author = "CybCas"
        description = "Detects Lowball malware and associated artifacts"
        reference = "https://attack.mitre.org/software/S0042/, https://malpedia.caad.fkie.fraunhofer.de/details/win.lowball, https://cve.nohackme.com/index.php?action=mitre_malwares&id=S0042, https://www.linkedin.com/pulse/lowball-malware-arpit-sharma/"
        date = "2025-01-07"
        version = "1.2"

    strings:
        // MD5 hashes of known malicious files
        $md5_lowball_1 = "b9208a5b0504cb2283b1144fc455eaaa" // "使命公民運動 我們的異象.doc"
        $md5_lowball_2 = "ec19ed7cddf92984906325da59f75351" // "新聞稿及公佈.doc"
        $md5_lowball_3 = "6495b384748188188d09e9d5a0c401a4" // "(代發)[采訪通知]港大校友關注組遞信行動.doc"
        $md5_time_exe = "d76261ba3b624933a6ebb5dd73758db4" // "time.exe"
        $md5_wmiapcom = "79b68cdd0044edd4fbf8067b22878644" // "WmiApCom.bat"
        $md5_bubblewrap = "0beb957923df2c885d29a9c1743dd94b" // "accounts.serveftp.com"

        // Known filenames
        $filename1 = "使命公民運動 我們的異象.doc" wide ascii
        $filename2 = "新聞稿及公佈.doc" wide ascii
        $filename3 = "(代發)[采訪通知]港大校友關注組遞信行動.doc" wide ascii
        $filename_time = "time.exe" wide ascii
        $filename_wmiapcom = "WmiApCom.bat" wide ascii

        // Dropbox API reference
        $dropbox_api = "api.dropbox.com" wide ascii
        $bearer_token = "Bearer" ascii

        // Commands observed in batch files
        $cmd1 = "dir c:\\ >> %temp%\\download" ascii
        $cmd2 = "ipconfig /all >> %temp%\\download" ascii
        $cmd3 = "net user /domain >> %temp%\\download" ascii
        $cmd4 = "netstat -ano >> %temp%\\download" ascii

        // BUBBLEWRAP C2 domain
        $c2_domain = "accounts.serveftp.com" wide ascii

    condition:
        // Match any known MD5, filenames, strings, or command patterns
        any of ($md5_*) or
        any of ($filename*) or
        $dropbox_api or $bearer_token or
        any of ($cmd*) or
        $c2_domain
}
