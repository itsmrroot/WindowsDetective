/*
    Windows Detective - starter YARA rules
    Powered by Bashar Salmo

    Used automatically when tools\yara64.exe exists. Add your own .yar files to this
    folder (e.g. from github.com/Neo23x0/signature-base or github.com/elastic/protections-artifacts).
    Sensitive strings are hex-encoded so this file is not itself flagged by antivirus.
*/

rule WD_Mimikatz
{
    meta:
        author = "Windows Detective (Bashar Salmo)"
        description = "Mimikatz credential dumper (strings)"
        mitre = "T1003"
    strings:
        $a0 = { 73 65 6B 75 72 6C 73 61 3A 3A 6C 6F 67 6F 6E 70 61 73 73 77 6F 72 64 73 }  // seku...
        $w0 = { 73 00 65 00 6B 00 75 00 72 00 6C 00 73 00 61 00 3A 00 3A 00 6C 00 6F 00 67 00 6F 00 6E 00 70 00 61 00 73 00 73 00 77 00 6F 00 72 00 64 00 73 00 }
        $a1 = { 6C 73 61 64 75 6D 70 3A 3A 73 61 6D }  // lsad...
        $w1 = { 6C 00 73 00 61 00 64 00 75 00 6D 00 70 00 3A 00 3A 00 73 00 61 00 6D 00 }
        $a2 = { 67 65 6E 74 69 6C 6B 69 77 69 }  // gent...
        $w2 = { 67 00 65 00 6E 00 74 00 69 00 6C 00 6B 00 69 00 77 00 69 00 }
        $a3 = { 6D 69 6D 69 6B 61 74 7A 2E 65 78 65 }  // mimi...
        $w3 = { 6D 00 69 00 6D 00 69 00 6B 00 61 00 74 00 7A 00 2E 00 65 00 78 00 65 00 }
    condition:
        uint16(0) == 0x5A4D and 2 of them
}

rule WD_CobaltStrike_Beacon
{
    meta:
        author = "Windows Detective (Bashar Salmo)"
        description = "Cobalt Strike beacon artefacts"
        mitre = "T1071.001"
    strings:
        $b0 = { 62 65 61 63 6F 6E 2E 78 36 34 2E 64 6C 6C }
        $b1 = { 62 65 61 63 6F 6E 2E 64 6C 6C }
        $b2 = { 25 30 32 64 2F 25 30 32 64 2F 25 30 32 64 20 25 30 32 64 3A 25 30 32 64 3A 25 30 32 64 }
        $b3 = { 52 65 66 6C 65 63 74 69 76 65 4C 6F 61 64 65 72 }
        $cfg = { 00 01 00 01 00 02 ?? ?? 00 02 00 01 00 02 ?? ?? }  // beacon config header
    condition:
        uint16(0) == 0x5A4D and (2 of ($b*) or $cfg)
}

rule WD_Rclone
{
    meta:
        author = "Windows Detective (Bashar Salmo)"
        description = "rclone binary (often renamed) used for data exfiltration"
        mitre = "T1567.002"
    strings:
        $a = "github.com/rclone/rclone" ascii
        $b = "rclone.org" ascii
    condition:
        uint16(0) == 0x5A4D and all of them
}

rule WD_Renamed_RMM_AnyDesk
{
    meta:
        author = "Windows Detective (Bashar Salmo)"
        description = "AnyDesk binary (detects renamed copies)"
        mitre = "T1219"
    strings:
        $a = "AnyDesk Software GmbH" ascii wide
        $b = "anydesk.com" ascii wide nocase
    condition:
        uint16(0) == 0x5A4D and all of them
}

rule WD_Encoded_PowerShell_In_File
{
    meta:
        author = "Windows Detective (Bashar Salmo)"
        description = "Script/LNK/document containing a long encoded PowerShell command"
        mitre = "T1059.001,T1027"
    strings:
        $a = /powershell(\.exe)?[^\n]{0,80}\s-[eE][a-zA-Z]{0,14}\s+[A-Za-z0-9+\/=]{200,}/ ascii wide nocase
    condition:
        filesize < 5MB and $a
}

rule WD_Suspicious_LNK_Interpreter
{
    meta:
        author = "Windows Detective (Bashar Salmo)"
        description = "Shortcut file that launches a script interpreter"
        mitre = "T1204.002"
    strings:
        $p1 = "powershell" ascii wide nocase
        $p2 = "mshta" ascii wide nocase
        $p3 = "cmd.exe /c" ascii wide nocase
        $p4 = "wscript" ascii wide nocase
    condition:
        uint32(0) == 0x0000004C and filesize < 1MB and any of them
}
