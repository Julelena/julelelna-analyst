<# ============================================================
JULELEN'S PRIVATE ANALYST V3.0.2 - Discord: julelena
============================================================
Defensive forensic tool focused on Minecraft screenshare checks.
Read-only evidence collection. Best run as Administrator.
#>

$ErrorActionPreference = "SilentlyContinue"

# ---------------- Pink Theme (ANSI Escapes) ----------------
$Pink       = "`e[38;5;205m"   # Bright pink
$LightPink  = "`e[38;5;218m"   # Softer pink
$Accent     = "`e[38;5;197m"   # Deep pink accent
$Reset      = "`e[0m"

# ---------------- UI Helpers ----------------
function Set-ConsoleTitle([string]$title) { try { $Host.UI.RawUI.WindowTitle = $title } catch {} }

function Show-Banner {
    Clear-Host
    Write-Host "$Pink============================================================$Reset"
    Write-Host "$LightPink     JULELEN'S PRIVATE ANALYST V3.0.2$Reset"
    Write-Host "$Pink     Discord: julelena$Reset"
    Write-Host "$Pink============================================================$Reset"
    Write-Host ""
}

function Show-ProgressBar([int]$Percent, [string]$Message) {
    $width = 50
    $filled = [Math]::Floor(($Percent / 100) * $width)
    $bar = ("=" * $filled) + (" " * ($width - $filled))
    $line = "$Pink[$bar]$Reset $LightPink{0,3}%$Reset $Message" -f $Percent
    [Console]::Write("`r$line".PadRight([Console]::WindowWidth - 1))
}

function Is-Admin {
    try {
        $id = [Security.Principal.WindowsIdentity]::GetCurrent()
        $p = New-Object Security.Principal.WindowsPrincipal($id)
        return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch { return $false }
}

function New-OutDir {
    $ts = Get-Date -Format "yyyyMMdd_HHmmss"
    $base = Join-Path (Get-Location) "JULELEN_PRIVATE_ANALYST_V3_0_2_$ts"
    New-Item -ItemType Directory -Path $base | Out-Null
    return $base
}

function Write-Text($path, $content) {
    $content | Out-File -FilePath $path -Encoding utf8 -Width 500
}

function Export-Json($path, $obj) {
    $obj | ConvertTo-Json -Depth 7 | Out-File -FilePath $path -Encoding utf8
}

function Export-CsvSafe($path, $obj) {
    try {
        $obj | Export-Csv -Path $path -NoTypeInformation -Encoding utf8
    } catch {
        ($obj | Out-String) | Out-File -FilePath ($path + ".txt") -Encoding utf8
    }
}

# ---------------- Findings Engine ----------------
$Findings = New-Object System.Collections.Generic.List[object]

function Add-Finding([string]$Severity, [string]$Category, [string]$Title, [string]$Detail, [string]$EvidencePath) {
    $sevRank = switch ($Severity) {
        "HIGH" { 3 }
        "MED"  { 2 }
        "LOW"  { 1 }
        default { 0 }
    }
    $Findings.Add([pscustomobject]@{
        Time = (Get-Date -Format o)
        Severity = $Severity
        SeverityRank = $sevRank
        Category = $Category
        Title = $Title
        Detail = $Detail
        Evidence = $EvidencePath
    }) | Out-Null
}

# ---------------- Depth-Limited Filesystem Scan ----------------
function Get-ChildItemDepth {
    param(
        [Parameter(Mandatory=$true)][string]$Path,
        [int]$Depth = 4,
        [switch]$DirectoriesOnly,
        [string]$Filter = $null
    )
    if ($Depth -lt 0) { return @() }

    $items = @()
    try {
        $gciArgs = @{ LiteralPath = $Path; Force = $true; ErrorAction = "SilentlyContinue" }
        if ($DirectoriesOnly) { $gciArgs["Directory"] = $true }
        if ($Filter) { $gciArgs["Filter"] = $Filter }
        $items = Get-ChildItem @gciArgs
    } catch { return @() }

    if ($Depth -eq 0) { return $items }

    $subDirs = Get-ChildItem -LiteralPath $Path -Directory -Force -ErrorAction SilentlyContinue
    foreach ($d in $subDirs) {
        $items += Get-ChildItemDepth -Path $d.FullName -Depth ($Depth - 1) -DirectoriesOnly:$DirectoriesOnly -Filter $Filter
    }
    return $items
}

# ---------------- Unicode Detection ----------------
function Detect-UnicodeNames($items) {
    $unicodeHits = $items | Where-Object { $_.Name -match "[\u200B-\u200D\uFEFF]" -or $_.Name -notmatch "^[\x00-\x7F]+$" }
    return $unicodeHits
}

# ---------------- Simple Entropy Calc ----------------
function Get-FileEntropy($path) {
    try {
        $bytes = [System.IO.File]::ReadAllBytes($path)
        $freq = New-Object int[] 256
        foreach ($b in $bytes) { $freq[$b]++ }
        $entropy = 0.0
        $len = $bytes.Length
        for ($i = 0; $i -lt 256; $i++) {
            if ($freq[$i] -gt 0) {
                $p = [double]$freq[$i] / $len
                $entropy -= $p * [Math]::Log($p, 2)
            }
        }
        return [Math]::Round($entropy, 2)
    } catch { return -1 }
}

# ---------------- Start ----------------
Set-ConsoleTitle "JULELEN'S PRIVATE ANALYST V3.0.2 - Discord: julelena"
Show-Banner

$admin = Is-Admin
if (-not $admin) {
    Write-Host "${Pink}WARNING:${Reset} Not running as Administrator. Some checks may be limited." -ForegroundColor Yellow
    Write-Host ""
}

Show-ProgressBar 0 "Initializing..."

$out = New-OutDir

$F = @{
    System      = Join-Path $out "01_System"
    Process     = Join-Path $out "02_Process"
    Network     = Join-Path $out "03_Network"
    Persistence = Join-Path $out "04_Persistence"
    Logs        = Join-Path $out "05_Logs"
    FileSystem  = Join-Path $out "06_FileSystem"
    Minecraft   = Join-Path $out "07_Minecraft"
    Forensics   = Join-Path $out "08_Forensics"
    Findings    = Join-Path $out "09_Findings"
}
$F.Values | ForEach-Object { New-Item -ItemType Directory -Path $_ | Out-Null }

$transcriptPath = Join-Path $out "console_transcript.txt"
try { Start-Transcript -Path $transcriptPath | Out-Null } catch {}

$summary = New-Object System.Collections.Generic.List[string]
$summary.Add("JULELEN'S PRIVATE ANALYST V3.0.2 SUMMARY")
$summary.Add("Timestamp: " + (Get-Date -Format o))
$summary.Add("Admin: " + $admin)
$summary.Add("OutputDir: " + $out)
$summary.Add("")

# Regex patterns
$Regex_EnvSubstr   = "%[A-Za-z0-9_]+:~\d+,\d+%"
$Regex_CaretObf    = "\^"
$Regex_EncodedPS   = "(?i)(\-enc|\-encodedcommand)\s+"
$Regex_ScriptHost  = "(?i)\b(powershell|pwsh|cmd|wscript|cscript|mshta|rundll32|regsvr32|installutil|forfiles|bitsadmin|certutil|schtasks|wevtutil|java|javaw)\b"
$Regex_Unicode     = "[\u200B-\u200D\uFEFF]"
$Regex_NoExtension = "^[^\.]+$"
$Regex_RenamedExt  = "\.(png|txt|jpg|bmp|ini|log|dat|tmp|old|bak)$"
$Regex_Suspicious  = "(?i)proxy|inject|hook|cheat|hack|aimbot|reach|velocity|autopot|killaura"

$roots = @($env:APPDATA, $env:LOCALAPPDATA, $env:ProgramData, $env:ProgramFiles, ${env:ProgramFiles(x86)}, $env:TEMP) | Where-Object { $_ } | Select-Object -Unique
$mcRoot = Join-Path $env:APPDATA ".minecraft"
if (Test-Path $mcRoot) { $roots += $mcRoot }

# ---------------- Analysis Steps ----------------
$steps = @(
    @{ pct = 5; msg = "System baseline & USN query..."; action = { 
        $os = Get-CimInstance Win32_OperatingSystem
        Write-Text (Join-Path $F.System "system_info.txt") @(
            "LocalTime: $(Get-Date -Format o)"
            "User: $env:USERNAME"
            "OS: $($os.Caption) Build $($os.BuildNumber)"
            "Boot: $($os.LastBootUpTime)"
        )
        cmd /c "fsutil usn queryjournal C:" > (Join-Path $F.Forensics "usn_C.txt") 2>&1
    }},
    @{ pct = 15; msg = "Snapshotting Processes & Command Lines..."; action = {
        $procs = Get-CimInstance Win32_Process | Select-Object ProcessId, ParentProcessId, Name, ExecutablePath, CommandLine, CreationDate
        Export-CsvSafe (Join-Path $F.Process "processes_full.csv") ($procs | Sort-Object Name)

        $uw = $procs | Where-Object { $_.ExecutablePath -match "\\Users\\|\\AppData\\|\\Temp\\|\\ProgramData\\" }
        Export-CsvSafe (Join-Path $F.Process "processes_userwritable.csv") $uw
        if ($uw.Count -gt 0) { Add-Finding "MED" "Process" "Processes in User-Writable Paths" "Review CSV." "02_Process\processes_userwritable.csv" }

        $obfHits = $procs | Where-Object { $_.CommandLine -match $Regex_EnvSubstr -or $_.CommandLine -match $Regex_CaretObf -or $_.CommandLine -match $Regex_EncodedPS }
        Export-CsvSafe (Join-Path $F.Findings "cmdline_obf_hits.csv") $obfHits
        if ($obfHits.Count -gt 0) { Add-Finding "MED" "CommandLine" "Obfuscated Command Lines" "Review." "09_Findings\cmdline_obf_hits.csv" }

        $lolHits = $procs | Where-Object { $_.CommandLine -match $Regex_ScriptHost }
        Export-CsvSafe (Join-Path $F.Findings "lolbin_hits.csv") $lolHits
        if ($lolHits.Count -gt 0) { Add-Finding "LOW" "CommandLine" "LOLBin/Script Host Usage" "Review." "09_Findings\lolbin_hits.csv" }

        $suspended = @()
        foreach ($p in $procs.ProcessId) {
            try {
                $threads = (Get-Process -Id $p -ErrorAction SilentlyContinue).Threads | Where-Object { $_.ThreadState -eq "Suspended" }
                if ($threads) { $suspended += [pscustomobject]@{PID=$p; SuspendedThreads=$threads.Count} }
            } catch {}
        }
        Export-CsvSafe (Join-Path $F.Process "suspended_threads.csv") $suspended
        if ($suspended.Count -gt 0) { Add-Finding "HIGH" "Process" "Suspended Threads Detected" "Review." "02_Process\suspended_threads.csv" }

        $hollowHits = @()
        foreach ($p in $procs) {
            if ($p.ExecutablePath -and (Test-Path $p.ExecutablePath)) {
                $fileMod = (Get-Item $p.ExecutablePath -ErrorAction SilentlyContinue).LastWriteTime
                if ($fileMod -and $p.CreationDate -lt $fileMod.AddMinutes(-5)) { $hollowHits += $p }
            }
        }
        Export-CsvSafe (Join-Path $F.Findings "potential_hollowing.csv") $hollowHits
        if ($hollowHits.Count -gt 0) { Add-Finding "HIGH" "Process" "Potential Process Hollowing" "Review." "09_Findings\potential_hollowing.csv" }

        $summary.Add("Processes Total: " + $procs.Count)
    }},
    @{ pct = 25; msg = "Integrity & Signature Checks..."; action = {
        $procs = Import-Csv (Join-Path $F.Process "processes_full.csv")
        $exePaths = $procs | Where-Object { $_.ExecutablePath -and (Test-Path $_.ExecutablePath) } | Select-Object -ExpandProperty ExecutablePath -Unique

        $integrityRows = @()
        foreach ($p in $exePaths) {
            $sig = Get-AuthenticodeSignature -FilePath $p -ErrorAction SilentlyContinue
            $hash = Get-FileHash -Algorithm SHA256 -LiteralPath $p -ErrorAction SilentlyContinue
            $entropy = Get-FileEntropy $p

            $status = if ($sig) { $sig.Status } else { "Unknown" }
            $signer = if ($sig.SignerCertificate) { $sig.SignerCertificate.Subject } else { "" }
            $sha256 = if ($hash) { $hash.Hash } else { "" }

            $integrityRows += [pscustomobject]@{
                Path = $p
                SignatureStatus = $status
                Signer = $signer
                SHA256 = $sha256
                Entropy = $entropy
            }

            if ($p -match "\\Windows\\|\\Program Files" -and $status -ne "Valid") {
                Add-Finding "HIGH" "Integrity" "Unsigned/Invalid Sig in System Path" "Review." "02_Process\integrity_checks.csv"
            }
            if ($entropy -gt 7.5) {
                Add-Finding "MED" "Integrity" "High Entropy File" "Review." "02_Process\integrity_checks.csv"
            }
        }
        Export-CsvSafe (Join-Path $F.Process "integrity_checks.csv") $integrityRows
    }},
    @{ pct = 35; msg = "Module Analysis for Java/Minecraft..."; action = {
        $procs = Get-CimInstance Win32_Process | Select-Object ProcessId, Name
        $targets = $procs | Where-Object { $_.Name -match "(?i)javaw|java|minecraft|anydesk" }
        Export-CsvSafe (Join-Path $F.Process "module_targets.csv") $targets

        foreach ($t in $targets) {
            try {
                $gp = Get-Process -Id $t.ProcessId -Module -ErrorAction SilentlyContinue
                if ($gp) {
                    $mods = $gp.Modules | Select-Object ModuleName, FileName, BaseAddress, ModuleMemorySize
                    $fn = "modules_pid$($t.ProcessId)_$($t.Name -replace '[^A-Za-z0-9]','_').csv"
                    Export-CsvSafe (Join-Path $F.Process $fn) $mods

                    $badMods = $mods | Where-Object { $_.FileName -match "\\Users\\|\\AppData\\|\\Temp\\|\\ProgramData\\" }
                    if ($badMods.Count -gt 0) { Add-Finding "HIGH" "Modules" "Modules from Writable Paths" "Review $fn" "02_Process\$fn" }

                    $proxyHits = $mods | Where-Object { $_.ModuleName -match $Regex_Suspicious }
                    if ($proxyHits.Count -gt 0) { Add-Finding "HIGH" "Modules" "Suspicious Module Names" "Review $fn" "02_Process\$fn" }
                }
            } catch {}
        }
    }},
    @{ pct = 40; msg = "Network Snapshot..."; action = {
        try { Get-NetTCPConnection | Export-CsvSafe (Join-Path $F.Network "net_tcp.csv") } catch {}
        cmd /c "ipconfig /displaydns" > (Join-Path $F.Network "dns_cache.txt") 2>$null
        $dnsContent = Get-Content (Join-Path $F.Network "dns_cache.txt") -ErrorAction SilentlyContinue
        if ($dnsContent -match "(?i)cheat|hack|proxy") { Add-Finding "MED" "Network" "Suspicious DNS Entries" "Review." "03_Network\dns_cache.txt" }
    }},
    @{ pct = 45; msg = "Services & Drivers..."; action = {
        Get-Service | Export-CsvSafe (Join-Path $F.System "services.csv")
        $suspendedSvcs = Get-Service | Where-Object { $_.Status -eq "Paused" }
        Export-CsvSafe (Join-Path $F.System "suspended_services.csv") $suspendedSvcs
        if ($suspendedSvcs.Count -gt 0) { Add-Finding "MED" "Services" "Paused Services Detected" "Review." "01_System\suspended_services.csv" }
        cmd /c "driverquery /si" > (Join-Path $F.System "drivers_signed.txt") 2>$null
    }},
    @{ pct = 55; msg = "Persistence Sweep..."; action = {
        cmd /c "schtasks /query /fo CSV /v" > (Join-Path $F.Persistence "tasks.csv") 2>$null

        $startupPaths = @("$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup", "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup")
        foreach ($sp in $startupPaths) {
            if (Test-Path $sp) {
                Get-ChildItem $sp -Force -ErrorAction SilentlyContinue | Export-CsvSafe (Join-Path $F.Persistence ("startup_" + (Split-Path $sp -Leaf) + ".csv"))
            }
        }

        $regKeys = @(
            "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
            "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
            "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
            "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows",
            "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options",
            "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit"
        )
        $regDir = Join-Path $F.Persistence "registry"
        New-Item -ItemType Directory $regDir -Force | Out-Null
        foreach ($key in $regKeys) {
            $safeName = $key -replace "[:\\]", "_"
            cmd /c "reg export `"$key`" `"$(Join-Path $regDir "$safeName.reg")`" /y" 2>$null
        }

        $xmlDir = Join-Path $F.Persistence "startup_xml"
        New-Item -ItemType Directory $xmlDir -Force | Out-Null
        Get-ChildItem "C:\Windows\System32\Tasks" -Filter *.xml -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
            Copy-Item $_.FullName $xmlDir -Force
        }
        if ((Get-ChildItem $xmlDir).Count -gt 0) { Add-Finding "MED" "Persistence" "Startup XML Tasks Found" "Review." "04_Persistence\startup_xml" }

        try {
            $wmiFilters = Get-CimInstance -Namespace root\subscription -Class __EventFilter -ErrorAction SilentlyContinue
            $wmiConsumers = Get-CimInstance -Namespace root\subscription -Class __EventConsumer -ErrorAction SilentlyContinue
            $wmiBindings = Get-CimInstance -Namespace root\subscription -Class __FilterToConsumerBinding -ErrorAction SilentlyContinue
            Export-CsvSafe (Join-Path $F.Persistence "wmi_filters.csv") $wmiFilters
            Export-CsvSafe (Join-Path $F.Persistence "wmi_consumers.csv") $wmiConsumers
            Export-CsvSafe (Join-Path $F.Persistence "wmi_bindings.csv") $wmiBindings
            if (($wmiFilters.Count + $wmiConsumers.Count + $wmiBindings.Count) -gt 0) {
                Add-Finding "HIGH" "Persistence" "WMI Persistence Artifacts" "Review." "04_Persistence"
            }
        } catch {}
    }},
    @{ pct = 60; msg = "PowerShell Artifacts..."; action = {
        $psDir = Join-Path $F.Persistence "ps_profiles"
        New-Item -ItemType Directory $psDir -Force | Out-Null
        @($PROFILE.AllUsersAllHosts, $PROFILE.AllUsersCurrentHost, $PROFILE.CurrentUserAllHosts, $PROFILE.CurrentUserCurrentHost) |
            Where-Object { $_ -and (Test-Path $_) } | ForEach-Object {
                Copy-Item $_ $psDir -Force
            }

        $psReadLine = Join-Path $env:APPDATA "Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
        if (Test-Path $psReadLine) { Copy-Item $psReadLine (Join-Path $F.Persistence "psreadline_history.txt") -Force }

        Get-Process | Where-Object { $_.Name -match "(?i)java|minecraft" } | Export-CsvSafe (Join-Path $F.Minecraft "miniss_java_processes.csv")
    }},
    @{ pct = 70; msg = "File System Forensics..."; action = {
        $reparse = @()
        foreach ($r in $roots) {
            $dirs = Get-ChildItemDepth $r -Depth 4 -DirectoriesOnly
            $reparse += $dirs | Where-Object { $_.Attributes -match "ReparsePoint" }
        }
        Export-CsvSafe (Join-Path $F.FileSystem "reparse_points.csv") $reparse
        if ($reparse.Count -gt 0) { Add-Finding "MED" "FileSystem" "Reparse Points Found" "Review." "06_FileSystem\reparse_points.csv" }

        $adsHits = @()
        foreach ($r in $roots) {
            Get-ChildItemDepth $r -Depth 4 | ForEach-Object {
                try {
                    Get-Item $_.FullName -Stream * -ErrorAction SilentlyContinue | Where-Object { $_.Stream -ne ':$DATA' } | ForEach-Object {
                        $adsHits += [pscustomobject]@{Path=$_.FileName; Stream=$_.Stream; Length=$_.Length}
                    }
                } catch {}
            }
        }
        Export-CsvSafe (Join-Path $F.FileSystem "ads_streams.csv") $adsHits
        if ($adsHits.Count -gt 0) { Add-Finding "MED" "FileSystem" "ADS Detected" "Review." "06_FileSystem\ads_streams.csv" }

        $unicodeFiles = @()
        foreach ($r in $roots) {
            $items = Get-ChildItemDepth $r -Depth 4
            $unicodeFiles += Detect-UnicodeNames $items
        }
        Export-CsvSafe (Join-Path $F.FileSystem "unicode_files.csv") $unicodeFiles
        if ($unicodeFiles.Count -gt 0) { Add-Finding "HIGH" "FileSystem" "Unicode Obfuscated Files" "Review." "06_FileSystem\unicode_files.csv" }

        $noExt = @()
        $renExt = @()
        foreach ($r in $roots) {
            $files = Get-ChildItemDepth $r -Depth 4
            $noExt += $files | Where-Object { $_.Name -match $Regex_NoExtension }
            $renExt += $files | Where-Object { $_.Extension -match $Regex_RenamedExt -and (Get-FileEntropy $_.FullName) -gt 6 }
        }
        Export-CsvSafe (Join-Path $F.FileSystem "no_extension_files.csv") $noExt
        Export-CsvSafe (Join-Path $F.FileSystem "renamed_extension_files.csv") $renExt
        if ($noExt.Count + $renExt.Count -gt 0) { Add-Finding "MED" "FileSystem" "Extensionless / Renamed Files" "Review." "06_FileSystem" }

        $bakFiles = Get-ChildItemDepth $mcRoot -Depth 3 -Filter "*.(bak|old|backup|tmp|orig)"
        Export-CsvSafe (Join-Path $F.FileSystem "bak_files.csv") $bakFiles
        if ($bakFiles.Count -gt 0) { Add-Finding "LOW" "FileSystem" ".bak-like Files in Minecraft" "Review." "06_FileSystem\bak_files.csv" }

        Get-ChildItem "C:\" -Recurse -Depth 2 -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 100 | Export-CsvSafe (Join-Path $F.Forensics "recent_mft_proxy.csv")
    }},
    @{ pct = 80; msg = "Minecraft-Specific Analysis..."; action = {
        if (Test-Path $mcRoot) {
            $modFolder = Join-Path $mcRoot "mods"
            if (Test-Path $modFolder) {
                $mods = Get-ChildItem $modFolder -Filter *.jar -ErrorAction SilentlyContinue
                $recentMods = $mods | Where-Object { $_.LastWriteTime -gt (Get-Date).AddMinutes(-30) }
                Export-CsvSafe (Join-Path $F.Minecraft "mods_list.csv") $mods
                if ($recentMods.Count -gt 0) { Add-Finding "HIGH" "Minecraft" "Recent Mod Folder Changes" "Review." "07_Minecraft\mods_list.csv" }
            }

            $jars = Get-ChildItem $mcRoot -Recurse -Filter *.jar -ErrorAction SilentlyContinue
            $jarHashes = @()
            foreach ($jar in $jars) {
                try {
                    $hash = Get-FileHash $jar.FullName -Algorithm SHA256 -ErrorAction SilentlyContinue
                    $jarHashes += [pscustomobject]@{Path=$jar.FullName; SHA256=$hash.Hash; LastWrite=$jar.LastWriteTime}
                } catch {}
            }
            Export-CsvSafe (Join-Path $F.Minecraft "all_jars_hashes.csv") $jarHashes

            $bytecodeTraces = Get-ChildItem $env:TEMP -Recurse -Filter "*.(class|jnativehook)" -ErrorAction SilentlyContinue
            Export-CsvSafe (Join-Path $F.Minecraft "bytecode_traces.csv") $bytecodeTraces
            if ($bytecodeTraces.Count -gt 0) { Add-Finding "MED" "Minecraft" "Java Bytecode Traces in Temp" "Review." "07_Minecraft\bytecode_traces.csv" }

            $forgeLogs = Join-Path $mcRoot "logs"
            if (Test-Path $forgeLogs) {
                New-Item -ItemType Directory (Join-Path $F.Minecraft "forge_logs_recent") -Force | Out-Null
                Get-ChildItem $forgeLogs -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 10 | ForEach-Object {
                    Copy-Item $_.FullName (Join-Path $F.Minecraft "forge_logs_recent") -Force
                }
            }
        } else {
            Add-Finding "LOW" "Minecraft" ".minecraft Not Found" "Review." "07_Minecraft"
        }
    }},
    @{ pct = 85; msg = "Event Logs & Anti-Forensic Checks..."; action = {
        $logNames = @("System", "Application", "Security", "Microsoft-Windows-PowerShell/Operational")
        foreach ($ln in $logNames) {
            cmd /c "wevtutil epl `"$ln`" `"$(Join-Path $F.Logs "$ln.evtx")`"" 2>$null
        }

        try {
            $clearEvents = Get-WinEvent -FilterHashtable @{LogName="Security"; ID=1102} -MaxEvents 10 -ErrorAction SilentlyContinue
            Export-CsvSafe (Join-Path $F.Logs "log_clear_events.csv") $clearEvents
            if ($clearEvents.Count -gt 0) { Add-Finding "HIGH" "Logs" "Event Log Clears Detected" "Review." "05_Logs\log_clear_events.csv" }
        } catch {}

        try {
            $sherlockHits = Get-WinEvent -FilterHashtable @{LogName="Application"; ProviderName="Microsoft-Windows-Sysmon"; ID=1,3,5} -MaxEvents 50 -ErrorAction SilentlyContinue |
                Where-Object { $_.Message -match "(?i)cheat|inject|hook" }
            Export-CsvSafe (Join-Path $F.Findings "sherlock_suspicious_events.csv") $sherlockHits
        } catch {}
    }},
    @{ pct = 90; msg = "Advanced Forensics..."; action = {
        cmd /c "vssadmin list shadows" > (Join-Path $F.Forensics "vss_list.txt") 2>$null
        $vssContent = Get-Content (Join-Path $F.Forensics "vss_list.txt") -ErrorAction SilentlyContinue
        if ($vssContent -notmatch "Shadow Copy ID") { Add-Finding "MED" "Forensics" "No Volume Shadow Copies" "Review." "08_Forensics\vss_list.txt" }

        Get-Process "lsass" -ErrorAction SilentlyContinue | Export-CsvSafe (Join-Path $F.Forensics "kernel_dump_proxy_lsass.csv")

        Get-ChildItem "C:\$Recycle.Bin" -Recurse -Force -ErrorAction SilentlyContinue | Export-CsvSafe (Join-Path $F.Forensics "deleted_files_recycle.csv")
    }},
    @{ pct = 95; msg = "Suspicious Pattern Search..."; action = {
        $doomsDayHits = @()
        foreach ($r in $roots) {
            Get-ChildItem $r -Recurse -Filter "*.(exe|dll|jar)" -ErrorAction SilentlyContinue | Where-Object { $_.Name -match $Regex_Suspicious } | ForEach-Object {
                $doomsDayHits += $_
            }
        }
        Export-CsvSafe (Join-Path $F.Minecraft "doomsday_cheat_hits.csv") $doomsDayHits

        $oceanHits = $jarHashes | Where-Object { (Get-FileEntropy $_.Path) -gt 7.5 }
        Export-CsvSafe (Join-Path $F.Minecraft "ocean_high_entropy_jars.csv") $oceanHits

        Get-ChildItem $mcRoot -Recurse -ErrorAction SilentlyContinue | Export-CsvSafe (Join-Path $F.Minecraft "global_lister_minecraft.csv")
    }},
    @{ pct = 100; msg = "Finalizing findings & zipping..."; action = {
        $FindingsSorted = $Findings | Sort-Object @{Expression='SeverityRank'; Descending=$true}, @{Expression='Category'; Descending=$false}, @{Expression='Title'; Descending=$false}
        Export-CsvSafe (Join-Path $F.Findings "findings.csv") $FindingsSorted

        $readme = Join-Path $F.Findings "findings_readme.txt"
        $txtContent = @("FINDINGS", "Generated: $(Get-Date -Format o)", "")
        foreach ($f in $FindingsSorted) {
            $txtContent += "[$($f.Severity)] $($f.Category) - $($f.Title)"
            $txtContent += "Detail: $($f.Detail)"
            $txtContent += "Evidence: $($f.Evidence)"
            $txtContent += ""
        }
        $txtContent | Out-File $readme -Encoding utf8

        $summaryPath = Join-Path $out "summary.txt"
        $summary.Add("Findings: " + $Findings.Count)
        $summary.Add("High: " + ($Findings | Where-Object { $_.Severity -eq "HIGH" }).Count)
        $summary.Add("Med: " + ($Findings | Where-Object { $_.Severity -eq "MED" }).Count)
        $summary.Add("Low: " + ($Findings | Where-Object { $_.Severity -eq "LOW" }).Count)
        $summary | Out-File $summaryPath -Encoding utf8

        Compress-Archive -Path $out -DestinationPath "$out.zip" -Force -ErrorAction SilentlyContinue
    }}
)

foreach ($step in $steps) {
    Show-ProgressBar $step.pct $step.msg
    try { & $step.action } catch { Write-Host "$Pink[ERROR]$Reset Step failed: $($step.msg)" }
    Start-Sleep -Milliseconds 150
}

[Console]::WriteLine("")
Write-Host "$PinkDONE$Reset" -ForegroundColor Green
Write-Host "Output Folder → $out"
Write-Host "Zipped Results → $out.zip"
Write-Host ""

try { Stop-Transcript | Out-Null } catch {}
