#Requires -Version 5.1
#region ───────────────────────────── Script Notes ─────────────────────────────
<#
┌─────────────────────────────────────────────────────────────────────────────┐
│ SCRIPT NOTES                                                                │
├─────────────────────────────────────────────────────────────────────────────┤
│ Name:            4n6Duck.ps1                                                │
│ Author:          Kainu  -   Kainu@kainu.codes                               │
│ Created:        2025-08-25                                                  │
│ Last Modified:  2025-08-25                                                  │
│ Version:        0.1.0                                                       │
│ Tags:           <4n6>, <DuckyScript                                         │
│ Requires:       PowerShell 5.1+/7+, Modules: n/a                            │
├─────────────────────────────────────────────────────────────────────────────┤
│ Purpose:                                                                    │
│   this script runs a bunch of forensic collections and clamav from a        |
|    usb rubber ducky script and then uploads to a descord webhook you supply │
│                                                                             │
│ Parameters:                                                                 │
│   -webhook  use this to supply your discord webhook for uplo                │
│                                                                             │
│ Usage Examples:                                                             │
│   .\script.ps1 -webhook 'https://discord.com/api/webhooks/174863422..'      │
│                                                                             │
│ Notes / Change Log:                                                         │
│   2025-08-25  Kainu  Initial version.                                       │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
#>


#endregion ─────────────────────────────────────────────────────────────────────



#this is for webhooks
param(
    [Parameter(Mandatory)]
    [string]$webhook    # variable you use in the script
)






function Copy_evtx{
Start-Process powershell.exe -Verb RunAs -ArgumentList @(
  '-NoProfile','-ExecutionPolicy','Bypass','-Command',
  "New-Item -Path 'C:\Users\Public\evtx' -ItemType Directory -Force; Copy-Item 'C:\Windows\System32\winevt\Logs\*.evtx' -Destination 'C:\Users\Public\evtx' -Force -ErrorAction SilentlyContinue"
)}
 # Run with elevation and add exclusion
Start-Process powershell.exe -Verb RunAs -ArgumentList '-Command "Add-MpPreference -ExclusionPath ''C:\Users\Public''"'

function chainsaw_the_village {
    $ErrorActionPreference = 'Stop'
    try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch {}

    $url   = 'https://github.com/WithSecureLabs/chainsaw/releases/latest/download/chainsaw_all_platforms+rules.zip'
    $zip   = 'C:\Users\Public\chainsaw.zip'
    $base  = 'C:\Users\Public\chainsaw'
    $evtx  = 'C:\Users\Public\evtx'
    $out   = 'C:\Users\Public\4n6Duck\chainsaw'

    if (Get-Command Start-BitsTransfer -ErrorAction SilentlyContinue) {
        Start-BitsTransfer -Source $url -Destination $zip -Priority Foreground
    } else {
        Invoke-WebRequest -Uri $url -OutFile $zip -UseBasicParsing
    }

    $deadline = (Get-Date).AddMinutes(5)
    $stable = 0; $lastSize = -1
    while ((Get-Date) -lt $deadline -and $stable -lt 4) {
        Start-Sleep -Milliseconds 500
        if (-not (Test-Path $zip)) { continue }
        $size = (Get-Item $zip -ErrorAction SilentlyContinue).Length
        try {
            $fs=[IO.File]::Open($zip,'Open','Read','None');$fs.Close()
            if ($size -gt 0 -and $size -eq $lastSize) {
                $stable++
            } else {
                $stable=0
            }
            $lastSize=$size
        } catch { $stable = 0 }
    }
    if (-not (Test-Path $zip)) { throw "Download failed: $zip not found." }

    Expand-Archive -LiteralPath $zip -DestinationPath 'C:\Users\Public' -Force
    Remove-Item $zip -Force

    $exe = Join-Path $base 'chainsaw_x86_64-pc-windows-msvc.exe'
    if (-not (Test-Path $exe)) {
        $found = Get-ChildItem $base -Recurse -File -Filter 'chainsaw*.exe' | Select-Object -First 1
        if (-not $found) { throw "Chainsaw executable not found under $base" }
        $exe = $found.FullName
    }
    Unblock-File -Path $exe -ErrorAction SilentlyContinue

    $root  = Split-Path $exe
    $map   = Join-Path $root 'mappings\sigma-event-logs-all.yml'
    $rules = Join-Path $root 'rules'
    $sigma = Join-Path $root 'sigma'

    foreach ($p in @($map,$rules,$sigma)) { if (-not (Test-Path $p)) { throw "Missing required path: $p" } }

    $stdout = Join-Path $out 'chainsaw.stdout.txt'
    $stderr = Join-Path $out 'chainsaw.stderr.txt'
    $args = @('hunt', $evtx, '--mapping', $map, '-o', $out, '-r', $rules, '-s', $sigma, '--csv', '--skip-errors')

    $p = Start-Process -FilePath $exe -ArgumentList $args -NoNewWindow -Wait -PassThru `
         -RedirectStandardOutput $stdout -RedirectStandardError $stderr

    if ($p.ExitCode -ne 0) { throw "Chainsaw exited with code $($p.ExitCode). See $stderr" }

    Write-Host "Log hunting complete. Results + logs in: $out"
    Write-Host "Stdout: $stdout"
    Write-Host "Stderr: $stderr"
} 

Function collect_files {

#psreadline
Copy-Item @(
  "$env:APPDATA\Microsoft\PowerShell\PSReadLine\*.txt",
  "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\*.txt"
) -Destination 'C:\Users\Public\4n6Duck' -Force -ErrorAction SilentlyContinue
#chainsaw data
Copy-Item @(
  "C:\Users\Public\evtx\Chainsaw"
) -Destination 'C:\Users\Public\4n6Duck' -Recurse -Force -ErrorAction SilentlyContinue
#

}
Function ClamClam {

Start-Process powershell.exe -Verb RunAs -Wait -ArgumentList '-NoProfile','-ExecutionPolicy','Bypass','-Command','$tmp=Join-Path $env:USERPROFILE "AppData\Local\Temp\clamav"; New-Item -ItemType Directory -Force $tmp|Out-Null; cd $tmp; Invoke-WebRequest -Uri https://www.clamav.net/downloads/production/clamav-1.3.0.win.x64.zip -OutFile clam.zip; Expand-Archive -Force clam.zip -DestinationPath .; Remove-Item clam.zip -Force; cd (Get-ChildItem -Directory -Filter "clamav*"|Select-Object -First 1).FullName; Copy-Item .\conf_examples\freshclam.conf.sample freshclam.conf -Force; Copy-Item .\conf_examples\clamd.conf.sample clamd.conf -Force; (Get-Content freshclam.conf)|Select-String -Pattern "Example" -NotMatch|Set-Content freshclam.conf; (Get-Content clamd.conf)|Select-String -Pattern "Example" -NotMatch|Set-Content clamd.conf; .\freshclam.exe; New-Item -ItemType Directory -Force "C:\Users\Public\4n6Duck"|Out-Null; .\clamscan.exe --memory --kill | Tee-Object -FilePath "C:\Users\Public\4n6Duck\clamav_results.txt"; cd $env:TEMP; Remove-Item -Recurse -Force $tmp'
}


function Hayabusa_speedy {
$u='https://github.com/Yamato-Security/hayabusa/releases/download/v2.16.0/hayabusa-2.16.0-win-x64.zip'; $z=Join-Path $env:TEMP ([IO.Path]::GetFileName($u)); $o=Join-Path $env:TEMP 'hayabusa_win64'; try{[Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12; Invoke-WebRequest -Uri $u -OutFile $z -UseBasicParsing}catch{Start-BitsTransfer -Source $u -Destination $z}; if(-not (Test-Path $o)){New-Item -ItemType Directory -Path $o|Out-Null}; Expand-Archive -Path $z -DestinationPath $o -Force; $exe=(Get-ChildItem -Path $o -Recurse -Filter 'hayabusa*.exe' | Select-Object -First 1).FullName; if(-not $exe){throw 'Could not find hayabusa.exe after unzipping.'}; Unblock-File -Path $exe -ErrorAction SilentlyContinue
cd $env:TEMP
Start-Process powershell.exe -Verb RunAs -Wait -ArgumentList '-NoProfile','-ExecutionPolicy','Bypass','-Command', '$ErrorActionPreference=''Stop''; $ex=(Get-ChildItem "$env:TEMP\hayabusa_win64" -Recurse -Filter ''hayabusa*.exe'' | Select-Object -First 1).FullName; if(-not $ex){throw "Could not find hayabusa.exe under $env:TEMP\hayabusa_win64"}; $dir=''C:\Users\Public\4n6Duck''; if(-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }; $out=Join-Path $dir ''hayabusa_timeline.csv''; Unblock-File -Path $ex -ErrorAction SilentlyContinue; & $ex update-rules; & $ex csv-timeline -l -m low -o $out -w; Write-Host "Output => $out"'
}


Function collect_everything_else {

# PowerShell DFIR Collection Script
# Config
$EvidenceRoot = "C:\Users\Public\Dfir_everythingelse"
$TimeStamp = Get-Date -Format "yyyyMMdd_HHmmss"
$OutputDir = Join-Path $EvidenceRoot -ChildPath "Output"
$PrefetchDir = Join-Path $OutputDir "prefetch"

# Create directories
New-Item -ItemType Directory -Path $PrefetchDir -Force | Out-Null
New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null



# AutoRuns
$AutorunsExe = Join-Path $ToolsDir "autorunsc.exe"
if (Test-Path $AutorunsExe) {
    Write-Output "Collecting AutoRuns..."
    & $AutorunsExe -a * -c -h -t * -accepteula | Out-File -FilePath (Join-Path $OutputDir "autoruns.csv") -Encoding UTF8
} else {
    Write-Output "AutoRuns not found—skipping."
}



Start-Process powershell.exe -Verb RunAs `
  -ArgumentList "-NoProfile -ExecutionPolicy Bypass -Command $cmd" `
  -Wait

# Shares
Write-Output "Collecting Shares..."
net share | Out-File -FilePath (Join-Path $OutputDir "Shares.txt") -Encoding UTF8

# Local Administrators
Write-Output "Collecting Local Administrators group..."
net localgroup administrators | Out-File -FilePath (Join-Path $OutputDir "localadmins.txt") -Encoding UTF8

# Firewall Rules
Write-Output "Collecting Firewall Rules..."
netsh advfirewall firewall show rule name=all | Out-File -FilePath (Join-Path $OutputDir "firewallrules.txt") -Encoding UTF8

# Hosts File
Write-Output "Copying Hosts file..."
robocopy "C:\Windows\System32\drivers\etc" $OutputDir hosts

# System Info
Write-Output "Collecting System Information..."
systeminfo | Out-File -FilePath (Join-Path $OutputDir "SystemInfo.txt") -Encoding UTF8

# Environment Variables
Write-Output "Collecting Environment Variables..."
Get-ChildItem Env: | Out-File -FilePath (Join-Path $OutputDir "Environment_variables.txt") -Encoding UTF8

# Tasklist Verbose
Write-Output "Collecting Tasklist (/V)..."
tasklist /V | Out-File -FilePath (Join-Path $OutputDir "Tasklist-Verbose.txt") -Encoding UTF8

# Netstat -ano
Write-Output "Collecting Netstat -ano..."
netstat -ano | Out-File -FilePath (Join-Path $OutputDir "NetConnectionsANO.txt") -Encoding UTF8

# Netstat -abo
Write-Output "Collecting Netstat -abo..."
netstat -abo | Out-File -FilePath (Join-Path $OutputDir "NetConnectionsABO.txt") -Encoding UTF8

Write-Output "Forensics collection completed."


Copy-Item -Path $OutputDir -Destination "C:\Users\Public\4n6Duck" -Recurse -Force


}




function Rip_n_zip {
$src = 'C:\Users\Public\4n6Duck'
$zip = Join-Path $src ("Collection_{0}.zip" -f $env:COMPUTERNAME)
Compress-Archive -Path "$src\*" -DestinationPath $zip -CompressionLevel Optimal -Force
Write-Host "Created: $zip" 
}  

  Function Collection {
Add-Type -AssemblyName System.Net.Http

$src = 'C:\Users\Public\4n6Duck'
$zip = Join-Path $src ("Collection_{0}.zip" -f $env:COMPUTERNAME)

$File    = $zip
$Name    = [System.IO.Path]::GetFileName($File)

if (!(Test-Path -LiteralPath $File)) { throw "File not found: $File" }

# payload_json
$payload = @{
  content     = "$env:COMPUTERNAME collection has completed, results attached"
  attachments = @(@{ id = 0; filename = $Name })
} | ConvertTo-Json -Depth 5 -Compress

# multipart/form-data
$mp = [System.Net.Http.MultipartFormDataContent]::new()
$mp.Add([System.Net.Http.StringContent]::new($payload, [Text.Encoding]::UTF8, "application/json"), "payload_json")

$fs   = [System.IO.FileStream]::new($File, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read)
$file = [System.Net.Http.StreamContent]::new($fs)
$file.Headers.ContentDisposition = [System.Net.Http.Headers.ContentDispositionHeaderValue]::new("form-data")
$file.Headers.ContentDisposition.Name     = 'files[0]'
$file.Headers.ContentDisposition.FileName = $Name
$file.Headers.ContentType = [System.Net.Http.Headers.MediaTypeHeaderValue]::new("text/plain")
$mp.Add($file)

$client   = [System.Net.Http.HttpClient]::new()
$response = $client.PostAsync($Webhook, $mp).Result
$response.StatusCode
$response.Content.ReadAsStringAsync().Result

$fs.Dispose(); $mp.Dispose(); $client.Dispose()
} 



function Cleanup {
  [CmdletBinding(SupportsShouldProcess = $true)]
  param()

  $paths = @(
    "$env:LOCALAPPDATA\Temp\hayabusa-2.16.0-win-x64.zip",
    "C:\Users\Public\4n6Duck",
    "C:\Users\Public\chainsaw",
    "C:\Users\Public\Dfir_everythingelse",
    "C:\Users\Public\evtx",
    "$env:LOCALAPPDATA\Temp\hayabusa_win64"
  )

  foreach ($cleanupP in $paths) {
    if (-not (Test-Path -LiteralPath $cleanupP)) {
      Write-Verbose ("Skip (not found): {0}" -f $cleanupP)
      continue
    }
    if ($PSCmdlet.ShouldProcess($cleanupP, "Remove-Item -Recurse -Force")) {
      try {
        Remove-Item -LiteralPath $cleanupP -Recurse -Force -ErrorAction Stop
        Write-Verbose ("Deleted: {0}" -f $cleanupP)
      } catch {
        Write-Warning ("Couldn't delete {0}: {1}" -f $cleanupP, $_.Exception.Message)
      }
    }
  }
}



cleanup
mkdir C:\Users\Public\4n6Duck
 Copy_evtx
 ClamClam
 chainsaw_the_village
 collect_files
 Hayabusa_speedy
 collect_everything_else
 Rip_n_zip

 Collection



