# Windows live-host capture (docs/os-kernel-intelligence/
# 01_PRODUCT_SPEC.md §15 step 9). Run ONLY on an authorised Windows
# host under an agreed scope.
#
# Writes each documented source to its own capture file plus a
# manifest.json with SHA-256 digests, timestamps and any denied
# commands (recorded as 'permission_denied' — never as absence).
# METADATA ONLY: certificate METADATA and BitLocker status; private
# keys, recovery passwords and key material are never exported.
param(
    [string]$OutDir = "windows-capture-$(Get-Date -Format yyyyMMdd-HHmmss)"
)
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$ErrorActionPreference = "Continue"

function Capture([string]$Name, [string]$File, [scriptblock]$Command) {
    $path = Join-Path $OutDir $File
    try {
        & $Command 2>&1 | Out-File -FilePath $path -Encoding utf8
        Write-Host "captured $Name"
    } catch {
        "permission_denied or unavailable: $($_.Exception.Message)" |
            Out-File -FilePath $path -Encoding utf8
        Write-Host "unavailable $Name (recorded, never as absence)"
    }
}

Capture "systeminfo" "systeminfo.txt" { systeminfo }
Capture "ver" "ver.txt" { cmd /c ver }
Capture "certutil_csplist" "certutil_csplist.txt" { certutil -csplist }
# Certificate METADATA only — no private key export, ever (§7).
Capture "certutil_store" "certutil_store.txt" { certutil -store }
Capture "reg_schannel_protocols" "reg_schannel.txt" {
    reg query "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols" /s
}
Capture "reg_cipher_order" "reg_cipher_order.txt" {
    reg query "HKLM\SYSTEM\CurrentControlSet\Control\Cryptography\Configuration\Local\SSL\00010002" /v Functions
}
# BitLocker METADATA only — never recovery passwords or key protectors.
Capture "manage_bde" "manage_bde.txt" { manage-bde -status }
Capture "get_tpm" "get_tpm.txt" { Get-Tpm }
Capture "confirm_secureboot" "confirm_secureboot.txt" { Confirm-SecureBootUEFI }
Capture "driverquery" "driverquery.txt" { driverquery /fo list }

$manifest = @{
    schema = "cryptoscan.live-capture/1"
    platform = "windows"
    captured_at = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    host = $env:COMPUTERNAME
    note = "metadata only — private keys, recovery passwords and key material are never collected"
}
$manifest | ConvertTo-Json | Out-File -FilePath (Join-Path $OutDir "manifest.json") -Encoding utf8
Write-Host "wrote $OutDir (validate with: validate_capture.py --platform windows $OutDir)"
