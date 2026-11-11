# Signs bin\LocalAIMonitor.exe with the local self-signed code-signing certificate
# (CN=LocalAIMonitor Local Code Signing, CurrentUser\My, private key non-exportable).
$ErrorActionPreference = 'Stop'
$exe = Join-Path $PSScriptRoot 'bin\LocalAIMonitor.exe'
$cert = Get-ChildItem Cert:\CurrentUser\My -CodeSigningCert |
    Where-Object { $_.Subject -eq 'CN=LocalAIMonitor Local Code Signing' -and $_.NotAfter -gt (Get-Date) } |
    Sort-Object NotAfter -Descending | Select-Object -First 1
if (-not $cert) { Write-Error 'Signing certificate not found in CurrentUser\My.'; exit 1 }
$r = Set-AuthenticodeSignature -FilePath $exe -Certificate $cert -HashAlgorithm SHA256
# 'UnknownError' = signed, but the self-signed root is not in the trusted store (expected).
if (-not $r.SignerCertificate) { Write-Error "Signing failed: $($r.StatusMessage)"; exit 1 }
Write-Output "Signed with $($cert.Thumbprint) (status: $($r.Status))"
