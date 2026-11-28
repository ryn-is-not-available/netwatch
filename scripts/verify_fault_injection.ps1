# scripts/verify_fault_injection.ps1
param(
    [string]$BaseUrl = "http://localhost:8000",
    [string]$TargetNode = "node-1",
    [int]$ProbeWaitSeconds = 14
)

$ErrorActionPreference = "Stop"

function Get-AuthHeaders {
    $resp = Invoke-RestMethod -Method Post "$BaseUrl/auth/token" `
        -ContentType "application/json" `
        -Body '{"subject":"verify-script","role":"viewer"}'
    return @{ Authorization = "Bearer $($resp.access_token)" }
}

function Get-InboundLinks($headers, [string]$AtIso = "") {
    $url = if ($AtIso) { "$BaseUrl/topology?at=$([uri]::EscapeDataString($AtIso))" } else { "$BaseUrl/topology" }
    $topo = Invoke-RestMethod $url -Headers $headers
    return @($topo.observed_links | Where-Object { $_.dst_node_id -eq $TargetNode })
}

$headers = Get-AuthHeaders

Write-Host "`n[1/4] Baseline links toward $TargetNode..." -ForegroundColor Cyan
$baselineLinks = Get-InboundLinks $headers
$baselineLinks | Format-Table src_node_id, dst_node_id, status, latency_ms, packet_loss_pct

try {
    Write-Host "[2/4] Stopping $TargetNode and waiting ${ProbeWaitSeconds}s for ActiveProber sweep & LeaseManager..." -ForegroundColor Yellow
    docker stop $TargetNode | Out-Null
    Start-Sleep -Seconds ([math]::Floor($ProbeWaitSeconds / 2))
    $midOutageIso = (Get-Date).ToUniversalTime().ToString("o")
    Start-Sleep -Seconds ([math]::Ceiling($ProbeWaitSeconds / 2))

    Write-Host "[3/4] Checking degraded state, packet loss & lease eviction..." -ForegroundColor Yellow
    $activeLinks = Get-InboundLinks $headers
    $midOutageLinks = Get-InboundLinks $headers $midOutageIso
    $midOutageLinks | Format-Table src_node_id, dst_node_id, status, latency_ms, packet_loss_pct

    $lossyCount = @($midOutageLinks | Where-Object { $_.packet_loss_pct -ge 50.0 }).Count
    $evictedCount = $baselineLinks.Count - $activeLinks.Count

    if ($lossyCount -gt 0 -or $evictedCount -gt 0) {
        Write-Host "PASS: Detected $lossyCount link(s) with >=50% packet loss and $evictedCount lease-evicted link(s) for $TargetNode." -ForegroundColor Green
    } else {
        Write-Host "FAIL: Neither packet loss nor lease eviction occurred while $TargetNode was stopped." -ForegroundColor Red
    }
}
finally {
    Write-Host "[4/4] Restoring $TargetNode and waiting ${ProbeWaitSeconds}s for recovery..." -ForegroundColor Cyan
    docker start $TargetNode | Out-Null
    Start-Sleep -Seconds $ProbeWaitSeconds

    $recoveredLinks = Get-InboundLinks $headers
    $recoveredLinks | Format-Table src_node_id, dst_node_id, status, latency_ms, packet_loss_pct
}