# scripts/verify_fault_injection.ps1
# Stops a node, checks that the LeaseManager evicts its links (and that they stay evicted),
# that exactly one "unreachable" alert is raised for it, then restarts it and checks recovery.
# Exits 1 if any check fails.
param(
    [string]$BaseUrl = "http://localhost:8000",
    [string]$TargetNode = "node-1",
    [int]$EvictionWaitSeconds = 14,
    [int]$RecoveryTimeoutSeconds = 40
)

$ErrorActionPreference = "Stop"
$failures = New-Object System.Collections.Generic.List[string]

function Assert-Check([bool]$Ok, [string]$Message) {
    if ($Ok) {
        Write-Host "  PASS: $Message" -ForegroundColor Green
    } else {
        Write-Host "  FAIL: $Message" -ForegroundColor Red
        $failures.Add($Message)
    }
}

function Get-AuthHeaders {
    $resp = Invoke-RestMethod -Method Post "$BaseUrl/auth/token" `
        -ContentType "application/json" `
        -Body '{"subject":"verify-script","role":"viewer"}'
    return @{ Authorization = "Bearer $($resp.access_token)" }
}

function Get-TargetLinks($headers) {
    $topo = Invoke-RestMethod "$BaseUrl/topology" -Headers $headers
    return @($topo.observed_links | Where-Object { $_.src_node_id -eq $TargetNode -or $_.dst_node_id -eq $TargetNode })
}

# Windows PowerShell 5.1 emits a JSON array from Invoke-RestMethod as one pipeline object;
# assigning it to a variable first makes the pipeline enumerate its elements.
function Get-TargetHealth($headers) {
    $nodes = Invoke-RestMethod "$BaseUrl/nodes" -Headers $headers
    return [string](($nodes | Where-Object { $_.node_id -eq $TargetNode } | Select-Object -First 1).health_status)
}

function Get-OpenUnreachableAlerts($headers) {
    $alerts = Invoke-RestMethod "$BaseUrl/alerts" -Headers $headers
    return @($alerts | Where-Object {
        $_.affected_node_id -eq $TargetNode -and $_.status -ne "resolved" -and $_.message -like "Node unreachable*"
    })
}

$headers = Get-AuthHeaders

Write-Host "`n[1/4] Baseline links touching $TargetNode..." -ForegroundColor Cyan
$baseline = @(Get-TargetLinks $headers)
$baseline | Format-Table src_node_id, dst_node_id, status, latency_ms, packet_loss_pct
Assert-Check ($baseline.Count -gt 0) "$TargetNode has $($baseline.Count) open link(s) before the fault"

try {
    Write-Host "[2/4] Stopping $TargetNode and waiting ${EvictionWaitSeconds}s for lease expiry..." -ForegroundColor Yellow
    docker stop $TargetNode | Out-Null
    Start-Sleep -Seconds $EvictionWaitSeconds

    Write-Host "[3/4] Checking eviction, that it holds, and alerting..." -ForegroundColor Yellow
    Assert-Check ((Get-TargetHealth $headers) -eq "offline") "$TargetNode is marked offline"
    $firstSample = @(Get-TargetLinks $headers)
    Assert-Check ($firstSample.Count -eq 0) "all links touching $TargetNode evicted (open: $($firstSample.Count))"

    # Peers keep probing the dead node; its links must not be re-opened between lease sweeps.
    Start-Sleep -Seconds 10
    $secondSample = @(Get-TargetLinks $headers)
    Assert-Check ($secondSample.Count -eq 0) "links stay evicted 10s later (open: $($secondSample.Count))"

    $alerts = @(Get-OpenUnreachableAlerts $headers)
    Assert-Check ($alerts.Count -eq 1) "exactly one open 'unreachable' alert for $TargetNode (found: $($alerts.Count))"
}
finally {
    Write-Host "[4/4] Restoring $TargetNode and waiting up to ${RecoveryTimeoutSeconds}s for recovery..." -ForegroundColor Cyan
    docker start $TargetNode | Out-Null
}

$deadline = (Get-Date).AddSeconds($RecoveryTimeoutSeconds)
do {
    Start-Sleep -Seconds 2
    $recovered = @(Get-TargetLinks $headers)
    $health = Get-TargetHealth $headers
} while (((Get-Date) -lt $deadline) -and (($health -ne "healthy") -or ($recovered.Count -lt $baseline.Count)))

$recovered | Format-Table src_node_id, dst_node_id, status, latency_ms, packet_loss_pct
Assert-Check ($health -eq "healthy") "$TargetNode is healthy again (status: $health)"
Assert-Check ($recovered.Count -ge $baseline.Count) "links restored ($($recovered.Count)/$($baseline.Count))"
Assert-Check (@(Get-OpenUnreachableAlerts $headers).Count -eq 0) "the 'unreachable' alert for $TargetNode is resolved"

if ($failures.Count -gt 0) {
    Write-Host "`nFAILED: $($failures.Count) check(s) failed." -ForegroundColor Red
    exit 1
}
Write-Host "`nAll fault-injection checks passed." -ForegroundColor Green
exit 0
