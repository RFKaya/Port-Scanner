# Cleanup script to stop background jobs
Write-Host "Cleaning up local lab environment..." -ForegroundColor Yellow

$jobs = Get-Job -Name "Job*"
if ($jobs) {
    $jobs | Stop-Job
    $jobs | Remove-Job
    Write-Host "Cleanup complete." -ForegroundColor Green
} else {
    Write-Host "No active demo jobs found."
}
