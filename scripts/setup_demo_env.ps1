# Simple script to spawn background listeners to simulate a vulnerable machine
# Ports: 23 (Telnet), 80 (HTTP), 3306 (MySQL), 6379 (Redis)

Write-Host "Setting up local lab environment..." -ForegroundColor Cyan

$ports = @(23, 80, 3306, 6379)
$jobs = @()

foreach ($port in $ports) {
    Write-Host "Spawning listener on port $port..."
    $job = Start-Job -ScriptBlock {
        param($p)
        $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Any, $p)
        $listener.Start()
        while ($true) {
            if ($listener.Pending()) {
                $client = $listener.AcceptTcpClient()
                $stream = $client.GetStream()
                $writer = [System.IO.StreamWriter]::new($stream)
                $writer.AutoFlush = $true
                $writer.WriteLine("SecOps Demo - Vulnerable Service on port $p")
                $client.Close()
            }
            Start-Sleep -Milliseconds 100
        }
    } -ArgumentList $port
    $jobs += $job
}

Write-Host "Demo environment ready. Vulnerable ports: $($ports -join ', ')" -ForegroundColor Green
return $jobs
