# SOC Investigation Script
# Run this on a suspicious Windows host

Write-Host "=== SOC ENDPOINT INVESTIGATION ===" -ForegroundColor Red
Write-Host "Timestamp: $(Get-Date)"

Write-Host "`n[1] SUSPICIOUS PROCESSES" -ForegroundColor Yellow
Get-Process | Where-Object {$_.CPU -gt 50} | Select-Object Name, Id, CPU

Write-Host "`n[2] ACTIVE NETWORK CONNECTIONS" -ForegroundColor Yellow
Get-NetTCPConnection | Where-Object {$_.State -eq 'Established'} |
Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort

Write-Host "`n[3] RECENT FAILED LOGINS (Event ID 4625)" -ForegroundColor Yellow
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625} -MaxEvents 10 |
Select-Object TimeCreated, Message

Write-Host "`n[4] SCHEDULED TASKS (Persistence Check)" -ForegroundColor Yellow
Get-ScheduledTask | Where-Object {$_.State -eq 'Ready'} |
Select-Object TaskName, TaskPath
