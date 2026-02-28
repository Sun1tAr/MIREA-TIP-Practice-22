# test_sqli.ps1
$baseUrl = "https://localhost:8443"
$token = "demo-token"

Write-Host "=== Testing SQL Injection Demo ===" -ForegroundColor Green
Write-Host ""

# 1. Создаем тестовые задачи
Write-Host "1. Creating test tasks..." -ForegroundColor Yellow
for ($i=1; $i -le 3; $i++) {
    $body = @{
        title = "Test Task $i"
        description = "Description for test task $i"
        due_date = "2026-03-01"
    } | ConvertTo-Json

    curl.exe -k -s -X POST "$baseUrl/v1/tasks" `
        -H "Content-Type: application/json" `
        -H "Authorization: Bearer $token" `
        -d $body | Out-Null
    Write-Host -NoNewline "."
}
Write-Host " OK"

Write-Host ""
Write-Host "2. Normal search (safe mode) - query: 'Test'" -ForegroundColor Yellow
$response = curl.exe -k -s -G "$baseUrl/v1/tasks/search" `
    -H "Authorization: Bearer $token" `
    --data-urlencode "q=Test" | ConvertFrom-Json
Write-Host "Found $($response.Count) tasks"

Write-Host ""
Write-Host "3. DEMONSTRATING SQL INJECTION (unsafe mode)" -ForegroundColor Red
Write-Host "   Query: ' OR '1'='1" -ForegroundColor Red
$response = curl.exe -k -s -G "$baseUrl/v1/tasks/search" `
    -H "Authorization: Bearer $token" `
    --data-urlencode "q=' OR '1'='1" `
    --data-urlencode "unsafe=true" | ConvertFrom-Json
Write-Host "Found $($response.Count) tasks (should return ALL tasks!)" -ForegroundColor Red

Write-Host ""
Write-Host "4. Safe mode with the same injection" -ForegroundColor Green
$response = curl.exe -k -s -G "$baseUrl/v1/tasks/search" `
    -H "Authorization: Bearer $token" `
    --data-urlencode "q=' OR '1'='1" `
    --data-urlencode "unsafe=false" | ConvertFrom-Json
Write-Host "Found $($response.Count) tasks (should return 0, searching for literal string)" -ForegroundColor Green

Write-Host ""
Write-Host "Test completed!" -ForegroundColor Green