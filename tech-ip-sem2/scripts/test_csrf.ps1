# test_csrf_simple.ps1
$baseUrl = "https://localhost:8443"
$authUrl = "http://localhost:8081"

Write-Host "=== Testing CSRF Protection Demo (Simple Mode) ===" -ForegroundColor Green
Write-Host ""

# Фиксированный CSRF токен (как в коде Auth service)
$csrfToken = "demo-csrf-456"

Write-Host "Using fixed CSRF token: $csrfToken" -ForegroundColor Cyan
Write-Host ""

# 1. Логин (просто показываем, что cookies устанавливаются)
Write-Host "1. Logging in..." -ForegroundColor Yellow
$loginBody = @{
    username = "student"
    password = "student"
} | ConvertTo-Json

$response = curl.exe -k -s -i -X POST "$authUrl/v1/auth/login" `
    -H "Content-Type: application/json" `
    -d $loginBody `
    -c cookies.txt

Write-Host "Login response headers:" -ForegroundColor Cyan
$response | Select-String "Set-Cookie"
Write-Host ""

# 2. Попытка создать задачу без CSRF заголовка (должно быть 403)
Write-Host "2. Creating task WITHOUT CSRF header (should be 403)..." -ForegroundColor Yellow
$taskBody = @{
    title = "CSRF Test"
    description = "No CSRF header"
    due_date = "2026-03-15"
} | ConvertTo-Json

$response = curl.exe -k -s -i -X POST "$baseUrl/v1/tasks" `
    -H "Content-Type: application/json" `
    -b cookies.txt `
    -d $taskBody

$statusLine = $response | Select-String -Pattern "HTTP/1.1"
Write-Host $statusLine
Write-Host ""

# 3. Создание задачи С CSRF заголовком (должно быть 201)
Write-Host "3. Creating task WITH CSRF header (should be 201)..." -ForegroundColor Yellow
$response = curl.exe -k -s -i -X POST "$baseUrl/v1/tasks" `
    -H "Content-Type: application/json" `
    -H "X-CSRF-Token: $csrfToken" `
    -b cookies.txt `
    -d $taskBody

$statusLine = $response | Select-String -Pattern "HTTP/1.1"
$body = $response -split "\r\n\r\n" | Select-Object -Last 1

Write-Host $statusLine
Write-Host "Response body: $body"
Write-Host ""

# 4. Демонстрация XSS-защиты
Write-Host "4. Testing XSS protection..." -ForegroundColor Yellow
$xssBody = @{
    title = "XSS Test"
    description = "<script>alert('XSS')</script>"
    due_date = "2026-03-15"
} | ConvertTo-Json

$xssResponse = curl.exe -k -s -X POST "$baseUrl/v1/tasks" `
    -H "Content-Type: application/json" `
    -H "X-CSRF-Token: $csrfToken" `
    -b cookies.txt `
    -d $xssBody

$xssResponse | ConvertFrom-Json | Format-List

# 5. Проверка заголовков безопасности
Write-Host "5. Checking security headers..." -ForegroundColor Yellow
$headers = curl.exe -k -s -I -X GET "$baseUrl/v1/tasks" -b cookies.txt

Write-Host "Security headers present:" -ForegroundColor Cyan
$headers | Select-String "X-Content-Type-Options"
$headers | Select-String "X-Frame-Options"
$headers | Select-String "Content-Security-Policy"
$headers | Select-String "Referrer-Policy"
$headers | Select-String "Strict-Transport-Security"

Write-Host ""
Write-Host "Test completed!" -ForegroundColor Green

# Очистка
Remove-Item cookies.txt -ErrorAction SilentlyContinue