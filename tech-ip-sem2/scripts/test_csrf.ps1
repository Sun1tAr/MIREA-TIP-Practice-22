# test_csrf.ps1
$baseUrl = "https://localhost:8443"
$authUrl = "http://localhost:8081"  # Auth HTTP порт

Write-Host "=== Testing CSRF Protection Demo ===" -ForegroundColor Green
Write-Host ""

# 1. Логин и сохранение cookies
Write-Host "1. Logging in to get cookies..." -ForegroundColor Yellow
$loginBody = @{
    username = "student"
    password = "student"
} | ConvertTo-Json

$response = curl.exe -k -s -i -X POST "$authUrl/v1/auth/login" `
    -H "Content-Type: application/json" `
    -d $loginBody `
    -c cookies.txt

Write-Host "Login response headers (cookies set):" -ForegroundColor Cyan
$response | Select-String "Set-Cookie"
Write-Host ""

# Извлекаем CSRF токен из cookies.txt
# Формат файла cookies.txt: домен, флаг, путь, безопасность, expiry, имя, значение
$csrfToken = ""
if (Test-Path cookies.txt) {
    $lines = Get-Content cookies.txt
    foreach ($line in $lines) {
        if ($line -match "csrf_token\s+(\S+)") {
            $csrfToken = $matches[1]
            break
        }
    }
}
Write-Host "CSRF Token from cookies: $csrfToken" -ForegroundColor Cyan
Write-Host ""

if (-not $csrfToken) {
    Write-Host "Failed to extract CSRF token!" -ForegroundColor Red
    exit 1
}

# 2. Попытка создать задачу без CSRF заголовка (должно быть 403)
Write-Host "2. Creating task WITHOUT CSRF header (should be 403)..." -ForegroundColor Yellow
$taskBody = @{
    title = "CSRF Test"
    description = "No CSRF header"
    due_date = "2026-03-15"
} | ConvertTo-Json

curl.exe -k -i -X POST "$baseUrl/v1/tasks" `
    -H "Content-Type: application/json" `
    -b cookies.txt `
    -d $taskBody
Write-Host ""

# 3. Создание задачи С CSRF заголовком (должно быть 201)
Write-Host "3. Creating task WITH CSRF header (should be 201)..." -ForegroundColor Yellow
curl.exe -k -i -X POST "$baseUrl/v1/tasks" `
    -H "Content-Type: application/json" `
    -H "X-CSRF-Token: $csrfToken" `
    -b cookies.txt `
    -d $taskBody
Write-Host ""

# 4. Демонстрация XSS-защиты
Write-Host "4. Testing XSS protection (script injection)..." -ForegroundColor Yellow
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

# Пытаемся распарсить JSON ответ, чтобы показать санитизированное описание
try {
    $responseObj = $xssResponse | ConvertFrom-Json
    Write-Host "Response description (sanitized): $($responseObj.description)" -ForegroundColor Cyan
} catch {
    Write-Host "Response (raw): $xssResponse" -ForegroundColor Cyan
}
Write-Host ""

# 5. Проверка заголовков безопасности
Write-Host "5. Checking security headers..." -ForegroundColor Yellow
$headers = curl.exe -k -s -I "$baseUrl/v1/tasks" -b cookies.txt
$headers | Select-String "X-Content-Type-Options"
$headers | Select-String "X-Frame-Options"
$headers | Select-String "Content-Security-Policy"
$headers | Select-String "Strict-Transport-Security"

Write-Host ""
Write-Host "Test completed!" -ForegroundColor Green

# Очистка
Remove-Item cookies.txt -ErrorAction SilentlyContinue