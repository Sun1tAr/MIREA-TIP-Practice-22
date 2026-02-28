$env:Path += ";C:\Program Files\OpenSSL-Win64\bin"

# generate_cert.ps1
Write-Host "Generating self-signed TLS certificate for localhost..." -ForegroundColor Green

$certDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$keyPath = Join-Path $certDir "key.pem"
$certPath = Join-Path $certDir "cert.pem"

# Проверяем наличие openssl
$openssl = Get-Command openssl -ErrorAction SilentlyContinue
if (-not $openssl) {
    Write-Host "OpenSSL not found. Please install OpenSSL or use WSL." -ForegroundColor Red
    exit 1
}

# Генерируем сертификат
openssl req -x509 -newkey rsa:2048 -nodes `
    -keyout $keyPath `
    -out $certPath `
    -days 365 `
    -subj "/CN=localhost"

Write-Host "Certificate generated successfully:" -ForegroundColor Green
Write-Host "  Key: $keyPath"
Write-Host "  Cert: $certPath"