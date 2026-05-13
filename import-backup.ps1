# ══════════════════════════════════════════════════════════════════
#  Import-Backup.ps1 — Backup-JSON ins self-hosted CRM (MySQL) laden
#
#  Anwendung:
#    .\import-backup.ps1 -BackupFile "C:\pfad\zu\webars-crm-backup-2026-05-12.json" `
#                        -ServerUrl  "https://deine-domain.at" `
#                        -ApiSecret  "dein-API_SECRET"
# ══════════════════════════════════════════════════════════════════

param(
  [Parameter(Mandatory=$true)] [string]$BackupFile,
  [Parameter(Mandatory=$true)] [string]$ServerUrl,
  [Parameter(Mandatory=$true)] [string]$ApiSecret
)

if (-not (Test-Path $BackupFile)) {
  Write-Host "❌ Datei nicht gefunden: $BackupFile" -ForegroundColor Red
  exit 1
}

$ServerUrl = $ServerUrl.TrimEnd('/')
Write-Host "→ Lade Backup: $BackupFile"
$backup = Get-Content $BackupFile -Raw | ConvertFrom-Json

if (-not $backup.encryptedData) {
  Write-Host "❌ Diese Datei enthält kein 'encryptedData' Feld — falsches Backup-Format?" -ForegroundColor Red
  exit 1
}

# Server erreichbar?
try {
  $h = Invoke-RestMethod -Uri "$ServerUrl/health"
  if (-not $h.dbReady) { Write-Host "⚠ MySQL noch nicht verbunden: $($h.dbError)" -ForegroundColor Yellow; exit 1 }
  Write-Host "✓ Server erreichbar, DB ready"
} catch {
  Write-Host "❌ Server nicht erreichbar: $($_.Exception.Message)" -ForegroundColor Red
  exit 1
}

# Import
$body = @{ encryptedData = $backup.encryptedData } | ConvertTo-Json -Depth 100 -Compress
Write-Host "→ Importiere ($($body.Length) bytes)…"
try {
  $r = Invoke-RestMethod -Uri "$ServerUrl/api/import" -Method POST `
    -Headers @{ Authorization = "Bearer $ApiSecret"; "Content-Type" = "application/json" } `
    -Body $body
  Write-Host "✓ Erfolgreich importiert. Version: $($r.version)" -ForegroundColor Green
  Write-Host ""
  Write-Host "→ Jetzt: Browser öffnen, https://… aufrufen, mit demselben Passwort einloggen wie damals beim Backup-Erstellen." -ForegroundColor Cyan
} catch {
  Write-Host "❌ Import fehlgeschlagen: $($_.Exception.Message)" -ForegroundColor Red
  if ($_.ErrorDetails.Message) { Write-Host $_.ErrorDetails.Message }
}
