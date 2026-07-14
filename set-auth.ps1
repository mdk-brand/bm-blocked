$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$configPath = Join-Path $root "auth-config.json"
$iterations = 310000

function ConvertTo-PlainText {
  param([Security.SecureString]$SecureValue)

  $pointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureValue)

  try {
    return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer)
  } finally {
    [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer)
  }
}

function New-Pbkdf2Credential {
  param([string]$Value)

  $salt = New-Object byte[] 16
  $random = [Security.Cryptography.RandomNumberGenerator]::Create()

  try {
    $random.GetBytes($salt)
  } finally {
    $random.Dispose()
  }

  $derive = [Security.Cryptography.Rfc2898DeriveBytes]::new(
    $Value,
    $salt,
    $iterations,
    [Security.Cryptography.HashAlgorithmName]::SHA256
  )

  try {
    $hash = $derive.GetBytes(32)
  } finally {
    $derive.Dispose()
  }

  return [ordered]@{
    algorithm = "pbkdf2-sha256"
    iterations = $iterations
    salt = [Convert]::ToBase64String($salt)
    hash = [Convert]::ToBase64String($hash)
  }
}

if (Test-Path $configPath) {
  $answer = Read-Host "Authorization is already configured. Overwrite it? (yes/no)"

  if ($answer.Trim().ToLowerInvariant() -notin @("yes", "y")) {
    Write-Host "Setup cancelled."
    exit 0
  }
}

$username = (Read-Host "Login").Trim()

if ($username.Length -lt 8 -or $username.Length -gt 128) {
  throw "Login must contain between 8 and 128 characters."
}

$securePassword = Read-Host "Password (at least 16 characters)" -AsSecureString
$secureConfirmation = Read-Host "Repeat password" -AsSecureString
$password = ConvertTo-PlainText $securePassword
$confirmation = ConvertTo-PlainText $secureConfirmation

try {
  if ($password.Length -lt 16) {
    throw "Password must contain at least 16 characters."
  }

  if (-not [string]::Equals($password, $confirmation, [StringComparison]::Ordinal)) {
    throw "Passwords do not match."
  }

  $config = [ordered]@{
    version = 2
    username = (New-Pbkdf2Credential $username)
    password = (New-Pbkdf2Credential $password)
  }

  $json = $config | ConvertTo-Json -Depth 4
  $utf8WithoutBom = New-Object Text.UTF8Encoding($false)
  [IO.File]::WriteAllText($configPath, $json, $utf8WithoutBom)

  Write-Host "Authorization configured."
  Write-Host "Created: $configPath"
  Write-Host "Run build-exe.ps1 to build the internal release."
} finally {
  $password = $null
  $confirmation = $null
}
