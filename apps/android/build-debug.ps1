[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$MobileBaseUrl,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$CloudflareIssuer,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$CloudflareResource,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$OAuthClientId,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$OAuthAuthorizationEndpoint,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$OAuthTokenEndpoint
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Stop-WithError {
    param([Parameter(Mandatory = $true)][string]$Message)
    throw $Message
}

function Get-RequiredCommand {
    param([Parameter(Mandatory = $true)][string]$Name)

    $command = Get-Command $Name -ErrorAction SilentlyContinue
    if ($null -eq $command) {
        Stop-WithError "Required command '$Name' was not found on PATH. Install the Android/JDK toolchain, then rerun this script."
    }
    return $command
}

function Get-HttpsUri {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$Value,
        [Parameter(Mandatory = $true)][bool]$OriginOnly
    )

    $uri = $null
    if (-not [Uri]::TryCreate($Value, [UriKind]::Absolute, [ref]$uri)) {
        Stop-WithError "$Name must be an absolute HTTPS URL."
    }
    if ($uri.Scheme -ne "https" -or [string]::IsNullOrWhiteSpace($uri.Host)) {
        Stop-WithError "$Name must use HTTPS and include a host."
    }
    if (-not [string]::IsNullOrEmpty($uri.UserInfo) -or
        -not [string]::IsNullOrEmpty($uri.Query) -or
        -not [string]::IsNullOrEmpty($uri.Fragment)) {
        Stop-WithError "$Name must not contain credentials, a query, or a fragment."
    }
    if ($OriginOnly -and $uri.AbsolutePath -notin @("", "/")) {
        Stop-WithError "$Name must be an origin URL without a path."
    }
    return $uri
}

$mobileUri = Get-HttpsUri -Name "MobileBaseUrl" -Value $MobileBaseUrl -OriginOnly $true
$resourceUri = Get-HttpsUri -Name "CloudflareResource" -Value $CloudflareResource -OriginOnly $false
$issuerUri = Get-HttpsUri -Name "CloudflareIssuer" -Value $CloudflareIssuer -OriginOnly $false
$authorizationUri = Get-HttpsUri -Name "OAuthAuthorizationEndpoint" -Value $OAuthAuthorizationEndpoint -OriginOnly $false
$tokenUri = Get-HttpsUri -Name "OAuthTokenEndpoint" -Value $OAuthTokenEndpoint -OriginOnly $false

if ($resourceUri.GetLeftPart([UriPartial]::Authority).TrimEnd("/") -ine
    $mobileUri.GetLeftPart([UriPartial]::Authority).TrimEnd("/")) {
    Stop-WithError "CloudflareResource must use the same origin as MobileBaseUrl."
}
if ($authorizationUri.GetLeftPart([UriPartial]::Authority).TrimEnd("/") -ine
    $issuerUri.GetLeftPart([UriPartial]::Authority).TrimEnd("/") -or
    $tokenUri.GetLeftPart([UriPartial]::Authority).TrimEnd("/") -ine
    $issuerUri.GetLeftPart([UriPartial]::Authority).TrimEnd("/")) {
    Stop-WithError "OAuth endpoints must use the Cloudflare issuer origin."
}
if ($OAuthClientId -match "[\x00-\x1F\x7F\s]") {
    Stop-WithError "OAuthClientId must not contain whitespace or control characters."
}

$java = Get-RequiredCommand -Name "java"
$javaVersion = (& $java.Source -version 2>&1 | Out-String)
if ($LASTEXITCODE -ne 0) {
    Stop-WithError "The Java runtime could not be executed. Install JDK 17 or newer."
}
$javaMatch = [regex]::Match($javaVersion, 'version\s+"(?<major>\d+)')
if (-not $javaMatch.Success -or [int]$javaMatch.Groups["major"].Value -lt 17) {
    Stop-WithError "JDK 17 or newer is required. Detected: $($javaVersion.Trim())"
}

$sdkRootValue = if (-not [string]::IsNullOrWhiteSpace($env:ANDROID_SDK_ROOT)) {
    $env:ANDROID_SDK_ROOT
} elseif (-not [string]::IsNullOrWhiteSpace($env:ANDROID_HOME)) {
    $env:ANDROID_HOME
} else {
    $null
}
if ([string]::IsNullOrWhiteSpace($sdkRootValue)) {
    Stop-WithError "ANDROID_SDK_ROOT (or the legacy ANDROID_HOME) is not set. Install Android SDK API 36 and set its path."
}
$sdkRoot = [IO.Path]::GetFullPath($sdkRootValue)
if (-not (Test-Path -LiteralPath $sdkRoot -PathType Container)) {
    Stop-WithError "Android SDK directory does not exist: $sdkRoot"
}
$androidJar = Join-Path $sdkRoot "platforms\android-36\android.jar"
if (-not (Test-Path -LiteralPath $androidJar -PathType Leaf)) {
    Stop-WithError "Android SDK platform 36 is missing: $androidJar"
}
$buildToolsRoot = Join-Path $sdkRoot "build-tools"
$isWindowsHost = $env:OS -eq "Windows_NT" -or
    [Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT
$sdkExecutable = if ($isWindowsHost) { "aapt2.exe" } else { "aapt2" }
$buildTools = @(Get-ChildItem -LiteralPath $buildToolsRoot -Directory -ErrorAction SilentlyContinue |
    Where-Object { Test-Path -LiteralPath (Join-Path $_.FullName $sdkExecutable) } |
    Sort-Object Name -Descending)
if ($buildTools.Count -eq 0) {
    Stop-WithError "No Android SDK build-tools installation with $sdkExecutable was found under $buildToolsRoot."
}

$projectDir = [IO.Path]::GetFullPath($PSScriptRoot)
$gradleWrapper = @(
    (Join-Path $projectDir "gradlew.bat"),
    (Join-Path $projectDir "gradlew")
) | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } | Select-Object -First 1
if ([string]::IsNullOrWhiteSpace($gradleWrapper)) {
    Stop-WithError "Gradle wrapper is missing from $projectDir."
}

$verificationMetadata = Join-Path $projectDir "gradle\verification-metadata.xml"

function Invoke-Gradle {
    param([Parameter(Mandatory = $true)][string[]]$Arguments)

    Push-Location -LiteralPath $projectDir
    try {
        & $gradleWrapper @Arguments
        $script:GradleExitCode = $LASTEXITCODE
    } finally {
        Pop-Location
    }
}

if (-not (Test-Path -LiteralPath $verificationMetadata -PathType Leaf)) {
    Write-Host "Gradle verification metadata is missing; generating SHA-256 metadata now..."
    $script:GradleExitCode = $null
    Invoke-Gradle -Arguments @(
        "--write-verification-metadata",
        "sha256",
        "dependencies"
    )
    $metadataExitCode = $script:GradleExitCode
    if ($metadataExitCode -ne 0 -or -not (Test-Path -LiteralPath $verificationMetadata -PathType Leaf)) {
        Stop-WithError "Gradle could not generate $verificationMetadata (exit code $metadataExitCode)."
    }
    Write-Host "Generated $verificationMetadata. Review it and commit it with the Android project."
}

$gradleArguments = @(
    "-Phermes.mobileBaseUrl=$MobileBaseUrl",
    "-Phermes.cloudflareIssuer=$CloudflareIssuer",
    "-Phermes.cloudflareResource=$CloudflareResource",
    "-Phermes.oauthClientId=$OAuthClientId",
    "-Phermes.oauthAuthorizationEndpoint=$OAuthAuthorizationEndpoint",
    "-Phermes.oauthTokenEndpoint=$OAuthTokenEndpoint",
    "assembleDebug"
)

Write-Host "Android toolchain preflight passed (JDK $($javaMatch.Groups["major"].Value), SDK API 36)."
Write-Host "Building the configured Hermes Mobile debug APK..."
$script:GradleExitCode = $null
Invoke-Gradle -Arguments $gradleArguments
$gradleExitCode = $script:GradleExitCode
if ($gradleExitCode -ne 0) {
    Stop-WithError "Gradle assembleDebug failed with exit code $gradleExitCode."
}

$apkPath = Join-Path $projectDir "app\build\outputs\apk\debug\app-debug.apk"
if (-not (Test-Path -LiteralPath $apkPath -PathType Leaf)) {
    Stop-WithError "Gradle completed without producing the expected APK: $apkPath"
}
$apkHash = (Get-FileHash -LiteralPath $apkPath -Algorithm SHA256).Hash.ToLowerInvariant()
Write-Host "Debug APK: $apkPath"
Write-Host "SHA-256:   $apkHash"
Write-Host "Next step: install this APK on the Android test device, then complete OAuth enrollment and host approval."
