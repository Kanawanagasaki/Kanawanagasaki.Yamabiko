$projectFile = Join-Path $pwd "Kanawanagasaki.Yamabiko.Server.csproj"

if (-not (Test-Path $projectFile)) {
    Write-Error "Project file not found: $projectFile"
    exit 1
}

try {
    $xml = [xml](Get-Content $projectFile)
    $versionNode = $xml.SelectSingleNode("//*[local-name()='Version']")
    
    if (-not $versionNode -or [string]::IsNullOrWhiteSpace($versionNode.InnerText)) {
        Write-Error "Version element not found or empty in $projectFile"
        exit 1
    }
    
    $version = $versionNode.InnerText.Trim()
    Write-Host "Yamabiko Server Version: $version"
}
catch {
    Write-Error "Failed to parse version from .csproj: $_"
    exit 1
}

$rids = @(
    "win-x64",
    "linux-x64",
    "osx-x64",
    "osx-arm64"
)

$outputDir = Join-Path $pwd "bin/Publish/$version"

$publishProps = @{
    Configuration = "Release"
    PublishSingleFile = "true"
    PublishTrimmed = "true"
}

New-Item -ItemType Directory -Force -Path $outputDir | Out-Null

foreach ($rid in $rids) {
    $targetName = "Yamabiko-Server-$version-$rid"
    $exeName = $targetName
    $publishName = "Kanawanagasaki.Yamabiko.Server"
    if ($rid.StartsWith("win")) {
        $exeName += ".exe"
        $publishName += ".exe"
    }
    
    Write-Host "`nPublishing $exeName..."

    $publishArgs = @(
        "publish",
        $projectFile,
        "-c", "Release",
        "-r", $rid,
        "-o", $outputDir
    )
    
    foreach ($prop in $publishProps.GetEnumerator()) {
        $publishArgs += "-p:$($prop.Key)=$($prop.Value)"
    }
    
    $process = Start-Process -FilePath "dotnet" -ArgumentList $publishArgs -NoNewWindow -Wait -PassThru
    
    if ($process.ExitCode -ne 0) {
        Write-Error "Publish failed for $rid with exit code $($process.ExitCode)"
        exit $process.ExitCode
    }

    $sourceExe = Join-Path $outputDir $publishName
    $destExe = Join-Path $outputDir $exeName
    Move-Item -Path $sourceExe -Destination $destExe -Force
}

Write-Host "Output directory: $outputDir"
