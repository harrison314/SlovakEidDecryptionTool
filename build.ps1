
Function CleanDir($dir){
    If (Test-Path $dir) {
        Remove-Item -LiteralPath $dir -Force -Recurse | Out-Null
    }
    New-Item -ItemType directory -Path $dir | Out-Null
}

Push-Location
& dotnet test "src\Tests\SlovakEidDecryptionTool.Tests\SlovakEidDecryptionTool.Tests.csproj"
If (-Not $?) {
    Write-Host "Test failed - Exited build"
    Exit
}

CleanDir(".\artefacts");
CleanDir(".\tmp");
& dotnet publish "src\Src\SlovakEidDecryptionToolCli\SlovakEidDecryptionToolCli.csproj" -c Release --output "..\..\..\tmp"
"dotnet SlovakEidDecryptionToolCli.dll %*" | Out-File ".\tmp\SlovakEidDecryptionToolCli.bat" | Out-Null
"dotnet SlovakEidDecryptionToolCli.dll $@" | Out-File ".\tmp\SlovakEidDecryptionToolCli.sh" | Out-Null
Compress-Archive -Path ".\tmp\*" -DestinationPath ".\artefacts\SlovakEidDecryptionToolCli.zip"

CleanDir(".\tmp");
& dotnet publish "src\Src\SlovakEidDecryptionToolCli\SlovakEidDecryptionToolCli.csproj" -c Release -o "..\..\..\tmp" -r win-x86
Compress-Archive -Path ".\tmp\*" -DestinationPath ".\artefacts\SlovakEidDecryptionToolCli.win-x86.zip"

CleanDir(".\tmp");
& dotnet publish "src\Src\SlovakEidDecryptionToolCli\SlovakEidDecryptionToolCli.csproj" -c Release -o "..\..\..\tmp" -r win-x64
Compress-Archive -Path ".\tmp\*" -DestinationPath ".\artefacts\SlovakEidDecryptionToolCli.win-x64.zip"

CleanDir(".\tmp");
& dotnet publish "src\Src\SlovakEidDecryptionToolCli\SlovakEidDecryptionToolCli.csproj" -c Release -o "..\..\..\tmp" -r linux-x64
Compress-Archive -Path ".\tmp\*" -DestinationPath ".\artefacts\SlovakEidDecryptionToolCli.linux-x64.zip"

Pop-Location

If (Test-Path ".\tmp") {
    Remove-Item -LiteralPath ".\tmp" -Force -Recurse | Out-Null
}