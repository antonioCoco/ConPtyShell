$Filename = (Get-Location).Path + "\ConPtyShell_dotnet2.exe"
$base64string_x64 = [Convert]::ToBase64String([IO.File]::ReadAllBytes($FileName))
$base64string_x64 | Out-File ConPtyShell.base64