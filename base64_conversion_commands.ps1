$Filename = (Get-Location).Path + "\ConPtyShell.exe"
$base64string_x64 = [Convert]::ToBase64String([IO.File]::ReadAllBytes($FileName))
$base64string_x64 | Out-File ConPtyShell.base64