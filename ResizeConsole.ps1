$width=80
$height=24
$Host.UI.RawUI.BufferSize = New-Object Management.Automation.Host.Size ($width, $height)
$host.UI.RawUI.WindowSize = New-Object -TypeName System.Management.Automation.Host.Size -ArgumentList ($width, $height)