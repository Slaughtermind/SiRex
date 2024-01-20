#-- Name		: SiRex.ps1
#-- Engine		: PowerShell 2.0+, .NET v3.5+, Minimum screen resolution: 1280x800
#-- Version		: 1.09 Stable
#-- Date		: 04.04.2019
#-- Changes		: Bug fixes and performance improvements
#-- Usage		: Get-Help .\SiRex.ps1
#-- Developer	: PS-Solutions.net
#-- First dev	: Basic version created by Effi-Azzari Abdullah
#-- License		: GNU General Public License | http://www.gnu.org/licenses/gpl-2.0.html
#-- Purpose		: Check systeam health of remote computers by WMI Win32 classes. Execute remote script as a local process.
#-- References	: StackOverflow, Microsoft Blogs, 4SYSOPS, ServerFault

<#
.SYNOPSIS
System Information and Remote Execution

.DESCRIPTION
Get software and hardware information from remote computers by WMI classes and Registry.
Send script (Batch, PS, VBS, Python, etc.) on remote system and execute it as a local process.
HTML report is generated with JavaScript management buttons that work only in Internet Explorer.

.Link
https://ps-solutions.net/index.php/sirex/

.EXAMPLE
.\SiRex.ps1 -ConfigFile .\config\iniTest.ini
#>

Param(
[ValidateScript({Test-Path $_ -PathType Leaf})]
[string]$ConfigFile <#config.ini#>,

[string]$ConfigKey <#<encryption key>#>,

[switch]$Update
)

Add-Type -AssemblyName System.DirectoryServices.AccountManagement | Out-Null
Add-Type -AssemblyName System.Web.Extensions | Out-Null
Add-Type -AssemblyName System.Web | Out-Null

$sync = [Hashtable]::Synchronized(@{})
$ScriptName = ($MyInvocation.MyCommand.Name)
$ScriptPath = $MyInvocation.MyCommand.Path
$ScriptPath = $ScriptPath.SubString(0, $ScriptPath.LastIndexOf("\"))
$Error.Clear()

Function DeserializeINI([string[]]$iniData ) {
	$Json = @{}
	$Json.Add("DecryptionTest", "</Milestone-AES256_Decryption&JSON_Verification!>")
	
	$iniData | ForEach-Object {
		$elem = $_.Split("=", 2)
		
		if([bool]$elem[0].Trim() -and -not $elem[0].StartsWith("[") -and -not $elem[0].StartsWith("`#") -and -not $elem[0].StartsWith(";")) {
			$Json.Add($elem[0].Trim(), $elem[1].Trim())
		}
	}
	
	#### Verify outfolder
	$Error.Clear(); $failure = $false
	$default = $Json.OutFolder
	
	if (-not $Json.OutFolder) { $Json.OutFolder = "<current script's folder>" }
	
	#### Get computers from file
	$Error.Clear(); $failure = $false
	$default = $Json.File
	
	if (-not $Json.File) {
		$Json.File = ''
	}
	elseif (Test-Path $Json.File -PathType Leaf) {
		$Json.File = (Resolve-Path $Json.File).Path
	}
	else { $failure = $true	}
	
	if ($Error -or $failure) { $Json.File = '' }
	elseif ($Json.File) { $Json.File = [System.IO.File]::ReadAllText($Json.File, [System.Text.Encoding]::UTF8) }
	
	#### Verify computers
	if ($Json.Computers -or $Json.File) {
		[string[]]$Computers = ($Json.Computers + "," + $Json.File) -split '[,;\s]' -match '\S'
		$Json.Computers = $Computers -join ","
	}
	
	#### Verify addon script
	$Error.Clear(); $failure = $false
	
	if (-not $Json.ScriptFile) {
		$Json.ScriptFile = "<Type script up to 1MB>"
	}
	elseif (Test-Path $Json.ScriptFile -PathType Leaf) {
		$Json.ScriptFile = (Resolve-Path $Json.ScriptFile).Path
	}
	else { $failure = $true }
	
	if ($Error -or $failure) { $Json.ScriptFile = '' }
	elseif ($Json.ScriptFile) {
		$Json.Extension = ($Json.ScriptFile.Split("."))[-1]
		if (@('bat','ps1') -contains $Json.Extension) { $Json.Extension = '' }
		$Json.ScriptFile = [System.IO.File]::ReadAllText($Json.ScriptFile, [System.Text.Encoding]::UTF8)
	}
	
	#### Check numeric values
	if ($Json.MultiTask -notmatch "^[\d]+$" -or [int]$Json.MultiTask -lt 1 -or [int]$Json.MultiTask -gt 9) {
		$Json.MultiTask = 5
	}
	
	if ($Json.Timeout -notmatch "^[\d]+$" -or [int]$Json.Timeout -lt 1 -or [int]$Json.Timeout -gt 999) {
		$Json.Timeout = 12
	}
	
	if ($Json.HotfixDays -notmatch "^[\d]+$" -or [int]$Json.HotfixDays -lt 1 -or [int]$Json.HotfixDays -gt 99999) {
		$Json.HotfixDays = 7
	}
	
	if (($Json.SmtpPort -notmatch "^[\d]+$") -or ([int]$Json.SmtpPort -lt 1) -or ([int]$Json.SmtpPort -gt 65535)) {
		$Json.SmtpPort = 587
	}
	
	$Json.DisableEdit = $(if (@("1","YES","TRUE") -contains $Json.DisableEdit) {1} else {0})
	$Json.WithCredentials = $(if (@("1","YES","TRUE") -contains $Json.WithCredentials) {1} else {0})
	$Json.VerifyCredentials = $(if (@("1","YES","TRUE") -contains $Json.VerifyCredentials) {1} else {0})
	$Json.Batch = $(if (@("1","YES","TRUE") -contains $Json.Batch) {1} else {0})
	$Json.PowerShell = $(if (@("1","YES","TRUE") -contains $Json.PowerShell) {1} else {0})
	$Json.UTF8BOM = $(if (@("1","YES","TRUE") -contains $Json.UTF8BOM) {1} else {0})
	$Json.Win32Process = $(if (@("1","YES","TRUE") -contains $Json.Win32Process) {1} else {0})
	$Json.InvokeCommand = $(if (@("1","YES","TRUE") -contains $Json.InvokeCommand) {1} else {0})
	$Json.SendMail = $(if (@("1","YES","TRUE") -contains $Json.SendMail) {1} else {0})
	
	$Json.HWinfo = $(if (@("1","YES","TRUE") -contains $Json.HWinfo) {1} else {0})
	$Json.OSinfo = $(if (@("1","YES","TRUE") -contains $Json.OSinfo) {1} else {0})
	$Json.DeviceError = $(if (@("1","YES","TRUE") -contains $Json.DeviceError) {1} else {0})
	$Json.LocalTime = $(if (@("1","YES","TRUE") -contains $Json.LocalTime) {1} else {0})
	$Json.BootTime = $(if (@("1","YES","TRUE") -contains $Json.BootTime) {1} else {0})
	$Json.UpTime = $(if (@("1","YES","TRUE") -contains $Json.UpTime) {1} else {0})
	$Json.Hotfix = $(if (@("1","YES","TRUE") -contains $Json.Hotfix) {1} else {0})
	$Json.PendingReboot = $(if (@("1","YES","TRUE") -contains $Json.PendingReboot) {1} else {0})
	$Json.Services = $(if (@("1","YES","TRUE") -contains $Json.Services) {1} else {0})
	$Json.Cluster = $(if (@("1","YES","TRUE") -contains $Json.Cluster) {1} else {0})
	$Json.DiskSpace = $(if (@("1","YES","TRUE") -contains $Json.DiskSpace) {1} else {0})
	$Json.SMB = $(if (@("1","YES","TRUE") -contains $Json.SMB) {1} else {0})
	$Json.RDP = $(if (@("1","YES","TRUE") -contains $Json.RDP) {1} else {0})
	
	return $Json
}

Function EncryptFile([string]$StringKey, [string]$contentBase64) {
	$bytes = [System.Convert]::FromBase64String($contentBase64)
	$KeyBytes = [System.Text.Encoding]::UTF8.GetBytes($StringKey)
	
	$KeyBytes += New-Object byte[] 32
	$key = $KeyBytes[0..31]
	
	$aesManaged = New-Object "System.Security.Cryptography.AesManaged"
	$aesManaged.Mode = [System.Security.Cryptography.CipherMode]::CBC
	$aesManaged.Padding = [System.Security.Cryptography.PaddingMode]::Zeros
	$aesManaged.BlockSize = 128
	$aesManaged.KeySize = 256
	$aesManaged.Key = $key
	
	$encryptor = $aesManaged.CreateEncryptor()
	$encryptedData = $encryptor.TransformFinalBlock($bytes, 0, $bytes.Length);
	[byte[]] $fullData = $aesManaged.IV + $encryptedData
	#$aesManaged.Dispose() ### PS 2.0 error
	
	$encryptedString = [System.Convert]::ToBase64String($fullData)
	
	return $encryptedString
}

Function DecryptFile([string]$StringKey, [string]$encryptedString) {
	$KeyBytes = [System.Text.Encoding]::UTF8.GetBytes($StringKey)
	$KeyBytes += New-Object byte[] 32
	$key = $KeyBytes[0..31]
	
	$bytes = [System.Convert]::FromBase64String($encryptedString)
	$IV = $bytes[0..15]
	
	$aesManaged = New-Object "System.Security.Cryptography.AesManaged"
	$aesManaged.Mode = [System.Security.Cryptography.CipherMode]::CBC
	$aesManaged.Padding = [System.Security.Cryptography.PaddingMode]::Zeros
	$aesManaged.BlockSize = 128
	$aesManaged.KeySize = 256
	
	$aesManaged.IV = $IV
	$aesManaged.Key = $key
	
	$decryptor = $aesManaged.CreateDecryptor();
	$unencryptedData = $decryptor.TransformFinalBlock($bytes, 16, $bytes.Length - 16);
	#$aesManaged.Dispose() ### PS 2.0 error
	$PlainText = [System.Text.Encoding]::UTF8.GetString($unencryptedData).Trim([char]0)
	
	return $PlainText
}

$ScriptUpdate = {
	Param([bool]$GUI, [string]$operation, [String]$ScriptPath, [String]$ScriptName)
	
	$Error.Clear()
	Add-Type -AssemblyName System.Web.Extensions | Out-Null
	Add-Type -AssemblyName System.Web | Out-Null
	
	$outfile = "$ScriptPath`\" + $ScriptName
	$tempfile = "$ScriptPath`\~" + $ScriptName + ".temp"
	$bakfile = "$ScriptPath`\" + $ScriptName.SubString(0, $ScriptName.LastIndexOf(".")) + "-backup.ps1"
	
	if ($GUI) {
		$UpdateInfo.check.Enabled = $UpdateInfo.stable.Enabled = $false
		$UpdateInfo.status.Text = "Connecting to cloud storage . . . "
	}
	else { Write-Host "`r`nConnecting to cloud storage . . . " -NoNewline }
	
	$ConfigURL = "https://ps-solutions.net/repository/sirex/update.json"
	
	$Json = (New-Object System.Net.WebClient).DownloadString($ConfigURL)
	$Serialization = New-Object System.Web.Script.Serialization.JavaScriptSerializer
	$Config = $Serialization.DeserializeObject($Json)
	
	if ($Error) {
		if ($GUI) {
			$UpdateInfo.status.Text += "Failure!`r`n`r`n" + [String]$Error
			$UpdateInfo.check.Enabled = $UpdateInfo.stable.Enabled = $true
		}
		else { Write-Host "Failure!`r`n`r`n" }
		
		return $null
	}
	else {
		if ($GUI) { $UpdateInfo.status.Text += "Connected.`r`n" }
		else { Write-Host "Connected.`r`n" }
	}
	
	if ($operation -eq "Info") {
		$AddText = "`r`nYour version: 1.09 Stable`r`n`r`nCurrent version: " + $Config.Stable.Version + ", " + $Config.Stable.Message
		
		if ($GUI) { $UpdateInfo.status.Text += $AddText }
		else { Write-Host $AddText }
	}
	else {
		$n = ($Config.Stable.URLs | Measure-Object).Count
		
		for ($i = 0; $i -lt $n; $i++) {
			$AddText = "Updating to version " + $Config.Stable.Version + " from mirror " + ($i + 1) + " . . . "
			
			if ($GUI) { $UpdateInfo.status.Text += $AddText }
			else { Write-Host $AddText -NoNewline }
			
			if (Test-Path $tempfile -PathType Leaf) { Remove-Item $tempfile -Force }
			
			$Error.Clear()
			(New-Object System.Net.WebClient).DownloadFile($Config.Stable.URLs[$i], $tempfile)
			
			if ($Error) {
				if ($GUI) { $UpdateInfo.status.Text += "Failure!`r`n" }
				else { Write-Host "Failure!`r`n" }
				
				if (Test-Path $tempfile -PathType Leaf) { Remove-Item $tempfile -Force }
				continue
			}
			else {
				if (Test-Path $bakfile -PathType Leaf) { Remove-Item $bakfile -Force }
				Rename-Item $outfile -NewName $bakfile -Force
				Rename-Item $tempfile -NewName $outfile -Force
				
				if ($GUI) { $UpdateInfo.status.Text += "Updated.`r`n`r`nUpdate succeeded. Close and run the sript again to apply new changes." }
				else { Write-Host "Updated.`r`n`r`nUpdate succeeded. Close and run the sript again to apply new changes." }
				
				break
			}
		}
		
		if ($Error) {
			if ($GUI) { $UpdateInfo.status.Text += "`r`nUnable to update from the available mirrors." }
			else { Write-Host "`r`nUnable to update from the available mirrors." }
		}
	}
	
	$UpdateInfo.check.Enabled = $UpdateInfo.stable.Enabled = $true
}

$CommandLine = [int][bool]$ConfigFile + [int][bool]$ConfigKey + [int][bool]$Update

### Stream compression: https://gist.github.com/marcgeld/bfacfd8d70b34fdf1db0022508b02aca

if ($CommandLine) {
	
	Function FaultConfig([string]$message) {
		Write-Host ("`r`n $message `r`n`r`n Type ""Get-Help .\SiRex.ps1"" for more details.`r`n") -ForegroundColor Red
		Exit
	}
	
	if ($Update.IsPresent) {
		Invoke-Command -ScriptBlock $ScriptUpdate -ArgumentList $false, "Stable", $ScriptPath, $ScriptName
		Exit
	}
	
	$sync.InstIndex = 0
	
	if ($ConfigFile) {
		$ConfigFile = (Resolve-Path $ConfigFile).Path
		
		if ($ConfigFile.EndsWith(".ini")) {
			[string[]]$iniData = [System.IO.File]::ReadAllLines($ConfigFile, [System.Text.Encoding]::UTF8)
			
			if (($iniData | Out-String).Trim()) { $Json = DeserializeINI $iniData }
			else { FaultConfig "Empty Config file or wrong format." }
		}
		elseif ($ConfigFile.EndsWith(".bin" )) {
			$bytes = [System.IO.File]::ReadAllBytes($ConfigFile)
			$contentBase64 = [System.Convert]::ToBase64String($bytes)
			$jsonData = (DecryptFile "<SiRex-Default_Encryption>" $contentBase64 | Out-String).Trim()
		}
		elseif ($ConfigFile.EndsWith(".enc")) {
			$bytes = [System.IO.File]::ReadAllBytes($ConfigFile)
			$contentBase64 = [System.Convert]::ToBase64String($bytes)
			$jsonData = (DecryptFile $ConfigKey $contentBase64 | Out-String).Trim()
		}
		else { FaultConfig "Wrong config file format." }
		
		if (-not $ConfigFile.EndsWith(".ini")) {
			if ($jsonData) {
				$Error.Clear()
				$Serialization = New-Object System.Web.Script.Serialization.JavaScriptSerializer
				Try { $Json = $Serialization.DeserializeObject($jsonData) } Catch {}
				
				if ([bool]$Error -or $Json.DecryptionTest -ne "</Milestone-AES256_Decryption&JSON_Verification!>") {
					FaultConfig "Decryption Failure!"
				}
			}
			else { FaultConfig "Empty Config file or wrong format." }
		}
	}
	else { FaultConfig "Config file is not specified." }
	
	$Json.OutFolder = $(if ($Json.OutFolder -ne "<current script's folder>" -and [bool]$Json.OutFolder.Trim()) { $Json.OutFolder } else { $ScriptPath })
	
	$wt = $Json.OutFolder + "\~" + (Get-Date).ToFileTime() + ".tmp"
	New-Item $wt -ItemType File -Force -ErrorAction SilentlyContinue | Out-Null
	
	if (Test-Path $wt -PathType Leaf) {
		Remove-Item $wt -Force | Out-Null
		$Json.OutFolder = (Resolve-Path $Json.OutFolder).Path
		$sync.add("OutFile", @{"Text" = $Json.OutFolder})
	}
	else {
		FaultConfig "Insufficient permissions to output folder: $wt"
	}
	
	if (-not $Json.Computers) { FaultConfig "There are no computers specified in cofig file!" }
	
	if ($Json.WithCredentials) {
		$creds = $Json.UserName.Split("\", 2)
		
		if ($creds.Count -ne 2) {
			FaultConfig "`r`n`t Wrong credentials format. Provide valid domain, username and password."
		}
		
		if ($creds[0] -ne "." -and [System.Uri]::CheckHostName($creds[0]) -eq 'Unknown') {
			FaultConfig "`r`n`t Invalid domain name."
		}
		
		if ($creds[1] -match "[\[\]\:\;\,\""\|\=\+\*\/\?\<\>\\]") {
			FaultConfig "`r`n`t Invalid username format."
		}
		
		if (-not $Json.Password) {
			FaultConfig "`r`n`t Missing password."
		}
		
		$Password = ConvertTo-SecureString $Json.Password -AsPlainText -Force
		$Cred = New-Object System.Management.Automation.PSCredential -ArgumentList $Json.UserName, $Password
	}
	else { $Cred = '' }
	
	if ($Json.SendMail) {
		if (-not ($Json.MailFrom -and $Json.MailPassword -and $Json.MailTo -and $Json.SmtpServer -and $Json.SmtpPort)) {
			FaultConfig "Missing important details in mail options. Mail will not be sent."
		}
		
		if (($Json.MailFrom.Trim() -match '[,;\s]') -or (-not ($Json.MailFrom.Trim() -as [System.Net.Mail.MailAddress]))) {
			FaultConfig ("`r`n`t Invalid sender's mail address: " + $Json.MailFrom.Trim())
		}
		
		$mails = $Json.MailTo -split '[,;\s]' -match '\S'
		$mailerr = $false
		if ($mails) {
			foreach ($mail in $mails) {
				if (-not ($mail -as [System.Net.Mail.MailAddress])) {
					FaultConfig ("`r`n`t Invalid recipient's mail address: " + $mail)
				}
			}
		}
		
		if ([System.Uri]::CheckHostName($Json.SmtpServer.Trim()) -eq 'Unknown') {
			FaultConfig "`r`n`t Invalid SMTP server."
		}
	}
	
	if ([bool]$Json.ScriptFile -and $Json.ScriptFile -ne "<Type script up to 1MB>"){
		$ScriptBinary = [System.Text.Encoding]::UTF8.GetBytes(($Json.ScriptFile -replace "`n", "`r`n")) + [byte[]](@(13,10))
		if ($Json.UTF8BOM) { $ScriptBinary = [System.Text.Encoding]::UTF8.GetPreamble() + $ScriptBinary }
		
		if (-not $Json.Batch) {
			$ScriptBase64 = [System.Convert]::ToBase64String($ScriptBinary)
		}
		else {
			for ($i = $j = 0; $j -lt $ScriptBinary.Count; $i += 20480) {
				$j = $i + 20480 - 1
				if ($j -ge $ScriptBinary.Count) {
					$j = $ScriptBinary.Count - 1
					$ScriptBase64 += [System.Convert]::ToBase64String($ScriptBinary[$i..$j]) + ","
					break
				}
				
				$ScriptBase64 += [System.Convert]::ToBase64String($ScriptBinary[$i..$j]) + ","
			}
		}
	}
	else { $Json.Token = $Json.ScriptFile = $Json.Extension = $Json.Arguments = '' }
	
	if (($Json.Token.ToCharArray() | Where-Object {$_ -eq """"} | Measure-Object).Count % 2 -eq 1) {
		FaultConfig "`r`n`t No closing quotes in Exec/Token"
	}
	
	if (($Json.Token.ToCharArray() | Where-Object {$_ -eq "'"} | Measure-Object).Count % 2 -eq 1) {
		FaultConfig "`r`n`t No closing quotes in Exec/Token"
	}
	
	if (($Json.Arguments.ToCharArray() | Where-Object {$_ -eq """"} | Measure-Object).Count % 2 -eq 1) {
		FaultConfig "`r`n`t No closing quotes in Arguments"
	}
	
	if (($Json.Arguments.ToCharArray() | Where-Object {$_ -eq "'"} | Measure-Object).Count % 2 -eq 1) {
		FaultConfig "`r`n`t No closing quotes in Arguments"
	}
	
	$query = @{
		Computers = [string[]]($Json.Computers -split '[,;\s]' -match '\S')
		Computer = ''
		Instance = $sync.InstIndex
		
		Domain = $Json.UserName.Split("\")[0]
		WithCred = $Json.WithCredentials
		Cred = $Cred
		NoCredVerify = -not $Json.VerifyCredentials
		LocalCred = $Json.UserName.Split("\")[0] -eq '.'
		Username = $Json.UserName
		Password = $Json.Password
		
		HW = $Json.HWinfo
		Device = $Json.DeviceError
		OS = $Json.OSinfo
		LTime = $Json.LocalTime
		BTime = $Json.BootTime
		UTime = $Json.UpTime
		Hotfix = $Json.Hotfix
		HotfixDays = $Json.HotfixDays
		Reboot = $Json.PendingReboot
		Service = $Json.Services
		Cluster = $Json.Cluster
		Disk = $Json.DiskSpace
		SMB = $Json.SMB
		RDP = $Json.RDP
		
		Tasks = $Json.MultiTask
		Timeout = $Json.Timeout
		RefreshTime = 3
		
		ScriptCMD = $Json.Batch
		ScriptWMI = $Json.Win32Process
		
		ScriptToken = $Json.Token -replace """", $("""" * 3)
		ScriptExt = $Json.Extension
		ScriptBase64 = $ScriptBase64
		ScriptArg = $Json.Arguments -replace """", $("""" * 3)
		
		OutFolder = $Json.OutFolder
		Filename = $Json.OutFolder + "\Report-" + (Get-Date).ToFileTime() + ".html"
		
		SendMail = $Json.SendMail
		MailUser = $Json.MailFrom
		MailPass = $Json.MailPassword
		MailTo = $mails -join ', '
		SmtpServer = $Json.SmtpServer
		SmtpPort = $Json.SmtpPort
	}
}

else {
	Write-Host "`r`n`t Wait until graphic interface shows. Do not close this window." -ForegroundColor Yellow
	
	Add-Type -AssemblyName PresentationCore,PresentationFramework | Out-Null
	
	[void] [System.Reflection.Assembly]::LoadWithPartialName("System.Drawing")
	[void] [System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms")
	
	################# Build GUI ######################
	
	$FontReset = "Microsoft Sans Serif, 8.50"
	$FontCalibri = 'Calibri, 12.50pt'
	$FontMS = 'Microsoft Sans Serif, 11.50pt'
	$FontButtons = 'Calibri, 13.50pt'
	
	Function ShowEvent([bool]$add, [String]$event) {
		$i = $Script:sync.InstIndex
		Invoke-Expression -Command "if(`$add) {`$sync.Log$i.Text += `$event} else {`$sync.Log$i.Text = `$event}"
	}
	
	Function AddHosts($list) {
		$Items = $hosts = $NULL
		[String[]]$Items = $list -split '[,;\s]' -match '\S'
		
		if ($Items) {
			$hosts = $Items | Where-Object { ([System.Uri]::CheckHostName($_) -ne 'Unknown') }
			
			if ($hosts) {
				$hosts | Foreach-Object {[void] $objListBox.Items.Add($_)}
				
				$nItems = ($objListBox.Items | Measure-Object).count
				$objHostCounter.Text = $LabelHosts + $nItems
			}
			else { ShowEvent $true "`r`n`r`n`t Invalid host names. Make yourself familiar with the standards:`r`n`t RFC-1123 page-13 from 1989, which is an update of RFC-952 from 1985.`r`n`t`t https://tools.ietf.org/html/rfc1123#page-13`r`n" }
		}
		$InputBox.Clear()
	}
	
	Function StateForms([bool]$State) {
		$btnAdd2.Enabled = $btnReturn.Enabled = $AddButton.Enabled = $objBrowse.Enabled = $objRemoveItem.Enabled = $ClearCheckList.Enabled = $State
		$objRemoveDuplucate.Enabled = $objCurrentUser.Enabled = $objDomainUser.Enabled = $locateOutFolder.Enabled = $State
		
		$objOptHW.Enabled =	$objOptDevice.Enabled = $objOptOS.Enabled = $objOptLTime.Enabled = $objOptBTime.Enabled = $objOptUTime.Enabled = $objOptHotfix.Enabled =`
		$objHotFixDays.Enabled = $objOptReboot.Enabled = $objOptService.Enabled = $objOptCluster.Enabled = $objOptDisk.Enabled = $objOptSMB.Enabled =`
		$objOptRDP.Enabled = $objSelectQueries.Enabled = $objTimeout.Enabled = $State
		
		$objSendMail.Enabled = $objDontSend.Enabled = $objSaveConfig.Enabled = $optCMD.Enabled = $optPowerShell.Enabled = $optScriptWMI.Enabled = $optScriptInvoke.Enabled = $State
		
		$objOutFolder.ReadOnly = $argScript.ReadOnly = $optAddScript.ReadOnly = (-not $State)
	}
	
	Function ConfigState([bool]$show, [bool]$pass, [string]$message) {
		$LabelErrorCFG.Text = $message
		
		if ($pass) {
			$LabelErrorCFG.BackColor = 'lightgreen'
			$LabelErrorCFG.ForeColor = 'black'
		}
		else {
			$LabelErrorCFG.ForeColor = 'red'
			$LabelErrorCFG.BackColor = 'black'
		}
		
		if ($show) { $LabelErrorCFG.Show() }
		else { $LabelErrorCFG.Hide() }
	}
	
	Function GetKey() {
		$popupForm = New-Object System.Windows.Forms.Form
		$popupForm.Size = New-Object System.Drawing.Size(270,200)
		$popupForm.FormBorderStyle = 'Fixed3D'
		$popupForm.StartPosition = "CenterScreen"
		$popupForm.KeyPreview = $True
		$popupForm.MaximizeBox = $true
		$popupForm.Font = $FontMS
		$popupForm.Text = "AES 256 Encryption"
		$popupForm.Topmost = $False
		$popupForm.Add_Shown({$popupForm.Activate()})
		
		$popupLabel = New-Object System.Windows.Forms.Label
		$popupLabel.Location = New-Object System.Drawing.Size(10,10)
		$popupLabel.Size = New-Object System.Drawing.Size(225,25)
		#$popupLabel.BackColor = 'red'
		$popupLabel.Text = "Type encryption key [AES256]:"
		$popupForm.Controls.Add($popupLabel)
		
		$popupKey = New-Object System.Windows.Forms.TextBox
		$popupKey.Location = New-Object System.Drawing.Point(($popupLabel.Location.X), ($popupLabel.Location.Y + 30))
		$popupKey.Size = $popupLabel.Size
		$popupKey.PasswordChar = '*'
		$popupKey.Font = $FontCalibri
		$popupKey.MaxLength = 32
		$popupForm.Controls.Add($popupKey)
		
		$popupShowPass = New-Object System.Windows.Forms.checkbox
		$popupShowPass.Location = New-Object System.Drawing.Point(($popupKey.Location.X + 10), ($popupKey.Location.Y + 35))
		$popupShowPass.Size = $MailShowPass.Size
		$popupShowPass.Text = "Show key"
		$popupShowPass.Checked = $false
		$popupForm.Controls.Add($popupShowPass)
		
		$popupShowPass.Add_CheckStateChanged({
			if ($popupShowPass.Checked) { $popupKey.PasswordChar = 0 }
			else { $popupKey.PasswordChar = '*' }
		})
		
		$popupCancel = New-Object System.Windows.Forms.Button
		$popupCancel.Location = New-Object System.Drawing.Point(($popupShowPass.Location.X + 10), ($popupShowPass.Location.Y + 40))
		$popupCancel.Size = New-Object System.Drawing.Size(70,30)
		$popupCancel.Text = "Cancel"
		$popupCancel.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
		$popupForm.CancelButton = $popupCancel
		$popupForm.Controls.Add($popupCancel)
		
		$popupOK = New-Object System.Windows.Forms.Button
		$popupOK.Location = New-Object System.Drawing.Size(150,($popupCancel.Location.Y))
		$popupOK.Size = $popupCancel.Size
		$popupOK.Text = "OK"
		$popupOK.DialogResult = [System.Windows.Forms.DialogResult]::OK
		$popupForm.AcceptButton = $popupOK
		$popupForm.Controls.Add($popupOK)
		
		$popupForm.Add_Shown({$popupKey.Select()})
		$AcceptKey = $popupForm.ShowDialog()
		
		if ($AcceptKey -eq [System.Windows.Forms.DialogResult]::OK) {
			return ($popupKey.Text)
		}
		else { return $null }
	}
	
	$Resize = {
		if ($TabMenu.SelectedTab.Name -eq 'TabGeneral') {
			$TabGeneralSize = New-Object System.Drawing.Size(($objForm.Size.Width), [int]($objForm.Size.Height * 0.60))
			$TabMenu.Size = $TabGeneralSize
			
			$ControlInstances.Show()
			$ControlInstances.Location = New-Object System.Drawing.Point(1, ($TabGeneralSize.Height + 11))
			$ControlInstances.Size = New-Object System.Drawing.Size(($objForm.Size.Width), ($objForm.Size.Height - $TabGeneralSize.Height - 50))
			
			$InstLogSize = New-Object System.Drawing.Size(($ControlInstances.Size.Width - 35), ($ControlInstances.Size.Height - 30))
			
			for ($i = 0; $i -lt $CpuCores; $i++) {
				$InstLog[$i].Size = $InstLogSize
			}
			
			if ($objForm.Size.Width -ge 1900) {
				$InputBox.Size = New-Object System.Drawing.Size(([int]($TabGeneralSize.Width * 0.30)), ($TabGeneralSize.Height - 95))
			}
			else {
				$InputBox.Size = New-Object System.Drawing.Size(([int]($TabGeneralSize.Width * 0.30)), ($TabGeneralSize.Height - 135))
			}
			
			$btnAdd2.Location = New-Object System.Drawing.Point(($InputBox.Location.X + $InputBox.Size.Width + 10), ($InputBox.Location.Y + $InputBox.Size.Height / 2 - 60))
			
			$btnReturn.Location = New-Object System.Drawing.Point(($InputBox.Location.X + $InputBox.Size.Width + 10), ($InputBox.Location.Y + $InputBox.Size.Height / 2 + 20))
			
			$objListBox.Location = New-Object System.Drawing.Size(($InputBox.Location.X + $InputBox.Size.Width + 50), ($InputBox.Location.Y))
			$objListBox.Size = $InputBox.Size
			$objHostCounter.Location = New-Object System.Drawing.Size(($objListBox.Location.X + 15), ($objInputTitle.Location.Y))
			
			$ClearInputList.Location = New-Object System.Drawing.Point(($InputBox.Location.X + $InputBox.Size.Width / 2 - 110), ($InputBox.Location.Y + $InputBox.Size.Height + 10))
			
			$AddButton.Location = New-Object System.Drawing.Point(($InputBox.Location.X + $InputBox.Size.Width / 2), ($ClearInputList.Location.Y))
			
			if ($objForm.Size.Width -ge 1900) {
				$ClearCheckList.Location = New-Object System.Drawing.Point(($objListBox.Location.X + $objListBox.Size.Width / 2 - 285), ($ClearInputList.Location.Y))
				$objBrowse.Location = New-Object System.Drawing.Point(($ClearCheckList.Location.X + 110), ($ClearInputList.Location.Y))
				$objRemoveItem.Location = New-Object System.Drawing.Point(($objBrowse.Location.X + 120), ($ClearInputList.Location.Y))
				$objRemoveDuplucate.Location = New-Object System.Drawing.Point(($objRemoveItem.Location.X + 180), ($ClearInputList.Location.Y))
			}
			else {
				$objBrowse.Location = New-Object System.Drawing.Point(($objListBox.Location.X + $objListBox.Size.Width / 2 - 135), ($ClearInputList.Location.Y))
				$objRemoveItem.Location = New-Object System.Drawing.Point(($objBrowse.Location.X + 120), ($ClearInputList.Location.Y))
				$ClearCheckList.Location = New-Object System.Drawing.Point(($objBrowse.Location.X), ($objBrowse.Location.Y + 40))
				$objRemoveDuplucate.Location = New-Object System.Drawing.Point(($objRemoveItem.Location.X - 10), ($ClearCheckList.Location.Y))
			}
			
			$objCurrentUser.Location = New-Object System.Drawing.Size(($objListBox.Location.X + $objListBox.Size.Width + 20), 5)
			
			$objDomainUser.Location = New-Object System.Drawing.Size(($objCurrentUser.Location.X), ($objCurrentUser.Location.Y + 50))
			
			$objNoCredsVerify.Location = New-Object System.Drawing.Size(($objCurrentUser.Location.X + 30), ($objDomainUser.Location.Y + 25))
			
			$objLabel.Location = New-Object System.Drawing.Size(($objCurrentUser.Location.X), ($objDomainUser.Location.Y + 55))
			
			$objUsername.Location = New-Object System.Drawing.Point(($objCurrentUser.Location.X + 95), ($objLabel.Location.Y - 4))
			$objUsername.Size = New-Object System.Drawing.Point(($objForm.Size.Width - $objUsername.Location.X - 40), ($objUsername.Size.Height))
			
			$objPassword.Location = New-Object System.Drawing.Point(($objUsername.Location.X), ($objUsername.Location.Y + 35))
			$objPassword.Size = New-Object System.Drawing.Point(($objUsername.Size.Width), ($objUsername.Size.Height))
			
			$objShowPassword.Location = New-Object System.Drawing.Size(($objPassword.Location.X + 20), ($objPassword.Location.Y + 30))
			
			$objOutFolder.Location = New-Object System.Drawing.Size(($objCurrentUser.Location.X), ($objLabel.Location.Y + $objLabel.Size.Height + 2))
			$objOutFolder.Size = New-Object System.Drawing.Size(($objForm.Size.Width - $objOutFolder.Location.X - 75), ($objOutFolder.Size.Height))
			
			$locateOutFolder.Location = New-Object System.Drawing.Size(($objOutFolder.Location.X + $objOutFolder.Size.Width + 5), ($objOutFolder.Location.Y))
			
			$objLinkFolder.Location = New-Object System.Drawing.Size(($objOutFolder.Location.X), ($objOutFolder.Location.Y + 50))
			$objLinkFolder.MaximumSize = New-Object System.Drawing.Size(($TabGeneralSize.Width - $objOutFolder.Location.X - 30), ($objRemoveItem.Location.Y - $objLinkFolder.Location.Y))
			
			$StopButton.Location = New-Object System.Drawing.Point(($objCurrentUser.Location.X + 50), ($objRemoveDuplucate.Location.Y - 10))
			
			$RunButton.Location = New-Object System.Drawing.Size(($StopButton.Location.X + 130), ($StopButton.Location.Y))
		}
		else {
			$ControlInstances.Hide()
			$TabMenu.Size = New-Object System.Drawing.Size(($objForm.Size.Width), ($objForm.Size.Height - 40))
			
			if ($TabMenu.SelectedTab.Name -eq "TabOptions") {
				$optAddScript.Location = New-Object System.Drawing.Size(($GroupRemote.Location.X), ($GroupConfig.Location.Y + $GroupConfig.Size.Height + 10))
				$optAddScript.Size = New-Object System.Drawing.Size(($objForm.Size.Width - 35), ($TabMenu.Size.Height - $optAddScript.Location.Y - 32))
				
				$GroupConfig.Size = New-Object System.Drawing.Size(($objForm.Size.Width - $GroupConfig.Location.X - 35), ($GroupConfig.Size.Height))
				$objLoadConfig.Width = $GroupConfig.Size.Width - 240
				
				$objLoadConfig.DropDownHeight = $objForm.Size.Height - $GroupConfig.Location.Y - 150
			}
			elseif ($TabMenu.SelectedTab.Name -eq "TabSupport") {
				$objTerms.Size = New-Object System.Drawing.Size(($objForm.Size.Width - 35), ($TabMenu.Size.Height / 2.8))
				
				$objHLine.Location = New-Object System.Drawing.Size(5, ($objTerms.Location.Y + $objTerms.Size.Height + 25))
				$objHLine.Size = New-Object System.Drawing.Size(($objTerms.Size.Width), 2)
				
				$objUpdateCheck.Location = New-Object System.Drawing.Point(20, ($objHLine.Location.Y + $objHLine.Size.Height + 20))
				
				$objUpdateFix.Location = New-Object System.Drawing.Point(($objUpdateCheck.Location.X + 235), ($objUpdateCheck.Location.Y))
				
				$objUpdateLog.Location = New-Object System.Drawing.Size(5, ($objUpdateCheck.Location.Y + $objUpdateCheck.Size.Height + 20))
				$objUpdateLog.Size = New-Object System.Drawing.Size(($objTerms.Size.Width), ($TabMenu.Size.Height - $objUpdateLog.Location.Y - 35))
	
			}
			else {}
		}
	}
	
	# http://www.iconarchive.com/show/nuoveXT-2-icons-by-saki/Apps-utilities-system-monitor-icon.html
	# http://www.iconarchive.com/show/fs-icons-by-franksouza183/Apps-scan-monitor-icon.html
	# http://www.iconarchive.com/show/network-icons-by-devcom/satellite-Vista-icon.html
	
	$objFormIcon = "iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAYAAABzenr0AAAIaUlEQVR42s1Xe3BU5RX/3b17970hgWYEZaR2nDaQFgSaPgwqibbQQu04tuNjOgx/tNZhVLQmMLF1nM7UJBCLGUeGyLNRQkN4EyKYaewDqiQEEKWCtBYDYZNsNpvse+/u3nt7znd3lyXT2sc/9mZOz"
	$objFormIcon += "ne//e53zvmd1/dJ+Iwf6f9GgQ0bNshiQvoUnQwDxuQZwyh8Qe5d8Ovrr6/LztXV1YkJacf2Hcojjz5yJJVKLbZYLBI/xJHlBitElOeGrhs6baIz1/UcF2Paw2DKZDLQNM0gMiUbyP4zsiMYVqs14LDbfyj19PQsnDt3bn86nQZNQpZlsALMC8dZpVggb57nTFmBiE"
	$objFormIcon += "ajrIR45/147tOe6dOnr2cFvj5v3ryT/EHWyrwbCt1hmFbnBfL6QlJVFbFYTCiQI57ntYV7Fcr4wm23/VrqPvbW10KXRnpHB4ahWBVBNpsdVossxhLMxekMWaRrtKlpbUbLIJlKQE2piKtxTMSCiCdjtC6DhJpAipWi35KpJClhrmcjNOY6BH/8Z6tfko69ebTiYve"
	$objFormIcon += "ZvqFLg6ZQWYHT4RLB4nK4odNCm2KnzZLkBllsbHM4cPuC2eh9+zhSGRWBiB/RZBiRRFQoHElGBVpqJoUEfQdDQkpTaX8FGT2d508/t/Yl6WjXmxUfHuvvu3rxMmxWmyBFZq7AKlNMkFABnxk/NLbg1rLbsfjRpdjyXDNZPobh0CApQP4ngSlCyqSUQC031kihyc/q"
	$objFormIcon += "ujVNUldn11fPH+09NfLxEGTanBFwOd0wNB0el5fgSwtEkgQrI6FrBuZ8cz4hUIbunZ3w+Qbwif8SaWZBOB6CRbIinAiB5bHgeCoOCmNE1Shssl0gYbPYkNJTeGptbZN05HDnwnNd7/YPfjRQgIAZC8wZAQttThAI6630ccWSRVAoTi5f/CtO9R7HWHREQJ23WksXW"
	$objFormIcon += "G8Sv0+uIk+sebZJ6jx4eOHpwyf6/ZeHSZhFwO5m35MJHqcHmbSJAMeA0+4SAXTn9+5FNBBBQovhRM/v4J/wsW8QjoUoZRWBBLvLRCBByDIqYSikvKolCQlCQEthVc0zTdKh/QcX9B384+lrf7tiWs9ZILP/meQ8AhwHsiTTGgfuXF4NVrhoVhGOtHUglBgnBBJkJS"
	$objFormIcon += "FAQSssJp5DIa2ZnLOo8KEsWC8d2Lt//rv7e86MDowIQQIBOyOgwe30ik1dhEAqrcJl94iIrlxWjcELVzD723PQ0dwqEDAYgfgEuc1O2RBmhwkFEjkEKEuYJygmGAGVYuGx1U+ul/Z17L3j+J63zvr+Ppi13kSBFREkEDArodViJQTs+MaSe3D+nbN4YM3DeLVmPQm"
	$objFormIcon += "cEMHGAavlChYR5z4jkRGopJBMJ7MZkQEVb/z4yVXrpD3tHXf8vr3r7PDAEGlvFYHnUBxCoJ041y+OfnYqc3ZDRXUlTvb8Cas31qF5VQNiZB0HHqPEMUCtwSw6XLiyBYgtZuvHwgGoQhEVK1f9dJ20e1f7vO62Q+/5rwwLi22KDSVTpsLpcgqu2GzweLyQrTLcbg+c"
	$objFormIcon += "Hic+vnAJI4PX8NiLT2NaaSlZraG/uxd/7vwDnm35OTwlRTeUcR4rNoI/nsCDi76DwJgf8XQMD634UaP0251tc7ta950bvuIzXSDSz5ZPQ4adgzHnBt42TEHHKemkWJniLcb0W2bioZoVOPzKPqys/wk21b5CLomJ+GHlGAnZbsV4KIgz/X2IUU1IUxYsf/CBRqnt9"
	$objFormIcon += "Te+cmh7+/tjvkDez6IEk588DipEBC2/pwleB6Uhl1w1HRfKcVue6imF0+bGr/a+jM7mA6hacR9+ubIOoXiQBMWQSCdglRQqz2Fx/EhqcVHo/GMjWPr9ZQ3SG79p/fKBbbs+GLp6jVLODDwlH4BmKWbFBNEG0WRIBBDDyr3BRcKneW5CfUczTh85hVnzP4/6J57HSM"
	$objFormIcon += "hHayMiADkgOSMyhITL7UYRuYjlVX93SYPUum1H+b6tO8+P+4NQ7DaCWiKLXCJS3ZR2aQoWNxUkDhw9rWM8Fsgrx+iUEAIeexFe2NqI0BAVIIuBdWteyDYosz/MuHkmfENXIelkhE1GKcXNwMAnuPtbVfXSji3byvdsef18YNgPh9MpfCusJc6VkfuDTAJZsYlwUNQ"
	$objFormIcon += "H/p0f5g6rE6VFM1DT9Dxm3HozPug9h5bGl6lB+URqcncsveUmjI8GISsy9IwOd7EHw4NDqKy6u17a9trmObs3t/4lEgzDW1zEJR92ynW2mJHgHu+g6scpJMsWarGqcAXXA26pbsVLzcWOx9c+g6of3IcDG/egdctr4nzAec8BOHPWLARGRyljPoex0QCKS4oFApVV"
	$objFormIcon += "d9VLmze1zG5v2f7heCCYRSB7IiroG2x9JErVjXyfO5qJGBDd04YprhIsvf9+PFVfg1+srMHJkycoUyZgdzrEyaikdCqi4xF4pxUhMhaGs8hFCPhQWU0ItLy6sWzXpq0XwsFQXib7l9Pn+gHCSu00InoFu4ADkwNWpzUOxSnG07ylmL2gHO/3vYdgNCDSzOV1I5FIw"
	$objFormIcon += "OslwZEwioiHibtdbqoFo1hUvVgg8KV3ut++GI/GxCE913R0UocF5RoIBxNbzFFtHhJh5rdkruFOJ45dVAXjlH65gyvPcf6I7+mPs4G/5RpReQ8h0NbWVlZRUXGBFxdWrxzU/Ew+3ebO/9lj+Q33gfydoID/qzlybaPU2NDwxWXLl3/EQiZfSvg9J+ifKTBZ8H/7UI"
	$objFormIcon += "V9USorK1Nqa2t3l5eX30W3C9nI3pZoY8G1TEbKqWNeKQxJKHXjzSd3xeJjU15PKfcZj8155gZfeNSkOur3+x/OrbbTJDV7OIj4iiaTEOaW7LulgKQCfgMwRHoBz5FWwDVSgClJl50oZYj6n15O/9dL7L/1z2d+O/4HtH0eY5OJOXIAAAAASUVORK5CYII="
	
	$objIconBytes = [Convert]::FromBase64String($objFormIcon)
	$objIconStream = New-Object IO.MemoryStream($objIconBytes, 0, $objIconBytes.Length)
	$objIconStream.Write($objIconBytes, 0, $objIconBytes.Length);
	$objIconImage = [System.Drawing.Image]::FromStream($objIconStream, $true)
	
	$objIcon = [System.Drawing.Icon]::FromHandle(($objIconImage.GetHicon()))
	
	$objForm = New-Object System.Windows.Forms.Form
	$objForm.Size = New-Object System.Drawing.Size(960, 756)
	$objForm.MinimumSize = New-Object System.Drawing.Size(960, 756)
	$objForm.Icon = $objIcon
	$objForm.StartPosition = "CenterScreen"
	$objForm.KeyPreview = $True
	$objForm.MaximizeBox = $true
	$objForm.Text = "System Information and Remote Execution   |   v1.09 Stable   |   Copyright PS-Solutions.net"
	$objForm.Add_Closing({Write-Host "`r`n`t Closing the script...`r`n" -ForegroundColor Yellow})
	$objForm.Add_SizeChanged($Resize)
	
	$objForm.Add_KeyDown({
		if ($btnAdd2.Enabled) {
			if ($_.KeyCode -eq [System.Windows.Forms.Keys]::Delete){
				$nItems = $objListBox.SelectedItems.Count
				for ($i=0; $i -lt $nItems; $i++) {
					$objListBox.Items.Remove($objListBox.SelectedItems[0])
				}
				$objHostCounter.Text = $LabelHosts + ($objListBox.Items | Measure-Object).count
			}
		}
	})
	
	#### Build Tabs on the top ####
	
	$TabMenu = New-Object System.Windows.Forms.TabControl
	$TabMenu.DataBindings.DefaultDataSourceUpdateMode = 0
	$TabMenu.Location = New-Object System.Drawing.Point(1,1)
	$TabMenu.Font = 'Microsoft Sans Serif, 10.00pt'
	$TabMenu.Name = "TabMenu"
	$TabMenu.SelectedIndex = 0
	$TabMenu.Add_SelectedIndexChanged($Resize)
	$objForm.Controls.Add($TabMenu)
	
	$TabGeneral = New-Object System.Windows.Forms.TabPage
	$TabGeneral.DataBindings.DefaultDataSourceUpdateMode = 0
	$TabGeneral.Font = $FontReset
	$TabGeneral.UseVisualStyleBackColor = $True
	$TabGeneral.Name = "TabGeneral"
	$TabGeneral.Text = "General"
	$TabMenu.Controls.Add($TabGeneral)
	
	#### Build input box and list box. ####
	
	$InputBox = New-Object System.Windows.Forms.RichTextBox
	$InputBox.Location = New-Object System.Drawing.Size(5,25)
	$InputBox.Size = New-Object System.Drawing.Size(250,345)
	$InputBox.Font = $FontCalibri
	$InputBox.AcceptsTab = $true
	$InputBox.Multiline = $true
	$InputBox.ScrollBars = 'Both'
	$InputBox.Wordwrap = $False
	$TabGeneral.Controls.Add($InputBox)
	
	$objInputTitle = New-Object System.Windows.Forms.Label
	$objInputTitle.Location = New-Object System.Drawing.Size(($InputBox.Location.X + 15), ($InputBox.Location.Y - 20))
	$objInputTitle.Size = New-Object System.Drawing.Size(250,20)
	$objInputTitle.Font = $FontMS
	#$objInputTitle.BackColor = 'red'
	$objInputTitle.Text = "Input Box  |  Type hostnames here"
	$TabGeneral.Controls.Add($objInputTitle)
	
	$btnAdd2 = New-Object System.Windows.Forms.Button
	$btnAdd2.Size = New-Object System.Drawing.Size(30,30)
	$btnAdd2.Font = 'Calibri, 25.00pt, style=Bold'
	$btnAdd2.ForeColor = 'green'
	$btnAdd2.Text = ">"
	$TabGeneral.Controls.Add($btnAdd2)
	$btnAdd2.Add_Click({
		AddHosts ($InputBox.Text)
	})
	
	$btnReturn = New-Object System.Windows.Forms.Button
	$btnReturn.Size = $btnAdd2.Size
	$btnReturn.Font = $btnAdd2.Font
	$btnReturn.ForeColor = 'red'
	$btnReturn.Text = "<"
	$btnReturn.Add_Click({
		[int]$n = $objListBox.SelectedItems.Count
		for ($i=0; $i -lt $n; $i++) {
			$InputBox.Text += "`r`n" + $objListBox.SelectedItems[0]
			$objListBox.Items.Remove($objListBox.SelectedItems[0])
		}
		
		if ($n) {
			$NewItems = ($objListBox.Items | Measure-Object).count
			$objHostCounter.Text = $LabelHosts + $NewItems
		}
	})
	$TabGeneral.Controls.Add($btnReturn)
	
	$objListBox = New-Object System.Windows.Forms.ListBox
	$objListBox.Font = $FontCalibri
	$objListBox.SelectionMode = "MultiExtended"
	$objListBox.ScrollAlwaysVisible = $True
	$objListBox.HorizontalScrollbar = $True
	$TabGeneral.Controls.Add($objListBox)
	
	$LabelHosts = "Check List  |  Total hosts added: "
	
	$objHostCounter = New-Object System.Windows.Forms.Label
	$objHostCounter.Size = New-Object System.Drawing.Size(280,20)
	$objHostCounter.Font = $FontMS
	#$objHostCounter.BackColor = 'red'
	$objHostCounter.Text = $LabelHosts + ($objListBox.Items | Measure-Object).count
	$TabGeneral.Controls.Add($objHostCounter)
	
	#### Build buttons ####
	
	$ClearInputList= New-Object System.Windows.Forms.Button
	$ClearInputList.Size = New-Object System.Drawing.Size(80,25)
	$ClearInputList.Font = $FontButtons
	$ClearInputList.Text = "Clear"
	$ClearInputList.Add_Click({	$InputBox.Clear() })
	$TabGeneral.Controls.Add($ClearInputList)
	
	$AddButton = New-Object System.Windows.Forms.Button
	$AddButton.Size = New-Object System.Drawing.Size(100,25)
	$AddButton.Font = $FontButtons
	$AddButton.Text = "Add Items"
	$AddButton.Add_Click({
		AddHosts ($InputBox.Text)
	})
	$TabGeneral.Controls.Add($AddButton)
	
	$objBrowse = New-Object System.Windows.Forms.Button
	$objBrowse.Size = New-Object System.Drawing.Size(90,25)
	$objBrowse.Font = $FontButtons
	$objBrowse.Text = "Browse..."
	$objBrowse.Add_Click({
		$OpenFileDialog = New-Object 'Microsoft.Win32.OpenFileDialog'
		$OpenFileDialog.initialDirectory = $ScriptPath
		$OpenFileDialog.filter = "All files (*.*)| *.*"
		$OpenFileDialog.ShowDialog() | Out-Null
		
		if ($OpenFileDialog.filename) {
			$list = [System.IO.File]::ReadAllLines($OpenFileDialog.filename, [System.Text.Encoding]::UTF8) | Out-String
			AddHosts $list
		}
	})
	$TabGeneral.Controls.Add($objBrowse)
	
	$objRemoveItem = New-Object System.Windows.Forms.Button
	$objRemoveItem.Size = New-Object System.Drawing.Size(150,25)
	$objRemoveItem.Font = $FontButtons
	$objRemoveItem.Text = "Remove-Selected"
	$objRemoveItem.Add_Click({
		[int]$nItems = $objListBox.SelectedItems.Count
		for ($i=0; $i -lt $nItems; $i++) {
			$objListBox.Items.Remove($objListBox.SelectedItems[0])
		}
		
		if ($nItems) {
			$NewItems = ($objListBox.Items | Measure-Object).count
			$objHostCounter.Text = $LabelHosts + $NewItems
		}
	})
	$TabGeneral.Controls.Add($objRemoveItem)
	
	$ClearCheckList = New-Object System.Windows.Forms.Button
	$ClearCheckList.Size = $ClearInputList.Size
	$ClearCheckList.Font = $FontButtons
	$ClearCheckList.Text = $ClearInputList.Text
	$TabGeneral.Controls.Add($ClearCheckList)
	$ClearCheckList.Add_Click({
		$objListBox.Items.Clear()
		$objHostCounter.Text = $LabelHosts + 0
	})
	
	$objRemoveDuplucate = New-Object System.Windows.Forms.Button
	$objRemoveDuplucate.Size = New-Object System.Drawing.Size(160,25)
	$objRemoveDuplucate.Font = $FontButtons
	$objRemoveDuplucate.Text = "Remove-Duplicates"
	$TabGeneral.Controls.Add($objRemoveDuplucate)
	$objRemoveDuplucate.Add_Click({
		if ($objListBox.Items) {
			[Array]$Items = $objListBox.Items | Sort-Object -Unique
			$objListBox.Items.Clear()
			$Items | Foreach-Object {[void] $objListBox.Items.Add($_)}
			$objHostCounter.Text = $LabelHosts + ($objListBox.Items | Measure-Object).count
		}
	})
	
	$StopButton = New-Object System.Windows.Forms.Button
	$StopButton.Size = New-Object System.Drawing.Size(70,35)
	$StopButton.Font = 'Courier New, 16.00pt, style=Bold'
	$StopButton.ForeColor = 'red'
	$StopButton.Text = "Stop"
	$StopButton.Enabled = $false
	$StopButton.Add_Click({
		$StopButton.Enabled = $false
		$i = $sync.InstIndex
		Invoke-Expression -Command "`$sync.StopInst$i = `$true; ShowEvent `$TRUE ""``r``n``t Kill switch is sent.""; `$sync.BtnStopInst$i = `$false"
	})
	$TabGeneral.Controls.Add($StopButton)
	
	$sync.StopButton = $StopButton
	
	$RunButton = New-Object System.Windows.Forms.Button
	$RunButton.Size = $StopButton.Size
	$RunButton.Font = $StopButton.Font
	$RunButton.ForeColor = 'Green'
	$RunButton.Text = "Run"
	$TabGeneral.Controls.Add($RunButton)
	
	$sync.RunButton = $RunButton
	
	$TabGeneral.Controls.AddRange(@($sync.RunButton, $sync.StopButton))
	$sync.BtnStopInst1 = $sync.BtnStopInst2 = $sync.BtnStopInst3 = $sync.BtnStopInst4 = $sync.BtnStopInst5 = $sync.BtnStopInst6 = $sync.BtnStopInst7 = $sync.BtnStopInst8 = $false
	$sync.BtnRunInst1 = $sync.BtnRunInst2 = $sync.BtnRunInst3 = $sync.BtnRunInst4 = $sync.BtnRunInst5 = $sync.BtnRunInst6 = $sync.BtnRunInst7 = $sync.BtnRunInst8 = $true
	$sync.StopInst1 = $sync.StopInst2 = $sync.StopInst3 = $sync.StopInst4 = $sync.StopInst5 = $sync.StopInst6 = $sync.StopInst7 = $sync.StopInst8 = $false
	
	#### Create tooltips. Show buttons popup help. ####
	
	$objTooltip= New-Object System.Windows.Forms.Tooltip
	$objTooltip.AutomaticDelay = 1
	$objTooltip.AutoPopDelay = 12000
	$objTooltip.SetToolTip($btnAdd2, "Add Computers to check list")
	$objTooltip.SetToolTip($btnReturn, "Return selected items")
	$objTooltip.SetToolTip($ClearInputList, "Clear input list above")
	$objTooltip.SetToolTip($AddButton, "Add Computers to check list")
	$objTooltip.SetToolTip($objBrowse, "Browse from text file")
	$objTooltip.SetToolTip($objRemoveItem, "Remove selected entries")
	$objTooltip.SetToolTip($ClearCheckList, "Clear added entries")
	$objTooltip.SetToolTip($objRemoveDuplucate, "Remove duplicate entries and sort")
	
	#### Build Radio buttons ####
	
	$objCurrentUser = New-Object System.Windows.Forms.RadioButton
	$objCurrentUser.Size = New-Object System.Drawing.Size(500,40)
	$objCurrentUser.Font = $FontMS
	$objCurrentUser.Checked = $true
	$objCurrentUser.text = "Use current session credentials:`r`n" + $env:USERDOMAIN + "\" + $env:USERNAME
	$TabGeneral.controls.Add($objCurrentUser)
	
	$objDomainUser = New-Object System.Windows.Forms.RadioButton
	$objDomainUser.Size = New-Object System.Drawing.Size(240,20)
	$objDomainUser.Font = $FontMS
	$objDomainUser.text = "Domain or local(.\) credentials"
	$TabGeneral.controls.Add($objDomainUser)
	
	$objDomainUser.Add_CheckedChanged({
		if ($objDomainUser.Enabled) {
			if ($objDomainUser.Checked) {
				$objNoCredsVerify.Enabled = $objUsername.Enabled = $objPassword.Enabled = $objShowPassword.Enabled = $true
			}
			else {
				$objNoCredsVerify.Enabled = $objNoCredsVerify.Checked = $objUsername.Enabled = $objPassword.Enabled = $objShowPassword.Enabled = $objShowPassword.Checked = $false
			}
			
			$objUsername.ReadOnly = $objPassword.ReadOnly = $false
		}
		else {
			$objUsername.ReadOnly = $objPassword.ReadOnly = $true
			$objNoCredsVerify.Enabled = $objShowPassword.Enabled = $objShowPassword.Checked = $false
		}
	})
	
	$objDomainUser.Add_EnabledChanged({
		if ($objDomainUser.Enabled) {
			if ($objDomainUser.Checked) {
				$objNoCredsVerify.Enabled = $objUsername.Enabled = $objPassword.Enabled = $objShowPassword.Enabled = $true
			}
			else {
				$objNoCredsVerify.Enabled = $objUsername.Enabled = $objPassword.Enabled = $objShowPassword.Enabled = $objShowPassword.Checked = $false
			}
			
			$objUsername.ReadOnly = $objPassword.ReadOnly = $false
		}
		else {
			$objUsername.ReadOnly = $objPassword.ReadOnly = $true
			$objNoCredsVerify.Enabled = $objShowPassword.Enabled = $objShowPassword.Checked = $false
		}
	})
	
	#### Check box do not verify domain credentials. ####
	
	$objNoCredsVerify = New-Object System.Windows.Forms.checkbox
	$objNoCredsVerify.Size = New-Object System.Drawing.Size(235,20)
	$objNoCredsVerify.Font = 'Calibri, 11.50pt'
	$objNoCredsVerify.Text = "Do not verify domain credentials"
	$objNoCredsVerify.Checked = $false
	$objNoCredsVerify.Enabled = $false
	$TabGeneral.Controls.Add($objNoCredsVerify)
	
	$objNoCredsVerify.Add_Click({
		if ($objNoCredsVerify.Checked) {
			$objNoCredsVerify.Checked = $false
			
			$ShowWarning = [System.Windows.MessageBoxButton]::YesNo
			$ShowWarningIcon = [System.Windows.MessageBoxImage]::Warning
			$ShowWarningTitle = "Confirm Selection"
			$ShowWarningBody = "This option bypass credentials verification. Use it only if LDAP is blocked on port 636 or when domain name can't be resolved by NetBIOS .`r`n`r`n"
			$ShowWarningBody += "If wrong password is filled in the account will be locked out.`r`n`r`n" 
			$ShowWarningBody += "By enabling this option you must be 100% sure that provided password is correct!"
			
			$ShowWarningResult = [System.Windows.MessageBox]::Show($ShowWarningBody,$ShowWarningTitle,$ShowWarning,$ShowWarningIcon)
			
			if ($ShowWarningResult -eq 'YES') {
				$objNoCredsVerify.Checked = $true
			}
		}
	})
	
	#### Label and text to input credentials. ####
	
	$objUsername = New-Object System.Windows.Forms.TextBox
	$objUsername.Size = New-Object System.Drawing.Size(160,20)
	$objUsername.Font = $FontCalibri
	$objUsername.Enabled = $false
	$TabGeneral.Controls.Add($objUsername)
	
	$objPassword = New-Object System.Windows.Forms.TextBox
	$objPassword.Size = $objUsername.Size
	$objPassword.Font = $FontCalibri
	$objPassword.PasswordChar = '*'
	$TabGeneral.Controls.Add($objPassword)
	$objPassword.Enabled = $false
	
	#### Check box show domain/local password. ####
	
	$objShowPassword = New-Object System.Windows.Forms.checkbox
	$objShowPassword.Size = New-Object System.Drawing.Size(125,20)
	$objShowPassword.Font = 'Calibri, 11.50pt'
	$objShowPassword.Text = "Show password"
	$objShowPassword.Checked = $false
	$objShowPassword.Enabled = $false
	$TabGeneral.Controls.Add($objShowPassword)
	
	$objShowPassword.Add_CheckStateChanged({
		if ($objShowPassword.Checked) { $objPassword.PasswordChar = 0 }
		else { $objPassword.PasswordChar = '*' }
	})
	
	$locateOutFolder = New-Object System.Windows.Forms.Button
	$locateOutFolder.Size = New-Object System.Drawing.Size(30,25)
	$locateOutFolder.Font = $FontButtons
	$locateOutFolder.Text = "..."
	$locateOutFolder.Add_Click({
		$OpenFileDialog = New-Object System.Windows.Forms.FolderBrowserDialog
		$OpenFileDialog.RootFolder = "MyComputer"
		$OpenFileDialog.SelectedPath = $ScriptPath
		
		if ($OpenFileDialog.ShowDialog() -eq "OK") {
			$objOutFolder.Text = $OpenFileDialog.SelectedPath
		}
	})
	$TabGeneral.Controls.Add($locateOutFolder)
	
	$objOutFolder = New-Object System.Windows.Forms.TextBox
	$objOutFolder.Size = New-Object System.Drawing.Size(220,20)
	$objOutFolder.Font = $FontCalibri
	$objOutFolder.Text = "Report"
	$TabGeneral.Controls.Add($objOutFolder)
	
	$objOutFolder.Add_GotFocus({
		if ($objOutFolder.Text -eq "<current script's folder>") { $objOutFolder.Text = '' }
	})
	
	$objOutFolder.Add_LostFocus({
		$objOutFolder.Text = $objOutFolder.Text.Trim()
		if (-not $objOutFolder.Text) { $objOutFolder.Text = "<current script's folder>" }
	})
	
	$objLinkFolder = New-Object System.Windows.Forms.LinkLabel
	$objLinkFolder.Location = New-Object System.Drawing.Size(645,275)
	$objLinkFolder.AutoSize = $true
	$objLinkFolder.Font = $FontMS
	#$objLinkFolder.BackColor = 'yellow'
	$objLinkFolder.LinkColor = 'blue'
	$objLinkFolder.ActiveLinkColor = 'red'
	$objLinkFolder.Hide()
	$TabGeneral.Controls.Add($objLinkFolder)
	
	$sync.OutFile = $objLinkFolder
	$objLinkFolder.Add_Click({[System.Diagnostics.Process]::Start($sync.OutFile.Text)})
	
	$objLabel = New-Object System.Windows.Forms.Label
	$objLabel.Size = New-Object System.Drawing.Size(300,125)
	$objLabel.Font = $FontMS
	#$objLabel.BackColor = 'red'
	$objLabel.Text = "domain\user:`r`n`r`n    Password:`r`n`r`n`r`n`r`nSet output folder of generated report."
	$TabGeneral.Controls.Add($objLabel)
	
	#### Create up to 8 instance tabs on the bottom with loops ####
	
	$ControlInstances = New-Object System.Windows.Forms.TabControl
	$ControlInstances.DataBindings.DefaultDataSourceUpdateMode = 0
	$ControlInstances.Name = "TabInstances"
	$ControlInstances.Font = "Lucida Console, 10.00pt"
	$objForm.Controls.Add($ControlInstances)
	
	$ControlInstances.SelectedIndex = 0
	$sync.InstIndex = 1
	
	$ControlInstances.Add_SelectedIndexChanged({
		$i = $sync.InstIndex = $ControlInstances.SelectedIndex + 1
		Invoke-Expression -Command "`$RunButton.Enabled = `$sync.BtnRunInst$i; `$StopButton.Enabled = `$sync.BtnStopInst$i"
		Invoke-Expression -Command "`$sync.OutFile.Text = `$sync.LinkFile$i"
	})
	
	$RichTextBoxDefault = @{
		Location = New-Object System.Drawing.Size(5,1)
		Size = New-Object System.Drawing.Size(820,175)
		#Padding = New-Object -TypeName System.Windows.Forms.Padding -ArgumentList (5,5,5,5)
		BackColor = '#012456'
		AcceptsTab = $true
		Multiline = $true
		ScrollBars = 'Both'
		ReadOnly = $true
		Wordwrap = $true
	}
	
	[int]$CpuCores = $env:NUMBER_OF_PROCESSORS
	if ((-not $CpuCores) -or ($CpuCores -lt 1)) { $CpuCores = 1}
	if ($CpuCores -gt 8) { $CpuCores = 8}
	
	$CpuCores = 8
	
	$TabInst = $InstLog = @()
	for ($i = 0; $i -lt $CpuCores; $i++) {
		$TabInst += New-Object System.Windows.Forms.TabPage
		$TabInst[$i].DataBindings.DefaultDataSourceUpdateMode = 0
		$TabInst[$i].UseVisualStyleBackColor = $True
		$TabInst[$i].Name = "Instance" + ($i+1)
		$TabInst[$i].Text = "Instance-" + ($i+1)
		
		$ControlInstances.Controls.Add($TabInst[$i])
		
		$InstLog += New-Object System.Windows.Forms.RichTextBox -Property $RichTextBoxDefault
		$InstLog[$i].Text = "Instance-" + ($i+1) + " logs will be shown here."
		
		switch ($i%4) {
			0 { $InstLog[$i].ForeColor = 'white' }
			1 { $InstLog[$i].ForeColor = '#00FF00' }
			2 { $InstLog[$i].ForeColor = 'yellow' }
			3 { $InstLog[$i].ForeColor = '#FFA500' }
		}
		
		$InstAddEvent = "`$InstLog[`$i].Add_TextChanged({ `$InstLog[$i].SelectionStart = `$InstLog[$i].Text.Length ; `$InstLog[$i].ScrollToCaret() })"
		
		Invoke-Expression $InstAddEvent
		Invoke-Expression ("`$sync.log" + ($i+1) + "= `$InstLog[`$i]")
		Invoke-Expression ("`$TabInst[`$i].Controls.Add(`$sync.log" + ($i+1) + ")")
	}
	
	########## Tab Options & Send E-mail #########
	
	$TabOptions = New-Object System.Windows.Forms.TabPage
	$TabOptions.DataBindings.DefaultDataSourceUpdateMode = 0
	$TabOptions.UseVisualStyleBackColor = $True
	$TabOptions.Font = $FontMS
	$TabOptions.Name = "TabOptions"
	$TabOptions.Text = "Options"
	$TabMenu.Controls.Add($TabOptions)
	
	#### Options ####
	
	$objWMI = New-Object System.Windows.Forms.GroupBox
	$objWMI.Location = New-Object System.Drawing.Size(5,5)
	$objWMI.Text = "WMI Queries"
	$TabOptions.Controls.Add($objWMI)
	
	$objOptHW = New-Object System.Windows.Forms.checkbox
	$objOptHW.Location = New-Object System.Drawing.Size(10,30)
	$objOptHW.Size = New-Object System.Drawing.Size(125,25)
	#$objOptHW.BackColor = 'red'
	$objOptHW.Text = "Hardware info"
	$objOptHW.Checked = $false
	$objWMI.Controls.Add($objOptHW)
	
	$objOptDevice = New-Object System.Windows.Forms.checkbox
	$objOptDevice.Location = New-Object System.Drawing.Size(($objOptHW.Location.X), ($objOptHW.Location.Y + 30))
	$objOptDevice.Size = $objOptHW.Size
	$objOptDevice.Text = "Devices Error"
	$objOptDevice.Checked = $false
	$objWMI.Controls.Add($objOptDevice)
		
	$objOptOS = New-Object System.Windows.Forms.checkbox
	$objOptOS.Location = New-Object System.Drawing.Size(($objOptHW.Location.X), ($objOptDevice.Location.Y + 30))
	$objOptOS.Size = $objOptHW.Size
	$objOptOS.Text = "OS info"
	$objOptOS.Checked = $true
	$objWMI.Controls.Add($objOptOS)
	
	$objOptLTime = New-Object System.Windows.Forms.checkbox
	$objOptLTime.Location = New-Object System.Drawing.Size(($objOptHW.Location.X), ($objOptOS.Location.Y + 30))
	$objOptLTime.Size = $objOptHW.Size
	$objOptLTime.Text = "Local Time"
	$objOptLTime.Checked = $false
	$objWMI.Controls.Add($objOptLTime)
	
	$objOptBTime = New-Object System.Windows.Forms.checkbox
	$objOptBTime.Location = New-Object System.Drawing.Size(($objOptHW.Location.X), ($objOptLTime.Location.Y + 30))
	$objOptBTime.Size = $objOptHW.Size
	$objOptBTime.Text = "Boot Time"
	$objOptBTime.Checked = $false
	$objWMI.Controls.Add($objOptBTime)
	
	$objOptUTime = New-Object System.Windows.Forms.checkbox
	$objOptUTime.Location = New-Object System.Drawing.Size(($objOptHW.Location.X), ($objOptBTime.Location.Y + 30))
	$objOptUTime.Size = $objOptHW.Size
	$objOptUTime.Text = "Up Time"
	$objOptUTime.Checked = $true
	$objWMI.Controls.Add($objOptUTime)
	
	$objHotFixDays = New-Object System.Windows.Forms.TextBox
	$objHotFixDays.Size = New-Object System.Drawing.Size(37,20)
	$objHotFixDays.Font = $FontReset
	$objHotFixDays.MaxLength = 5
	$objWMI.Controls.Add($objHotFixDays)
	$objHotFixDays.Text = 7
	
	$objHotFixDays.Add_TextChanged({ $objHotFixDays.Text = $objHotFixDays.Text -replace '(^0+)|(\D)' })
	$objHotFixDays.Add_LostFocus({ if (-not $objHotFixDays.Text) { $objHotFixDays.Text = 7 } })
	
	$objOptHotfix = New-Object System.Windows.Forms.checkbox
	$objOptHotfix.Location = New-Object System.Drawing.Size(($objOptHW.Location.X + $objOptHW.Size.Width + 30), ($objOptHW.Location.Y - 15))
	$objOptHotfix.Size = New-Object System.Drawing.Size(150, 35)
	$objOptHotfix.Font = $FontMS
	$objOptHotfix.Text = "Installed HotFixes`r`nfor last           days"
	#$objOptHotfix.BackColor = 'red'
	$objOptHotfix.Checked = $true
	$objWMI.Controls.Add($objOptHotfix)
	
	$objHotFixDays.Location = New-Object System.Drawing.Size(($objOptHotfix.Location.X + 68), ($objOptHotfix.Location.Y + 16))
	
	$objOptReboot = New-Object System.Windows.Forms.checkbox
	$objOptReboot.Location = New-Object System.Drawing.Size(($objOptHotfix.Location.X), ($objOptHotfix.Location.Y + 45))
	$objOptReboot.Size = New-Object System.Drawing.Size(145,25)
	$objOptReboot.Text = "Pending Reboot"
	$objOptReboot.Checked = $true
	$objWMI.Controls.Add($objOptReboot)
	
	$objOptService = New-Object System.Windows.Forms.checkbox
	$objOptService.Location = New-Object System.Drawing.Size(($objOptHotfix.Location.X), ($objOptReboot.Location.Y + 30))
	$objOptService.Size = $objOptReboot.Size
	$objOptService.Text = "Services"
	$objOptService.Checked = $true
	$objWMI.Controls.Add($objOptService)
	
	$objOptCluster = New-Object System.Windows.Forms.checkbox
	$objOptCluster.Location = New-Object System.Drawing.Size(($objOptHotfix.Location.X), ($objOptService.Location.Y + 30))
	$objOptCluster.Size = $objOptReboot.Size
	$objOptCluster.Text = "Is Cluster?"
	$objOptCluster.Checked = $true
	$objWMI.Controls.Add($objOptCluster)
	
	$objOptDisk = New-Object System.Windows.Forms.checkbox
	$objOptDisk.Location = New-Object System.Drawing.Size(($objOptHotfix.Location.X), ($objOptCluster.Location.Y + 30))
	$objOptDisk.Size = $objOptReboot.Size
	$objOptDisk.Text = "Free Space"
	$objOptDisk.Checked = $true
	$objWMI.Controls.Add($objOptDisk)
	
	$objOptSMB = New-Object System.Windows.Forms.checkbox
	$objOptSMB.Location = New-Object System.Drawing.Size(($objOptHotfix.Location.X), ($objOptDisk.Location.Y + 30))
	$objOptSMB.Size = $objOptReboot.Size
	$objOptSMB.Text = "SMB Test"
	$objOptSMB.Checked = $true
	$objWMI.Controls.Add($objOptSMB)
	
	$objWMI.Size = New-Object System.Drawing.Size(($objOptHotfix.Location.X + $objOptHotfix.Size.Width + 2), 240)
	
	$objCommon = New-Object System.Windows.Forms.GroupBox
	$objCommon.Location = New-Object System.Drawing.Size(($objWMI.Location.X + $objWMI.Size.Width + 10), ($objWMI.Location.Y))
	$objCommon.Text = "Common"
	$TabOptions.Controls.Add($objCommon)
	
	$objOptRDP = New-Object System.Windows.Forms.checkbox
	$objOptRDP.Location = $objOptHW.Location
	$objOptRDP.Size = New-Object System.Drawing.Size(110,25)
	$objOptRDP.Text = "RDP Test"
	$objOptRDP.Checked = $true
	$objCommon.Controls.Add($objOptRDP)
	
	$objSelectQueries = New-Object System.Windows.Forms.TextBox
	$objSelectQueries.Location = New-Object System.Drawing.Size(($objOptRDP.Location.X), ($objOptRDP.Location.Y + 35))
	$objSelectQueries.Size = New-Object System.Drawing.Size(27,20)
	$objSelectQueries.Font = $FontReset
	$objSelectQueries.MaxLength = 1
	$objSelectQueries.Text = 5
	$objCommon.Controls.Add($objSelectQueries)
	$objTooltip.SetToolTip($objSelectQueries, "Specify how many computers`r`ncan be checked simultaneously.")
	
	$objSelectQueries.Add_TextChanged({ $objSelectQueries.Text = $objSelectQueries.Text -replace '(^0+)|(\D)' })
	$objSelectQueries.Add_LostFocus({ if (-not $objSelectQueries.Text) { $objSelectQueries.Text = 5 } })
	
	$objLabelMultitask = New-Object System.Windows.Forms.Label
	$objLabelMultitask.Location = New-Object System.Drawing.Size(($objSelectQueries.Location.X + $objSelectQueries.Size.Width + 3), ($objSelectQueries.Location.Y))
	$objLabelMultitask.Size = New-Object System.Drawing.Size(110,20)
	$objLabelMultitask.Font = $FontMS
	#$objLabelMultitask.BackColor = 'red'
	$objLabelMultitask.Text = "Multiple Tasks"
	$objCommon.Controls.Add($objLabelMultitask)
	$objTooltip.SetToolTip($objLabelMultitask, "Specify how many computers`r`ncan be checked simultaneously.")
	
	$objTimeout = New-Object System.Windows.Forms.TextBox
	$objTimeout.Location = New-Object System.Drawing.Size(($objOptRDP.Location.X), ($objSelectQueries.Location.Y + 35))
	$objTimeout.Size = $objSelectQueries.Size
	$objTimeout.Font = $FontReset
	$objTimeout.MaxLength = 3
	$objCommon.Controls.Add($objTimeout)
	$objTimeout.Text = 12
	
	$objTooltip.SetToolTip($objTimeout, "If a single host did not complete the task within specified minutes,`r`nkill its job and drop the results.")
	$objTimeout.Add_TextChanged({ $objTimeout.Text = $objTimeout.Text -replace '(^0+)|(\D)'	})
	$objTimeout.Add_LostFocus({ if (-not $objTimeout.Text) { $objTimeout.Text = 12 } })
	
	$objTimeoutLabel = New-Object System.Windows.Forms.Label
	$objTimeoutLabel.Location = New-Object System.Drawing.Size(($objOptRDP.Location.X), ($objTimeout.Location.Y))
	$objTimeoutLabel.Size = New-Object System.Drawing.Size(150,20)
	#$objTimeoutLabel.BackColor = 'red'
	$objTimeoutLabel.Text = "       Minutes timeout"
	$objCommon.Controls.Add($objTimeoutLabel)
	$objTooltip.SetToolTip($objTimeoutLabel, "If a single host did not complete the task within specified minutes,`r`nkill its job and drop the results.")
	
	$objCommon.Size = New-Object System.Drawing.Size(($objTimeoutLabel.Location.X + $objTimeoutLabel.Size.Width + 2), ($objWMI.Size.Height))
	
	#### Send E-mail ####
	
	$objEMail = New-Object System.Windows.Forms.GroupBox
	$objEMail.Location = New-Object System.Drawing.Size(($objCommon.Location.X + $objCommon.Size.Width + 10), ($objWMI.Location.Y))
	#$objEMail.Size = New-Object System.Drawing.Size(415, ($objWMI.Size.Height))
	$objEMail.Text = "E-mail options"
	$TabOptions.Controls.Add($objEMail)
	
	$objDontSend = New-Object System.Windows.Forms.RadioButton
	$objDontSend.Location = $objOptHW.Location
	$objDontSend.Size = New-Object System.Drawing.Size(110,25)
	$objDontSend.Checked = $true
	$objDontSend.Text = "Do not send"
	$objEMail.controls.Add($objDontSend)
	
	$objSendMail = New-Object System.Windows.Forms.RadioButton
	$objSendMail.Location = New-Object System.Drawing.Size(($objDontSend.Location.X + $objDontSend.Size.Width + 40), ($objDontSend.Location.Y))
	$objSendMail.Size = New-Object System.Drawing.Size(220,25)
	$objSendMail.Checked = $false
	$objSendMail.Text = "Send mail with HTML report"
	$objEMail.controls.Add($objSendMail)
	
	$objSendMail.Add_EnabledChanged({
		if ($objSendMail.Enabled) {
			if ($objSendMail.Checked) {
				$objFromAddress.Enabled = $objMailPass.Enabled = $MailShowPass.Enabled = `
				$objToAddress.Enabled = $objSmtpServer.Enabled = $objSmtpPort.Enabled = $true
			}
			else {
				$objFromAddress.Enabled = $objMailPass.Enabled = $MailShowPass.Enabled = $MailShowPass.Checked = `
				$objToAddress.Enabled = $objSmtpServer.Enabled = $objSmtpPort.Enabled = $false
			}
			
			$objFromAddress.ReadOnly = $objMailPass.ReadOnly = $objToAddress.ReadOnly = $objSmtpServer.ReadOnly = $objSmtpPort.ReadOnly = $false
		}
		else {
			$objFromAddress.ReadOnly = $objMailPass.ReadOnly = $objToAddress.ReadOnly = $objSmtpServer.ReadOnly = $objSmtpPort.ReadOnly = $true
			$MailShowPass.Checked = $MailShowPass.Enabled = $false
		}
	})
	
	$objSendMail.Add_CheckedChanged({
		if ($objSendMail.Enabled) {
			if ($objSendMail.Checked) {
				$objFromAddress.Enabled = $objMailPass.Enabled = $MailShowPass.Enabled = `
				$objToAddress.Enabled = $objSmtpServer.Enabled = $objSmtpPort.Enabled = $true
			}
			else {
				$objFromAddress.Enabled = $objMailPass.Enabled = $MailShowPass.Checked = $MailShowPass.Enabled = `
				$objToAddress.Enabled = $objSmtpServer.Enabled = $objSmtpPort.Enabled = $false
			}
			
			$objFromAddress.ReadOnly = $objMailPass.ReadOnly = $objToAddress.ReadOnly = $objSmtpServer.ReadOnly = $objSmtpPort.ReadOnly = $false
		}
		else {
			$objFromAddress.ReadOnly = $objMailPass.ReadOnly = $objToAddress.ReadOnly = $objSmtpServer.ReadOnly = $objSmtpPort.ReadOnly = $true
			$MailShowPass.Checked = $MailShowPass.Enabled = $false
		}
	})
	
	$MailLabels = New-Object System.Windows.Forms.Label
	$MailLabels.Location = New-Object System.Drawing.Size(($objOptHW.Location.X), 70)
	$MailLabels.Size = New-Object System.Drawing.Size(110,160)
	#$MailLabels.BackColor = 'red'
	$MailLabels.Text = "From Address:`r`n`r`n       Password:`r`n`r`n    To Address:`r`n`r`n SMTP Server:`r`n`r`n     SMTP Port:"
	$objEMail.Controls.Add($MailLabels)
	
	$objFromAddress = New-Object System.Windows.Forms.TextBox
	$objFromAddress.Location = New-Object System.Drawing.Point(($MailLabels.Location.X + $MailLabels.Size.Width + 1), ($MailLabels.Location.Y - 4))
	$objFromAddress.Size = New-Object System.Drawing.Size(220,25)
	$objFromAddress.Font = $FontCalibri
	$objEMail.Controls.Add($objFromAddress)
	
	$objMailPass = New-Object System.Windows.Forms.TextBox
	$objMailPass.Location = New-Object System.Drawing.Point(($objFromAddress.Location.X), ($objFromAddress.Location.Y + 35))
	$objMailPass.Size = $objFromAddress.Size
	$objMailPass.Font = $FontCalibri
	$objMailPass.PasswordChar = '*'
	$objEMail.Controls.Add($objMailPass)
	
	$MailShowPass = New-Object System.Windows.Forms.checkbox
	$MailShowPass.Location = New-Object System.Drawing.Point(($objFromAddress.Location.X + $objMailPass.Size.Width + 10), ($objMailPass.Location.Y + 3))
	$MailShowPass.Size = New-Object System.Drawing.Size(70,25)
	$MailShowPass.Text = "Show"
	$MailShowPass.Checked = $false
	$objEMail.Controls.Add($MailShowPass)
	
	$MailShowPass.Add_CheckStateChanged({
		if ($MailShowPass.Checked) { $objMailPass.PasswordChar = 0 }
		else { $objMailPass.PasswordChar = '*' }
	})
	
	$objToAddress = New-Object System.Windows.Forms.TextBox
	$objToAddress.Location = New-Object System.Drawing.Point(($objFromAddress.Location.X), ($objMailPass.Location.Y + 35))
	$objToAddress.Size = $objFromAddress.Size
	$objToAddress.Font = $FontCalibri
	$objEMail.Controls.Add($objToAddress)
	
	$objSmtpServer = New-Object System.Windows.Forms.TextBox
	$objSmtpServer.Location = New-Object System.Drawing.Point(($objFromAddress.Location.X), ($objToAddress.Location.Y + 35))
	$objSmtpServer.Size = $objFromAddress.Size
	$objSmtpServer.Font = $FontCalibri
	$objSmtpServer.Text = 'smtp.office365.com'
	$objSmtpServer.Enabled = $true
	$objEMail.Controls.Add($objSmtpServer)
	
	$objSmtpPort = New-Object System.Windows.Forms.TextBox
	$objSmtpPort.Location = New-Object System.Drawing.Point(($objFromAddress.Location.X), ($objSmtpServer.Location.Y + 35))
	$objSmtpPort.Size = New-Object System.Drawing.Size(60,25)
	$objSmtpPort.Font = $FontCalibri
	$objSmtpPort.Text = '587'
	$objSmtpPort.MaxLength = 5
	$objSmtpPort.Add_LostFocus({
		if ($objSmtpPort.Text -eq '') { $objSmtpPort.Text = '587' }
	})
	$objSmtpPort.add_TextChanged({
		$objSmtpPort.Text = $objSmtpPort.Text -replace '(^0+)|(\D)'
		if ([int]$objSmtpPort.Text -gt 65535 ) { $objSmtpPort.Text = 65535 }
	})
	
	$objEMail.Controls.Add($objSmtpPort)
	
	$objFromAddress.Enabled = $objToAddress.Enabled = $objSmtpServer.Enabled = $objSmtpPort.Enabled = $objMailPass.Enabled = $MailShowPass.Enabled = $false
	
	$objEMail.Size = New-Object System.Drawing.Size(($MailShowPass.Location.X + $MailShowPass.Size.Width + 2), ($objWMI.Size.Height))
	
	
	#### Save/Load Predefined Configuration ####
	
	$GroupConfig = New-Object System.Windows.Forms.GroupBox
	$GroupConfig.Location = New-Object System.Drawing.Size(($objEMail.Location.X), ($objEMail.Location.Y + $objEMail.Size.Height + 10))
	$GroupConfig.Size = New-Object System.Drawing.Size(($objEMail.Size.Width), 170)
	$GroupConfig.Text = "Export / Import Configuration"
	$TabOptions.Controls.Add($GroupConfig)
	
	$objSaveConfig = New-Object System.Windows.Forms.Button
	$objSaveConfig.Location = New-Object System.Drawing.Point(10,32)
	$objSaveConfig.Size = New-Object System.Drawing.Size(170,30)
	$objSaveConfig.Font = $FontButtons
	$objSaveConfig.Text = "Save Configuration..."
	$GroupConfig.Controls.Add($objSaveConfig)
	$objSaveConfig.Add_Click({
		if (-not (Test-Path "$ScriptPath\config")) { New-Item -Path "$ScriptPath\config" -ItemType Directory }
		
		$SaveFile = New-Object 'Microsoft.Win32.SaveFileDialog' # WPF
		#$SaveFile = New-Object System.Windows.Forms.SaveFileDialog
		$SaveFile.initialDirectory = "$ScriptPath\config"
		
		if ($EncryptConfig.Checked) { $SaveFile.filter = "Encrypted Config (*.enc)|*.enc" }
		else { $SaveFile.filter = "Binary Config (*.bin)|*.bin|Plain Text (*.ini)|*.ini" }
		
		$SaveOK = $SaveFile.ShowDialog()
		
		if ($SaveOK -and ($SaveFile.FileName).EndsWith(".ini")) {
			$content = "`#`#`#`# Configuration file for Sirex.ps1 script `#`#`#`r`n"
			$content += "`# This an application specific initialization file. Most stardards for INI file are not met.`r`n"
			$content += "`# Comments are allowed only in the beginning of new line with '`#' or ';'.`r`n"
			$content += "`# There is no character escaping. All symbols are recognize.`r`n"
			$content += "`# Do not quote(""<data>"") text, numbers, paths or other values.`r`n"
			$content += "`# Delimiters for multiple values (array): comma(,) , semicolon(;), space, tab`r`n"
			
			$content += "`r`n[General Options]`r`n"
			$content += "DisableEdit = " + $(if ($DisableEdits.Checked) {'YES'} else {'NO'}) + "`r`n"
			$content += "OutFolder = " + $(if ($objOutFolder.Text -ne "<current script's folder>") { $objOutFolder.Text }) + "`r`n"
			$content += "MultiTask = " + $objSelectQueries.Text + "`r`n"
			$content += "`# Timeout in minutes for single host`r`n"
			$content += "Timeout = " + $objTimeout.Text + "`r`n"
			
			$content += "`r`n[Computers]`r`n"
			$content += "Computers = " + ($objListBox.Items -join ", ") + "`r`n"
			$content += "File = `r`n"
			
			$content += "`r`n[Credentials]`r`n"
			$content += "WithCredentials = " + $(if ($objDomainUser.Checked) {'YES'} else {'NO'}) + "`r`n"
			$content += "VerifyCredentials = " + $(if (-not $objNoCredsVerify.Checked) {'YES'} else {'NO'}) + "`r`n"
			$content += "UserName = " + $objUsername.Text + "`r`n"
			$content += "Password = " + $objPassword.Text + "`r`n"
			
			$content += "`r`n[Preference]`r`n"
			$content += "HWinfo = " + $(if ($objOptHW.Checked) {'YES'} else {'NO'}) + "`r`n"
			$content += "OSinfo = " + $(if ($objOptOS.Checked) {'YES'} else {'NO'}) + "`r`n"
			$content += "DeviceError = " + $(if ($objOptDevice.Checked) {'YES'} else {'NO'}) + "`r`n"
			$content += "LocalTime = " + $(if ($objOptLTime.Checked) {'YES'} else {'NO'}) + "`r`n"
			$content += "BootTime = " + $(if ($objOptBTime.Checked) {'YES'} else {'NO'}) + "`r`n"
			$content += "UpTime = " + $(if ($objOptUTime.Checked) {'YES'} else {'NO'}) + "`r`n"
			$content += "Hotfix = " + $(if ($objOptHotfix.Checked) {'YES'} else {'NO'}) + "`r`n"
			$content += "HotfixDays = " + $objHotFixDays.Text + "`r`n"
			$content += "PendingReboot = " + $(if ($objOptReboot.Checked) {'YES'} else {'NO'}) + "`r`n"
			$content += "Services = " + $(if ($objOptService.Checked) {'YES'} else {'NO'}) + "`r`n"
			$content += "Cluster = " + $(if ($objOptCluster.Checked) {'YES'} else {'NO'}) + "`r`n"
			$content += "DiskSpace = " + $(if ($objOptDisk.Checked) {'YES'} else {'NO'}) + "`r`n"
			$content += "SMB = " + $(if ($objOptSMB.Checked) {'YES'} else {'NO'}) + "`r`n"
			$content += "RDP = " + $(if ($objOptRDP.Checked) {'YES'} else {'NO'}) + "`r`n"
			
			$content += "`r`n[Mail Options]`r`n"
			$content += "SendMail = " + $(if ($objSendMail.Checked) {'YES'} else {'NO'}) + "`r`n"
			$content += "MailFrom = " + $objFromAddress.Text + "`r`n"
			$content += "MailPassword = " + $objMailPass.Text + "`r`n"
			$content += "MailTo = " + $objToAddress.Text + "`r`n"
			$content += "SmtpServer = " + $objSmtpServer.Text + "`r`n"
			$content += "SmtpPort = " + $objSmtpPort.Text + "`r`n"
			
			if ([bool]$optAddScript.Text.Trim() -and $optAddScript.Text.Trim() -ne "<Type script up to 1MB>") {
				$AddScript = "$ScriptPath\config\" + ($SaveFile.FileName.Split("\"))[-1]
				
				if ($objScriptExt.Text.Trim()) { $AddScript += "." + $objScriptExt.Text.Trim() }
				elseif ($optCMD.Checked) { $AddScript += ".bat" }
				else { $AddScript += ".ps1" }
				
				$AddScriptBinary = [System.Text.Encoding]::UTF8.GetPreamble() + [System.Text.Encoding]::UTF8.GetBytes(($optAddScript.Text -replace "`n", "`r`n"))
				[System.IO.File]::WriteAllBytes($AddScript, $AddScriptBinary)
				
				$AddScript = ".\config\" + $AddScript.Split("\")[-1]
			}
			else { $AddScript = '' }
			
			$content += "`r`n[Remote Execution]`r`n"
			$content += "Token = " + $objTokenScript.Text + "`r`n"
			$content += "ScriptFile = " + $AddScript + "`r`n"
			$content += "UTF8BOM = " + $(if ($objBOM.Checked) {'YES'} else {'NO'}) + "`r`n"
			$content += "Arguments = "  + $argScript.Text + "`r`n"
			$content += "Batch = " + $(if ($optCMD.Checked) {'YES'} else {'NO'}) + "`r`n"
			$content += "PowerShell = " + $(if ($optPowerShell.Checked) {'YES'} else {'NO'}) + "`r`n"
			$content += "Win32Process = " + $(if ($optScriptWMI.Checked) {'YES'} else {'NO'}) + "`r`n"
			$content += "InvokeCommand = " + $(if ($optScriptInvoke.Checked) {'YES'} else {'NO'}) + "`r`n"
			
			$data = [System.Text.Encoding]::UTF8.GetPreamble()
			$data += [System.Text.Encoding]::UTF8.GetBytes($content)
			
			[System.IO.File]::WriteAllBytes($SaveFile.FileName, $data)
		}
		elseif ($SaveOK) {
			$content = @{
				DecryptionTest = "</Milestone-AES256_Decryption&JSON_Verification!>"
				
				Computers = $objListBox.Items -join ", "
				OutFolder = $objOutFolder.Text
				
				WithCredentials = [int]($objDomainUser.Checked)
				UserName = $objUsername.Text
				Password = $objPassword.Text
				VerifyCredentials = [int](-not $objNoCredsVerify.Checked)
				
				HWinfo = [int]($objOptHW.Checked)
				OSinfo = [int]($objOptOS.Checked)
				DeviceError = [int]($objOptDevice.Checked)
				LocalTime = [int]($objOptLTime.Checked)
				BootTime = [int]($objOptBTime.Checked)
				UpTime = [int]($objOptUTime.Checked)
				Hotfix = [int]($objOptHotfix.Checked)
				HotfixDays = $objHotFixDays.Text
				PendingReboot = [int]($objOptReboot.Checked)
				Services = [int]($objOptService.Checked)
				Cluster = [int]($objOptCluster.Checked)
				DiskSpace = [int]($objOptDisk.Checked)
				SMB = [int]($objOptSMB.Checked)
				RDP = [int]($objOptRDP.Checked)
				MultiTask = $objSelectQueries.Text
				
				SendMail = [int]($objSendMail.Checked)
				MailFrom = $objFromAddress.Text
				MailPassword = $objMailPass.Text
				MailTo = $objToAddress.Text
				SmtpServer = $objSmtpServer.Text
				SmtpPort = $objSmtpPort.Text
				
				Batch = [int]($optCMD.Checked)
				Win32Process = [int]($optScriptWMI.Checked)
				
				ScriptFile = $optAddScript.Text
				Extension = $objScriptExt.Text
				UTF8BOM = [int]($objBOM.Checked)
				Arguments = $argScript.Text
				Token = $objTokenScript.Text
				DisableEdit = [int]($DisableEdits.Checked)
				Timeout = $objTimeout.Text
			}
			
			$Error.Clear()
			$Serialization = New-Object System.Web.Script.Serialization.JavaScriptSerializer
			$contentJson = $Serialization.Serialize($content)
			
			$bytes = [System.Text.Encoding]::UTF8.GetBytes($contentJson)
			$contentBase64 = [System.Convert]::ToBase64String($bytes)
			
			if (($SaveFile.FileName).EndsWith(".bin")) { $encData = EncryptFile "<SiRex-Default_Encryption>" $contentBase64 }
			else { $encData = EncryptFile ($objConfigKey.Text) $contentBase64 }
			
			[System.IO.File]::WriteAllBytes($SaveFile.FileName, [System.Convert]::FromBase64String($encData))
			
			if ($Error) {
				ConfigState $true $false "Saving error, access denied or wrong path."
			}
			else {
				ConfigState $true $true "Saving config file succeeded."
			}
		}
		else { ConfigState $true $false "Saving config file has been cancelled." }
	})
	
	$DisableEdits = New-Object System.Windows.Forms.CheckBox
	$DisableEdits.Location = New-Object System.Drawing.Size(($objSaveConfig.Location.X), ($objSaveConfig.Location.Y + 45))
	$DisableEdits.Size = New-Object System.Drawing.Size(213,20)
	$DisableEdits.Font = $FontMS
	#$DisableEdits.BackColor = 'red'
	$DisableEdits.Text = "Users can't modify config"
	$GroupConfig.Controls.Add($DisableEdits)
	
	$EncryptConfig = New-Object System.Windows.Forms.CheckBox
	$EncryptConfig.Location = New-Object System.Drawing.Size(($DisableEdits.Location.X), ($DisableEdits.Location.Y + 30))
	$EncryptConfig.Size = New-Object System.Drawing.Size(170,25)
	$EncryptConfig.Font = $FontMS
	$EncryptConfig.Text = "Encrypt file with key"
	$GroupConfig.Controls.Add($EncryptConfig)
	$EncryptConfig.Add_CheckStateChanged({
		$objConfigKey.Enabled = -not $objConfigKey.Enabled
		$ConfigKeyShow.Enabled = $objConfigKey.Enabled
		
		if (-not $objConfigKey.Enabled) {
			$objConfigKey.PasswordChar = '*'
			$ConfigKeyShow.Checked = $false
		}
	})
	
	$objConfigKey = New-Object System.Windows.Forms.TextBox
	$objConfigKey.Location = New-Object System.Drawing.Point(($objSaveConfig.Location.X), ($EncryptConfig.Location.Y + $EncryptConfig.Size.Height))
	$objConfigKey.Size = New-Object System.Drawing.Size(170,25)
	$objConfigKey.PasswordChar = '*'
	$objConfigKey.Font = $FontCalibri
	$objConfigKey.Enabled = $false
	$objConfigKey.MaxLength = 32
	$GroupConfig.Controls.Add($objConfigKey)
	
	$ConfigKeyShow = New-Object System.Windows.Forms.CheckBox
	$ConfigKeyShow.Location = New-Object System.Drawing.Size(($objSaveConfig.Location.X + $objSaveConfig.Size.Width + 10), ($objConfigKey.Location.Y + 10))
	$ConfigKeyShow.Size = New-Object System.Drawing.Size(65,20)
	$ConfigKeyShow.Font = $FontMS
	#$ConfigKeyShow.BackColor = 'red'
	$ConfigKeyShow.Text = "Show"
	$ConfigKeyShow.Enabled = $false
	$GroupConfig.Controls.Add($ConfigKeyShow)
	$ConfigKeyShow.Add_CheckStateChanged({
		if ($ConfigKeyShow.Checked) { $objConfigKey.PasswordChar = 0 }
		else { $objConfigKey.PasswordChar = '*' }
	})
	
	$LabelLoad = New-Object System.Windows.Forms.Label
	$LabelLoad.Location = New-Object System.Drawing.Size(230,15)
	$LabelLoad.Size = New-Object System.Drawing.Size(160,20)
	#$LabelLoad.BackColor = 'red'
	$LabelLoad.Font = $FontMS
	$LabelLoad.Text = "Load configuration file"
	$GroupConfig.Controls.Add($LabelLoad)
	
	$objLoadConfig = New-Object System.Windows.Forms.ComboBox
	$objLoadConfig.Location = New-Object System.Drawing.Size(($LabelLoad.Location.X), 35)
	$objLoadConfig.Font = $FontCalibri
	$objLoadConfig.DropDownStyle = "DropDownList"
	[void]$objLoadConfig.Items.Add("< Default Options >")
	$objLoadConfig.SelectedIndex = 0
	$GroupConfig.Controls.Add($objLoadConfig)
	
	$objLoadConfig.Add_DropDown({
		$index = $objLoadConfig.SelectedIndex
		$Error.Clear()
		$objLoadConfig.Items.Clear()
		[void]$objLoadConfig.Items.Add("< Default Options >")
		
		$files = Get-ChildItem "$ScriptPath\config" | Where-Object { $_.Name -like "*.bin" -or $_.Name -like "*.enc" -or $_.Name -like "*.ini" }
		
		$Items = foreach ($file in $files) {
			if ($file.Name.SubString(($file.Name).LastIndexOf(".")) -eq ".bin") {
				$file.Name.SubString(0, ($file.Name).LastIndexOf(".")) + " [Binary]"
			}
			elseif ($file.Name.SubString(($file.Name).LastIndexOf(".")) -eq ".enc") {
				$file.Name.SubString(0, ($file.Name).LastIndexOf(".")) + " [Protected]"
			}
			else {
				$file.Name.SubString(0, ($file.Name).LastIndexOf(".")) + " [PlainText]"
			}
		}
		
		if ($Items) {
			foreach ($item in $Items) { [void] $objLoadConfig.Items.Add($item) }
			ConfigState $true $true "List loaded"
		}
		else {
			if ([string]$Error -like "*exist*") { ConfigState $true $false "Missing 'config' folder" }
			elseif ([string]$Error -like "*access*") { ConfigState $true $false "Access denied to`r`n'config' folder." }
			else { ConfigState $true $false "Folder 'config' is empty." }
		}
		
		$objLoadConfig.SelectedIndex = $index 
	})
	
	$objLoadConfig.Add_SelectionChangeCommitted({
		if ($objLoadConfig.SelectedIndex -eq 0) {
			$InputBox.Text = ''
			$objListBox.Items.Clear()
			
			$objCurrentUser.Checked = $true
			$objDomainUser.Checked = $false
			$objUsername.Text = ''
			$objPassword.Text = ''
			$objNoCredsVerify.Checked = $false
			$objOutFolder.Text = "<current script's folder>"
			
			$objOptHW.Checked = $false
			$objOptDevice.Checked = $false
			$objOptOS.Checked = $true
			$objOptLTime.Checked = $false
			$objOptBTime.Checked = $false
			$objOptUTime.Checked = $true
			$objOptHotfix.Checked = $true
			$objHotFixDays.Text = 7
			$objOptReboot.Checked = $true
			$objOptService.Checked = $true
			$objOptCluster.Checked = $true
			$objOptDisk.Checked = $true
			$objOptSMB.Checked = $false
			$objOptRDP.Checked = $true
			$objSelectQueries.Text = 5
			$objTimeout.Text = 12
			
			$objDontSend.Checked = $true
			$objSendMail.Checked = $false
			$objFromAddress.Text = $objMailPass.Text = $objToAddress.Text = ''
			$objSmtpServer.Text = 'smtp.office365.com'
			$objSmtpPort.Text = '587'
			
			$optCMD.Checked = $true
			$optScriptWMI.Checked = $true
			
			$objTokenScript.Text = ''
			$argScript.Text = ''
			$objScriptExt.Text = ''
			$objBOM.Checked = $false
			$optAddScript.Text = "<Type script up to 1MB>"
			
			StateForms $true
			
			ConfigState $true $true "Default options loaded."
			return $null
		}
		
		$item = $objLoadConfig.Items[$objLoadConfig.SelectedIndex] #"$ScriptPath\config"
		$Json = $null
		
		if ($item.EndsWith("[PlainText]")) {
			$item = $item.SubString(0, $item.LastIndexOf(" [PlainText]"))
			$file = "$ScriptPath\config\" + $item + ".ini"
			
			[string[]]$iniData = [System.IO.File]::ReadAllLines($file, [System.Text.Encoding]::UTF8)
			
			if (($iniData | Out-String).Trim()) { $Json = DeserializeINI $iniData }
			else { ConfigState $true $false "Empty Config file or wrong format." }
		}
		elseif ($item.EndsWith("[Binary]" )) {
			$item = $item.SubString(0, $item.LastIndexOf(" [Binary]"))
			$file = "$ScriptPath\config\" + $item + ".bin"
			
			$bytes = [System.IO.File]::ReadAllBytes($file)
			$contentBase64 = [System.Convert]::ToBase64String($bytes)
			$jsonData = (DecryptFile "<SiRex-Default_Encryption>" $contentBase64 | Out-String).Trim()
		}
		elseif ($item.EndsWith("[Protected]")) {
			$item = $item.SubString(0, $item.LastIndexOf(" [Protected]"))
			$file = "$ScriptPath\config\" + $item + ".enc"
			
			$bytes = [System.IO.File]::ReadAllBytes($file)
			$contentBase64 = [System.Convert]::ToBase64String($bytes)
			$jsonData = (DecryptFile (GetKey) $contentBase64 | Out-String).Trim()
		}
		else {
			ConfigState $true $false "Wrong config file format."
			return $null
		}
		
		if (-not $file.EndsWith(".ini")) {
			if ($jsonData) {
				$Error.Clear()			
				$Serialization = New-Object System.Web.Script.Serialization.JavaScriptSerializer
				Try { $Json = $Serialization.DeserializeObject($jsonData) } Catch {}
				
				if ($Error) { ConfigState $true $false "Decryption Failure!" }
				else { ConfigState $true $true "Decryption succeeded." }
			}
			else {
				ConfigState $true $false "Empty Config file or wrong format."
			}
		}
		
		if ($Json) {
			if ($Json.DecryptionTest -ne "</Milestone-AES256_Decryption&JSON_Verification!>") {
				ConfigState $true $false "Encoding Error. Don't mess with the config file!"
			}
			else {
				$objShowPassword.Checked = $MailShowPass.Checked = $false
				
				$objListBox.Items.Clear()
				AddHosts ($Json.Computers)
				AddHosts ($Json.File)
				
				$objDomainUser.Checked = $Json.WithCredentials
				$objCurrentUser.Checked = -not $objDomainUser.Checked
				$objUsername.Text = $Json.UserName
				$objPassword.Text = $Json.Password
				$objNoCredsVerify.Checked = -not $Json.VerifyCredentials
				$objOutFolder.Text = $Json.OutFolder
				
				$objOptHW.Checked = $Json.HWinfo
				$objOptOS.Checked = $Json.OSinfo
				$objOptDevice.Checked = $Json.DeviceError
				$objOptLTime.Checked = $Json.LocalTime
				$objOptBTime.Checked = $Json.BootTime
				$objOptUTime.Checked = $Json.UpTime
				$objOptHotfix.Checked = $Json.Hotfix
				$objHotFixDays.Text = $Json.HotfixDays
				$objOptReboot.Checked = $Json.PendingReboot
				$objOptService.Checked = $Json.Services
				$objOptCluster.Checked = $Json.Cluster
				$objOptDisk.Checked = $Json.DiskSpace
				$objOptSMB.Checked = $Json.SMB
				$objOptRDP.Checked = $Json.RDP
				$objSelectQueries.Text = $Json.MultiTask
				$objTimeout.Text = $Json.Timeout
				
				$objSendMail.Checked = $Json.SendMail
				$objDontSend.Checked = -not $objSendMail.Checked
				$objFromAddress.Text = $Json.MailFrom
				$objMailPass.Text = $Json.MailPassword
				$objToAddress.Text = $Json.MailTo
				$objSmtpServer.Text = $Json.SmtpServer
				$objSmtpPort.Text = $Json.SmtpPort
				
				$optCMD.Checked = $Json.Batch
				$optPowerShell.Checked = -not $Json.Batch
				$optScriptWMI.Checked = $Json.Win32Process
				$optScriptInvoke.Checked = -not $Json.Win32Process
				
				$argScript.Text = $Json.Arguments
				$optAddScript.Text = $Json.ScriptFile
				$objTokenScript.Text = $Json.Token
				$objScriptExt.Text = $Json.Extension
				$objBOM.Checked = $Json.UTF8BOM
				StateForms $(if (@("1","YES","TRUE") -contains $Json.DisableEdit) {0} else {1})
				
				ConfigState $true $true "Loading succeeded."
			}
		}
	})
	
	$LabelErrorCFG = New-Object System.Windows.Forms.Label
	$LabelErrorCFG.Location = New-Object System.Drawing.Size(($objLoadConfig.Location.X), ($objLoadConfig.Location.Y + $objLoadConfig.Size.Height + 25))
	$LabelErrorCFG.Size = New-Object System.Drawing.Size(180,37)
	$LabelErrorCFG.Font = $FontMS
	$LabelErrorCFG.ForeColor = 'red'
	$LabelErrorCFG.BackColor = 'black'
	$GroupConfig.Controls.Add($LabelErrorCFG)
	$LabelErrorCFG.Hide()
	
	#### Remote Management ####
	
	$GroupRemote = New-Object System.Windows.Forms.GroupBox
	$GroupRemote.Location = New-Object System.Drawing.Size(($objWMI.Location.X), ($objEMail.Location.Y + $objEMail.Size.Height + 10))
	$GroupRemote.Size = New-Object System.Drawing.Size(($objWMI.Size.Width + $objCommon.Size.Width + 10), 185)
	$GroupRemote.Text = "Remote management. Execute script as a local process."
	
	$GroupScriptType = New-Object System.Windows.Forms.GroupBox
	$GroupScriptType.Location = New-Object System.Drawing.Size(10,25)
	$GroupScriptType.Size = New-Object System.Drawing.Size(220,80)
	$GroupScriptType.Text = "Shell"
	$GroupRemote.Controls.Add($GroupScriptType)
	
	$optCMD = New-Object System.Windows.Forms.RadioButton
	$optCMD.Location = New-Object System.Drawing.Size(20,20)
	$optCMD.Size = New-Object System.Drawing.Size(160,25)
	$optCMD.Checked = $true
	#$optCMD.BackColor = 'red'
	$optCMD.Text = "Command Prompt"
	$optCMD.Add_CheckedChanged({
		$optAddScript.BackColor = '#000000'
		$optAddScript.ForeColor = '#c0c0c0'
	})
	$GroupScriptType.controls.Add($optCMD)
	
	$optPowerShell = New-Object System.Windows.Forms.RadioButton
	$optPowerShell.Location = New-Object System.Drawing.Size(($optCMD.Location.X), ($optCMD.Location.Y + 30))
	$optPowerShell.Size = $optCMD.Size
	$optPowerShell.Checked = $false
	$optPowerShell.Text = "PowerShell 2.0+"
	$GroupScriptType.controls.Add($optPowerShell)
	$optPowerShell.Add_CheckedChanged({
		$optAddScript.BackColor = '#012456'
		$optAddScript.ForeColor = '#eeedf0'
	})
	
	$GroupScriptMethod = New-Object System.Windows.Forms.GroupBox
	$GroupScriptMethod.Location = New-Object System.Drawing.Size(($GroupScriptType.Location.X + $GroupScriptType.Size.Width + 10), ($GroupScriptType.Location.Y))
	$GroupScriptMethod.Size = New-Object System.Drawing.Size(240,80)
	$GroupScriptMethod.Text = "Method"
	$GroupRemote.Controls.Add($GroupScriptMethod)
	
	$optScriptWMI = New-Object System.Windows.Forms.RadioButton
	$optScriptWMI.Location = $optCMD.Location
	$optScriptWMI.Size = New-Object System.Drawing.Size(210,25)
	$optScriptWMI.Checked = $true
	#$optScriptWMI.BackColor = 'red'
	$optScriptWMI.Text = "WMI: Win32_Process"
	$GroupScriptMethod.controls.Add($optScriptWMI)
	
	$optScriptInvoke = New-Object System.Windows.Forms.RadioButton
	$optScriptInvoke.Location = $optPowerShell.Location
	$optScriptInvoke.Size = New-Object System.Drawing.Size(210,25)
	$optScriptInvoke.Checked = $false
	#$optScriptInvoke.BackColor = 'red'
	$optScriptInvoke.Text = "Cmdlet: Invoke-Command"
	$GroupScriptMethod.controls.Add($optScriptInvoke)
	
	$lblScript = New-Object System.Windows.Forms.Label
	$lblScript.Location = New-Object System.Drawing.Size(($GroupScriptType.Location.X), ($GroupScriptType.Location.X + $GroupScriptType.Size.Height + 25))
	$lblScript.Size = New-Object System.Drawing.Size(470,55)
	$lblScript.Font = $FontMS
	#$lblScript.BackColor = 'red'
	$lblScript.Text = "Exec/Token:                                                                      Ext.:`r`n`r`n  Arguments:"
	$objTooltip.SetToolTip($lblScript, "Exec/Token: It is the first part of command before calling a script.`r`nIt is required to run non Batch or non PowerShell scripts.`r`nFor example to run VBS script type: CScript`r`n`r`nExtension Examples: VBS; PY`r`n`r`nArguments: If the script has parameters you have to pass arguments.`r`nExample: -Properties SID, SamAccountName")
	
	$objTokenScript = New-Object System.Windows.Forms.TextBox
	$objTokenScript.Location = New-Object System.Drawing.Point(($lblScript.Location.X + 90), ($lblScript.Location.Y - 3))
	$objTokenScript.Size = New-Object System.Drawing.Size(($lblScript.Size.Width - 200), 25)
	$objTokenScript.Font = $FontCalibri
	$objTokenScript.ForeColor = 'DarkRed'
	$objTokenScript.MaxLength = 8192
	$GroupRemote.Controls.Add($objTokenScript)
	$objTooltip.SetToolTip($objTokenScript, "Examples:`r`n   CScript `r`n   C:\Python27\python.exe ")
	
	$objScriptExt = New-Object System.Windows.Forms.TextBox
	$objScriptExt.Location = New-Object System.Drawing.Point(($objTokenScript.Location.X + $objTokenScript.Size.Width + 45), ($objTokenScript.Location.Y))
	$objScriptExt.Size = New-Object System.Drawing.Size(60, 25)
	$objScriptExt.Font = $FontCalibri
	$objScriptExt.MaxLength = 32
	$objScriptExt.Add_TextChanged({ $objScriptExt.Text = $objScriptExt.Text -replace "[\""\'\s+]" })
	$GroupRemote.Controls.Add($objScriptExt)
	$objTooltip.SetToolTip($objScriptExt, "Extension example:`r`n`  vbs`r`n  py")
	
	$argScript = New-Object System.Windows.Forms.TextBox
	$argScript.Location = New-Object System.Drawing.Point(($objTokenScript.Location.X), ($objTokenScript.Location.Y + 35))
	$argScript.Size = $objTokenScript.Size
	$argScript.Font = $FontCalibri
	$argScript.ForeColor = 'DarkBlue'
	$argScript.MaxLength = 8192
	$GroupRemote.Controls.Add($argScript)
	$objTooltip.SetToolTip($argScript, "Examples:`r`n   -Domain dev.net -ListAvailable `r`n   -Backup Incremental ")
	
	$objBOM = New-Object System.Windows.Forms.checkbox
	$objBOM.Location = New-Object System.Drawing.Point(($argScript.Location.X + $argScript.Size.Width + 10), ($objScriptExt.Location.Y + 35))
	$objBOM.Size = New-Object System.Drawing.Size(105, 25)
	$objBOM.Font = $FontMS
	#$objBOM.BackColor = 'red'
	$objBOM.Text = "UTF8 BOM"
	$GroupRemote.Controls.Add($objBOM)
	$objTooltip.SetToolTip($objBOM, "Add 'Byte Order Mark' for UTF8 encoding into remote script file.")
	
	$GroupRemote.Controls.Add($lblScript)
	
	$optAddScript = New-Object System.Windows.Forms.RichTextBox
	$optAddScript.Font = "Lucida Console, 11.00pt"
	$optAddScript.AcceptsTab = $true
	$optAddScript.Multiline = $true
	$optAddScript.ScrollBars = 'Both'
	$optAddScript.Wordwrap = $false
	$optAddScript.MaxLength = 1048576
	$optAddScript.BackColor = '#000000'
	$optAddScript.ForeColor = '#c0c0c0'
	$optAddScript.Text = "<Type script up to 1MB>"
	$TabOptions.Controls.Add($optAddScript)
	
	$optAddScript.Add_GotFocus({ if ($optAddScript.Text.Trim() -eq "<Type script up to 1MB>") { $optAddScript.Text = '' } })
	$optAddScript.Add_LostFocus({ if (-not $optAddScript.Text.Trim()) { $optAddScript.Text = "<Type script up to 1MB>" } })
	
	$TabOptions.Controls.Add($GroupRemote)
	
	########## Tab Update #########
	
	### Reference1: https://blog.jourdant.me/post/3-ways-to-download-files-with-powershell
	### Reference2: https://monteledwards.com/2017/03/05/powershell-oauth-downloadinguploading-to-google-drive-via-drive-api/
	### Reference3: https://www.connorcg.com/uploading-and-downloading-from-google-drive-via-api-with-powershell-and-oauth2.html
	
	$UpdateReport = {
		Param([string]$operation)
		
		$Report = [PowerShell]::Create().AddScript($ScriptUpdate).AddArgument($true).AddArgument($operation).AddArgument($Script:ScriptPath).AddArgument($Script:ScriptName)
		
		$runspace = [RunspaceFactory]::CreateRunspace()
		$runspace.ApartmentState = "STA"
		$runspace.ThreadOptions = "ReuseThread"
		$runspace.Open()
		$runspace.SessionStateProxy.SetVariable("UpdateInfo", $UpdateInfo)
		
		$Report.Runspace = $runspace
		$Report.BeginInvoke()
	}
	
	$UpdateInfo = [Hashtable]::Synchronized(@{})
	
	$TabSupport = New-Object System.Windows.Forms.TabPage
	$TabSupport.DataBindings.DefaultDataSourceUpdateMode = 0
	$TabSupport.UseVisualStyleBackColor = $True
	$TabSupport.Font = $FontReset
	$TabSupport.Name = "TabSupport"
	$TabSupport.Text = "Support"
	$TabMenu.Controls.Add($TabSupport)
	
	#### Embed Image: https://stackoverflow.com/questions/53376491/powershell-how-to-embed-icon-in-powershell-gui-exe
	
	$PayPalIcon = "iVBORw0KGgoAAAANSUhEUgAAAHIAAAAgCAYAAADOmyyBAAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAADsMAAA7DAcdvqGQAABVPSURBVGhD7VoJeBVFtv6r736z3CR4s0EIYU3CEoQRMeyiiKiIgui4MSqj4wjq8GQUdT4cHR8uyLznio6CioKouCsoq4ILqyiL7HvIvueu3bd7TlV333sTAkblm+973+OHSlWfOlV16pyqU6e6L0Mbo"
	$PayPalIcon += "exeYNcqv8+L1B3oB1XuyxRfVzBYjOozOA3QNARgS94Lq2uLrdv4VZauExuMqp/FzxoyuOKPXotce4UWqruVhurJNM2pSXYwi51aS23o4QzaBI2SqkCLBKmscIoKa+IXcKb+j63X1BUsa0CEE0+Gk5pB7MD9H4zW5IbHaYB85kgHyzgHzNsfLLE9YEsELFaDm0txKpjDtIXv/2tfRI/I0EI1QMMRaBWbKa0nwzaRnt1rYU+60z767a0G8wkwR28G+cdnndrhZS"
	$PayPalIcon += "8h4h/PEnLdUu5YsMzfgVkdhgymIPHCtybgyYQ+GUz+/6t9teBjlJPXEhTym9x3Ci+m8c11qr54OyrJfmjHViGy/10ysj8cDKvTk6/+6mnB2gK8ZTPULBziTnBaljHJNkRqPxJSlytpRZAbPQHGgCaEkCd01wwRFdi286jxFIPVZkW6NwnpaUn0RP20oa82o5W+wiTHj+UhKplz0HM7nfidkm1IdvKjn9NaoA1yPbiyHFvLyD0SJhYm4cCyN1FWWYMuudnIycn"
	$PayPalIcon += "B6q/WYca029GpI3m1tiJYh8jOf0Gr2w5FZf90j18zzaiJoplUNW9fmJpglefT+Xe5pfNE2oXFJxHcnGRcnZikURY4sd2m7ccwYMIzepWuu1hO6JDhwfMzr8SlI/J1QhTmePE4sf+28Wn4eE8Ql79bajyfiLwUG+aO9uLCzk6DYuBn5tgQ0lD08jEcbpDF89tXZKCXtQJLV3yNs7xeLH5vKSJKAE88NB2987ucsq/WoO5ZBLX8SwRl9kTyxDX3GmSBZq2DS4Y/"
	$PayPalIcon += "JVmkaVLeREgZA4iikewGC9eRRGWhq5jCTDubi5XnHPH2N+semfsVZj6/WtActPzt1F8wHIEc4QyCLLpe8fIkjBjQSe+PV1AHCu0iG20U81kgbsD4sU3E03jZxJ+XN2DuVp8oOy0MNqoLqZrYqfH45jovzs22GZ0wyrg+SA3kHTni++T09aUKit+o5Kxw0Nz235oOh9yIz7/ahOzMDHTNzcTGH3eje157FHbrZLTU0bIvDsYM/VMljc5ryJgLoVZvVqoblQlZN"
	$PayPalIcon += "677UOcUQ+qofHPIuR63Za3kPc8m5Y4hiilt9E8czInxMfRydPR4NGvLcMmUxVj6zUHx9McrivDY3SMQDslYueEwbnjwY91IhHv/cC5uHNsHc9/ajJ2HqnC8vAn+sIxktwOdc1IwoGc2ZtxSTEOquGnmZ7QQyAI0/hN3D0d7ctEm3vh0B5Z+q4+XkujAP6YME3mfBY3YUS0iQ/ylrxMPnOdCUIng/b0Kpq72R0WeVezEqE5OvLItiB21Kip8EQSoWbKDoavHgm"
	$PayPalIcon += "E5Fkw92zx2GGZvCuGva6k9YVSODcvGJ4iyOBeFzlpDHL01FmFhqojWqeRmX0TEd+zY1Y9v7/7h+qoApwqRv5vd39q3c+IyyZE60tLtJhGR8nZ6H6LEC/SPVgYVhQF1Dkoc0VGiMI2i/9VQWh1E4YRX0eDX3c5rM0fh+jG6C20MyMi44EWE+LYjPHTrQKi0Qx5+eb3etblIuEcwcPUFXbFw1qUouGI+9hyrF3zvPH4JrhxBLosejlUGMPzWt3HwOF3FqG4ejTf"
	$PayPalIcon += "pknzsJ9Y+C0MIci9AWDrWgVEd9X7L/Ro6zg9BMYabM9iG7VURzNtlbFWDHp024f5+djxSTARSzIXvhbGqROeddZ4df+1vGpA3aJHT/3g98r8cnMOsM4oEXfcc/K8WqIS6+yWU1gbm5N787T2cJLZdXqarUGJsCEvsRsqiK4USBOP3GcqhUFDA80goShM5Pet0oxyfqA3n0fl4CmPrTyVo8OlGtJBBint7oYSDqKppwFOvb0BI1hWQ6LJhSC8v0Ztw2+UFWDLr"
	$PayPalIcon += "Qnz/xkRsfu0qTJnQi89JYNUGCprkIPrnn6UTaIZbdhwX40XkEO6YtTxqxEljemDSaHJlVPflkUDUiJkuoF9aCDLJUdEYxP3rwlEjplGAfkmOjDragnf20vD+KOCHqzV8fYWGa7rqSuVYslefX2ldEN9XGUTqY1R2ODp3kcfpUderqWOuM70c1ZdRp9dzGumTzlaznlldYM4MpCbabhlf7M3gQwpDuuyWCeKGb0mA5iun6DhEoW9QT9QRv6TqZaLHp5Z8Uf4Wf"
	$PayPalIcon += "ERbs/GIubxo8TLc8LcvMOAP76DPtW/hkVc2izqHTcI91xRi2Nnt8MQd/TD5sm5o9IWwZMUe/HPxj9i2r1rvgNAhg2Slfvt0TTUowM4DVYL2zFtb8enXhwXtd2To2VP6CzpPK48aliJUkV7GfabinHc0FCzS8OoevS7BouG+IhldEkN49XwFE/IU2q0RLNyt4bnttNubjB1KyEsmu5GSvyuTURvS6VluFYUePp4+96iuTH1xmqk3rttmujJ44utFHjbqAlAbSs"
	$PayPalIcon += "houXDaJM81Q9P5OSicp9X/7rBNVke7IpbcWwjCEjPAHCmifAJ4C0MXPIutzTi04AnTMu93yzLsOnqSN07E1DHDjb/f3BtXjeiIj9eV4MGXt+FgWRNU7mMoMdrFprvhuGdiPh6/vQjrttVg2NQvxFTyspLw4WNDMfT2z1HnV+D1OPD+o8NwXiGfC4MvQmfb4iRUhFqVWqAoLYL7+gRxVWeFXKoDD291oMRvuD76I44WwaljzoAg7uoVxv0bHXh8G21jwriOCpa"
	$PayPalIcon += "MpGBKMMe49T5oLkLtcYjqi/+JPhBa8FFMoPkroAXpfCAerWYdvv6p9v0R939/PVs0vTD7yuKMn5ijfTKzZwsGIYCrHViC2LU6rWWnJ+DkPD8dbcTA21fDF9LfMk2b0AXZXrcoc1c6uFcKOngTqGzF0g3lmDDzO+Fq3U4rrhmWifFk3N609PtOXoGaRoo2SBkfPVqMMedmoqohhJyrlkKmM9VKxj67eyo27qqh45Rh7rQi3Dw6T4zDsaHahuJPjQVK4t7bO4BM"
	$PayPalIcon += "Z4QWC8lh1zAyKwyvU0WCTcNr+9z40zeJkKnOQ8+TutKVJSdE7lhF0UdpugumtPGyWpzdTkb/j9rhh1r91fOrgxpxfRfa7j8L3glHS71xegsa35FNdGUK69E259H8e3C4tPxo9z9tGCIlOS3dab0lQ7PS1g3oiW/f+iNQq3ZCC9XpnRiuiftss2zy6348xhPj0+u+21YFX1A3oo2U/cC1XXH35R1w99gOmDwqA/lZDiRayUDkQhavPBo9L4f1ScOzU3vjorNT8"
	$PayPalIcon += "e32CtQ06JFmRpoLxYXk06jvFJdGO5EOO4JCFuFG5Ljhgg6YMChdl81IK47G3vG3J/f3QM8aTO1Ri7vya3FzXi06Of1IAOcN4ePDVmFEjom5fjzZtxrDvI347Jgteo7mJSgoSPDhEEW0u+v1vvlZNSKdlG2M2VwfMZ3oZd2VnljH6SaNEh13whZ+fnT4oco+QSe3CY/bmtnR68iT6A7n5QJoEUUYULwWopwfsJq/hi6g26mTXVSm+xGnqRSwRBMplr/opTL34T"
	$PayPalIcon += "E6PRv1PF+9Vb9bcQzplUrhO7kI/l6R85l5XBsTn2+qxJj71+OcO9bh6oe3RPsoykuExxER/BZNRudsI8w3UES794nJXZDExzH6lRUZy0voTmhgqDcAF6P58PEpRefBEz0ba0ng1f0JuHiVF30+zsL0TbHrzdD0EBwsjJWlNgQN/p4pMrIdpEOjr+b6iI1j0lut47rkxmo6Dq1yB90b90ALN5FdDANy43IbqSocVkbhqdaRvfaXgut/PzRjgQZavYzuROSHY76"
	$PayPalIcon += "dclE2pOT3IatTf2Un7kYnA9e4vmz5LimcVoqSOn1HPjTBg+mXeqhE9dFxOPQ25fUKBs8sw5FqXk87mILoAbkSdpaqoMBS4MFxCZgxLk1/IExf2ICnl/Fzg+54ToZl96aif5fmxq2Unei7bjDqI/rOeaXnD7g6q1yUdVljMvPyrgYXzt84ENWq/n7ZwVQMTS7FxsZ0+Iyvdy/12IJrc6pw/bZ++KBcj57vbr8P/yjYTyXeH4fZ56kQNzZfyIYxNSrzVwFCTwT+"
	$PayPalIcon += "QiJ6vgq9+eH3V6PPnRumsIevzbvmvqtyF2kqrTSttXeqvw38/Cmp1egaqyOVXGGy61SLAPCRT1u5k9pQ426ZDD0yJJRRnBThnRFSyJN6XPqEDlEgO/gxBZXG0TFrnAXTRhmTjQO/hx0N6ucy10WKLYwkiRR2CtTKdqypz6RdD3R116MHpdKwW6ic6zHDTjtSiqAmbEeTahVKdkkqzrLRbvnV4L2fKH+rkHyorG9U+961cRq7tP9ZFy26t/BTO3NatEjM9TRbJ"
	$PayPalIcon += "VHE0U7YTSbiaS3bt4Z4vra20REiOwyeY8c24xI+eZCG/52owUK759fBHP+XydEmRPXVcoyT5a3BqDP6Yja6ux6o9w2ZsXU6LSLWb9fz5y7v5HWlaaFYMNAcp+q8rTgdfZhgYrfO+JAi06/1QKcgQ8EXUwK021vMgSuPT/w34XTKfnLwEX6JpJJLwfyVZVW3PbdrKl3PpJy3phd8OG6g9+yIj1byaZa3tIGR29PFs5KP6pam0Ll3sgXzy1DeZBQI3Fl7E/Uyx4"
	$PayPalIcon += "EqFVnJGn/ZYVB+GQ5UMzSFGbq0iyDBzvRnmaF3ZoSU/VsXxm8HszBIbobJz+zatWBV2W0Wi8S0poBadM2w9H6IkJCyDKZRfprSh9stGPtSClbttuHFtU48utwNRY5gON2zmKrzyEpEnKOBkEqRJh3wBp1fQ/xEs0kKjtXSGqPD32WJ9R2hqM0XoPtUREVGogLJoPup3YA5qThQyTCscxBOOsc4nRjprOUBFd1RrRHYWKyvlumplU7cvCiZ5LZg8kAfZi934PZ"
	$PayPalIcon += "3kvHX4XUU6qiCh8t3rE6Dn65WSfZY24aACoV0yc/PeipL/Fcb0OnkS0TZ5P3ViTxPVaMcmfnmwc11vshCSVFV//If61Zv2uPzS3QBj4bF8dcJHp6bz9HcrIt7bqUNI2VzPH15NY7+7ThuL27CY6sTsekQbX3iOVKtYtizqTj/uTTkz/Ji6DNpCIWoH6rbW66i+3970etxL/rPPgsFj3nx1T7ae1TH1DAum+vB+HkpKHrSi56PpeFwNRmL6hZ8a0NtwIIPtrkw"
	$PayPalIcon += "/OlU0Z9CC/SBTxIw+oUUXLcgBX1np+Hr/bSzuMxc1pZzIddkoc28qcSOu5bwCNhwVbyOEo+qL6LxR89NRZ8n03Hx3BQhE2//96UuWkjtxMcALt+Qp1MgyyFBm72SomDiEVceStHrTyvPrdWJMnk2ZpHw2qryxkMVoc0kVSX3SJGwrGycsWDfeq5yluCkuwqFvvxeSXcvkWiColNBb0Hjdx+RcxqvI7rg0+vpD5++2GU2yLi4h09Esj8c1xfNoi1ObD1ux7o/l"
	$PayPalIcon += "+CbKUexmS7cL35LiqP2TFNQH2KYcX4t1lJ9XVDCuoOkXTGWgodG12BMgR8XdvPjUJ0Nq/dQsEZ1tw6sQ6Jdxe/7+bD+zqO08xS6/mh46Ts3Mj0RXExtShsteHMLna9GuB+bm2FMkjvVqWLmBbWYtzEBW0guAf7DKKp/gc7mH0juVbcexyc3lWDNQQfmfkNRMbUf29OHg7VWzF/vwp4qC34qt+Op1Uk4XG8R89cNo+uI8STmQ8+U82dRx8tG4nVCJp7T+Mzt5C"
	$PayPalIcon += "9Y1Gc+PnaYCF9S8ot7gMtuP/jl9rp3P/q2upE5bGRMl26YaOIXVT3xCUZpfOLxKY4vlnRDcldTTWfw57ucFFUC3dOCUKlNkLpMsKmwS2HhAi2SJlymarTn8Dhk5CQbl0i60/J2P5VLuGxeFmpJLyO6+IxATq/jstho1crk+igUFwtCJnfeFJbQJTWMHql+PHtpOS7Nb6LuZL1NnMz8WQxFC27aoGr0ywph9UE9qAItIF4fItH4Gx63VYad3D3fsGFFl3t4bgO"
	$PayPalIcon += "ykxU8+EUaRnf34XyS74m1HvTOCKOXly71cWNpJF90fMrNeYuykejBkIlcM7cNzXXay/vqSmvDa2iL8B9k6Z+xAuEw5/rkujk7Vm3e2xCSEtyQnCQ4dcAbxyc+iCjzOjOZz3F8sWcCDXzjO9kY8GwnLP4hEc9dVopBHRsFz23nVMFt13DBv3Ix6e1MCoZkDMmlKEa0N9wZz8Qzz+mByllJIVKghvVHnfhsV4Igk3A6H+WF3hBe3ZyMsa+3R5CMmJcaxMTejZi3"
	$PayPalIcon += "KRlv/ejBixtSsP6wnVg5vyGraGuUaTHxLhmdZ+9dfwRpLn0u/Msg55k2uAKJNg2jX8nBHe9nIN8bxpju/LsoKZ36vIwWSYQ0fkVBA+4eVAM/LaJxhY2wknfgxjPHierTHL+lHJQLfqZBSkqks9GJFz4raXptddluqnyPkngnSSqOQqJo7EKvx/bIu/f17DMw3+PQ/H5E6mKfjqLQZ9gcJ6H5ZAu5FN0t2WjZZCbJSKbAgLObaKRrzzdH3HCTYgq8QZyVoO9ER"
	$PayPalIcon += "WXYXe1EdqJMilSwo9JJeQSZ9Mw7ON5kx75qO7qmhVFHfXAeUUeQIwzfHXOLd7sDOjSJb9JcvO0VLhypt9IOV9DBE0aKkyuM0EL+xrAFxxts6NYuRG01VAesFCVbSb4QsenSB2QJXx3irwtV5KcHYn0ReN2hOgc6ekJiXjtJ9g7JYXg4jzmWeTWKPhs5RxwPs9khpaSB2e1YsLrMf8fcPYeDYe05mwXz5YgmfpJgNjMgORjTJmam2P5r/l0F+ecXpTr4ylQbGq"
	$PayPalIcon += "D6+Eda3vsZ/KfArHTMuRMgJSYhRGt/3hel/ntf318SDKtvSpL0vKqq5qfslj/51yLpHsfeinq58Y01Zbn1PiXxvAKPw5nkZlJSMl0EreK7oDCo7sv0ZmdwesAk2n02uujT0eZJoV2YCuZwoqQ6FLluzs7a5z8rKaGb2pvE+ZKmaZV6Ix0tdqQOu9XqDCuRkWSoO+ie2WvGhI4pk0ZmuXLT+f3kDP4ToKhU23PcL9N56F+8tqIpEFb5m/hFtPfep4irQueKoVV"
	$PayPalIcon += "DGrAwJnWiSHAClfnPCToWdUpMGFLosXfJclk7tHNaLNZTNT+DX4pQWNVKqoLqlv1N8vq9DeH9ZQEeqnOjfckYW2K1sK2yorb6Rr4tlnDSedxN09gg2qHF9Mx/psa/Q7X49e4ZnCbwaI1/k+M/OvqeAtAvKVLeSWUK80V42yravKXcdovNH1bpoAT/EJ1FRuW/eor/XHIGvx1kKNZAG6eMDFNBO7CG7qZhov9MMAL8G1uCRfQ/svkUAAAAAElFTkSuQmCC"
	$IconBytes = [Convert]::FromBase64String($PayPalIcon)
	$IconStream = New-Object IO.MemoryStream($iconBytes, 0, $iconBytes.Length)
	$IconStream.Write($iconBytes, 0, $iconBytes.Length);
	$iconImage = [System.Drawing.Image]::FromStream($IconStream, $true)
	
	$btnDonation = New-Object System.Windows.Forms.Button
	$btnDonation.Location = New-Object System.Drawing.Point(785,5)
	$btnDonation.Size = New-Object System.Drawing.Size(115,35)
	$btnDonation.UseVisualStyleBackColor = $false
	$btnDonation.FlatAppearance.BorderSize = 0
	$btnDonation.FlatStyle = 'Flat'
	$btnDonation.Font = $FontButtons
	$btnDonation.Image = $iconImage
	#$btnDonation.BackgroundImageLayout = "None"
	$btnDonation.Add_Click({[system.Diagnostics.Process]::start("https://www.paypal.com/cgi-bin/webscr?cmd=_s-xclick&hosted_button_id=WN3KLRK3EBSNS&source=url")})
	$TabSupport.Controls.Add($btnDonation)
	
	$objTextDonate = New-Object System.Windows.Forms.Label
	$objTextDonate.Location = New-Object System.Drawing.Size(5,15)
	$objTextDonate.Size = New-Object System.Drawing.Size(960,20)
	$objTextDonate.Font = $FontMS
	#$objTextDonate.BackColor = 'red'
	$objTextDonate.Text = "More features will be added based on user requests. It is being tough work. If you like this project please donate."
	$TabSupport.Controls.Add($objTextDonate)
	
	$objTerms = New-Object System.Windows.Forms.RichTextBox
	$objTerms.Location = New-Object System.Drawing.Size(5,50)
	$objTerms.Font = $FontCalibri
	$objTerms.AcceptsTab = $true
	$objTerms.Multiline = $true
	$objTerms.ScrollBars = 'Both'
	$objTerms.Wordwrap = $True
	$objTerms.MaxLength = 32768
	$objTerms.ReadOnly = $true
	$objTerms.Text = @"
Terms and Conditions

Copyright $([char]169) 2019 PS-Solutions: https://ps-solutions.net

This program is free software; you can redistribute it and/or modify it under the terms of the GNU General Public License
as published by the Free Software Foundation.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty
of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
http://www.gnu.org/licenses/gpl-2.0.html
"@
	$TabSupport.Controls.Add($objTerms)
	
	$objTerms.Add_LinkClicked({[System.Diagnostics.Process]::Start($_.LinkText)})
	
	$objTerms.SelectionStart = 0
	$objTerms.SelectionLength = 1
	
	$objTerms.SelectionStart = $objTerms.Text.IndexOf('Terms')
	$objTerms.SelectionLength = 20
	$objTerms.SelectionFont = 'Calibri, 18.00pt, style=Bold'
	$objTerms.SelectionAlignment = 'center'
	
	$objTerms.SelectionStart = $objTerms.Text.IndexOf('GNU')
	$objTerms.SelectionLength = 26
	$objTerms.SelectionColor = 'DarkBlue'
	
	$objTerms.SelectionStart = $objTerms.Text.IndexOf('Free')
	$objTerms.SelectionLength = 24
	$objTerms.SelectionColor = 'DarkBlue'
	
	$objHLine = New-Object System.Windows.Forms.Label
	$objHLine.BackColor = 'black'
	$TabSupport.Controls.Add($objHLine)
	
	$objUpdateCheck = New-Object System.Windows.Forms.Button
	$objUpdateCheck.Size = New-Object System.Drawing.Size(180,40)
	$objUpdateCheck.Font = 'Courier New, 12.50pt, style=Bold'
	$objUpdateCheck.Text = "Check for Update"
	$objUpdateCheck.Add_Click({Invoke-Command -ScriptBlock $UpdateReport -ArgumentList "Info"})
	$TabSupport.Controls.Add($objUpdateCheck)
	
	$UpdateInfo.check = $objUpdateCheck
	
	$objUpdateFix = New-Object System.Windows.Forms.Button
	$objUpdateFix.Size = $objUpdateCheck.Size
	$objUpdateFix.Font = $objUpdateCheck.Font
	$objUpdateFix.ForeColor = 'Green'
	$objUpdateFix.Text = "Update Script"
	$objUpdateFix.Add_Click({Invoke-Command -ScriptBlock $UpdateReport -ArgumentList "Stable"})
	$TabSupport.Controls.Add($objUpdateFix)
	
	$UpdateInfo.stable = $objUpdateFix
	
	$objUpdateLog = New-Object System.Windows.Forms.RichTextBox
	$objUpdateLog.Font = 'Courier New, 13.00pt' #, style=Bold'
	$objUpdateLog.AcceptsTab = $true
	$objUpdateLog.Multiline = $true
	$objUpdateLog.ScrollBars = 'Both'
	$objUpdateLog.ReadOnly = $true
	$objUpdateLog.Wordwrap = $true
	$objUpdateLog.Text = "Log field for ongoing update or report."
	$objUpdateLog.Add_TextChanged({
		$objUpdateLog.SelectionStart = $objUpdateLog.Text.Length
		$objUpdateLog.ScrollToCaret()
	})
	$TabSupport.Controls.Add($objUpdateLog)
	
	$UpdateInfo.status = $objUpdateLog
	
	Invoke-Command -ScriptBlock $Resize
	
	#### End GUI Construction. Begin invoke. ####
	
	$RunButton.Add_Click({
		$objLinkFolder.Hide()
		$nItems = ($objListBox.Items | Measure-Object).count
		
		if (-not $nItems) {
			ShowEvent $true "`r`n`t Check list is empty. Add at least one computer."
			return $null
		}
		
		if ($objSendMail.Checked) {
			if(-not ($objSmtpServer.Text -and $objSmtpPort.Text -and $objFromAddress.Text -and $objToAddress.Text -and $objMailPass.Text)) {
				ShowEvent $true "`r`n`t Invalid mail options. Check for empty fields or wrong input format."
				return $null
			}
			
			if (($objFromAddress.Text.Trim() -match '[,;\s]') -or (-not ($objFromAddress.Text.Trim() -as [System.Net.Mail.MailAddress]))) {
				ShowEvent $true ("`r`n`t Invalid sender's mail address: " + $objFromAddress.Text.Trim())
				return $null
			}
			
			$mails = $objToAddress.Text -split '[,;\s]' -match '\S'
			$mailerr = $false
			if ($mails) {
				foreach ($mail in $mails) {
					if (-not ($mail -as [System.Net.Mail.MailAddress])) {
						ShowEvent $true ("`r`n`t Invalid recipient's mail address: " + $mail)
						$mailerr = $true
					}
				}
				
				if ($mailerr) { return $null }
			}
			
			if ([System.Uri]::CheckHostName($objSmtpServer.Text.Trim()) -eq 'Unknown') {
				ShowEvent $true ("`r`n`t Invalid SMTP host: " + $objSmtpServer.Text.Trim())
				return $null
			}
		}
		
		if ($objDomainUser.Checked) {
			$creds = $objUsername.Text.Split("\", 2)
			
			if ($creds.Count -ne 2) {
				ShowEvent $true "`r`n`t Wrong credentials format. Provide valid domain, username and password."
				return $null
			}
			
			if ($creds[0] -ne "." -and [System.Uri]::CheckHostName($creds[0]) -eq 'Unknown') {
				ShowEvent $true "`r`n`t Invalid domain name."
				return $null
			}
			if ($creds[1] -match "[\[\]\:\;\,\""\|\=\+\*\/\?\<\>\\]") {
				ShowEvent $true "`r`n`t Invalid username format."
				return $null
			}
			
			if (-not $objPassword.Text) {
				ShowEvent $true "`r`n`t Missing password."
				return $null
			}
		}
		
		if ($objSelectQueries.Text -eq '' -or $objHotFixDays.Text -eq '' -or $objTimeout.Text -eq '') {
			ShowEvent $true "`r`n`t Empty fields are not allowed. Check ""Parallel tasks"", ""Days back"" and ""Timeout""."
			return $null
		}
		
		$workdir = $fpath = $null
		
		if ($objOutFolder.Text -ne "<current script's folder>" -and [bool]$objOutFolder.Text.Trim()) { $workdir = $objOutFolder.Text }
		else { $workdir = $Script:ScriptPath }
		
		$workdir = Resolve-Path $workdir -ErrorAction SilentlyContinue -ErrorVariable fpath | Convert-Path
		
		if ($workdir) { }
		elseif ($fpath[0].Exception -like "*find path*") { $workdir = $fpath[0].TargetObject }
		else { ShowEvent $true "`r`n`t Invalid path format of output folder."; return $null }
		
		$wt = $workdir + "\~" + (Get-Date).ToFileTime() + ".tmp"
		New-Item $wt -ItemType File -Force -ErrorAction SilentlyContinue | Out-Null
		
		if (Test-Path $wt -PathType Leaf) {
			Remove-Item $wt -Force | Out-Null
			$sync.OutFile.Text = $workdir
		}
		else { ShowEvent $true "`r`n`t Insufficient permissions to output folder: $workdir"; return $null }
		
		$ScriptToken = $ScriptBase64 = $ScriptArguments = $ScriptExt = ''
		
		if ([bool]$optAddScript.Text.Trim() -and ($optAddScript.Text.Trim() -ne "<Type script up to 1MB>")){
			$ScriptToken = $objTokenScript.Text.Trim()
			$ScriptArguments = $argScript.Text.Trim()
			$ScriptExt = $objScriptExt.Text.Trim()
			
			$ScriptBinary = [System.Text.Encoding]::UTF8.GetBytes(($optAddScript.Text -replace "`n", "`r`n")) + [byte[]](@(13,10))
			if ($objBOM.Checked) { $ScriptBinary = [System.Text.Encoding]::UTF8.GetPreamble() + $ScriptBinary }
			
			if ($optScriptInvoke.Checked) {
				$ScriptBase64 = [System.Convert]::ToBase64String($ScriptBinary)
			}
			else {
				for ($i = $j = 0; $j -lt $ScriptBinary.Count; $i += 20480) {
					$j = $i + 20480 - 1
					if ($j -ge $ScriptBinary.Count) {
						$j = $ScriptBinary.Count - 1
						$ScriptBase64 += [System.Convert]::ToBase64String($ScriptBinary[$i..$j]) + ","
						break
					}
					
					$ScriptBase64 += [System.Convert]::ToBase64String($ScriptBinary[$i..$j]) + ","
				}
			}
		}
		
		if (($ScriptToken.ToCharArray() | Where-Object {$_ -eq """"} | Measure-Object).Count % 2 -eq 1) {
			ShowEvent $true "`r`n`t No closing quotes in Exec/Token"
			return $null
		}
		
		if (($ScriptToken.ToCharArray() | Where-Object {$_ -eq "'"} | Measure-Object).Count % 2 -eq 1) {
			ShowEvent $true "`r`n`t No closing quotes in Exec/Token"
			return $null
		}
		
		if (($ScriptArguments.ToCharArray() | Where-Object {$_ -eq """"} | Measure-Object).Count % 2 -eq 1) {
			ShowEvent $true "`r`n`t No closing quotes in Arguments"
			return $null
		}
		
		if (($ScriptArguments.ToCharArray() | Where-Object {$_ -eq "'"} | Measure-Object).Count % 2 -eq 1) {
			ShowEvent $true "`r`n`t No closing quotes in Arguments"
			return $null
		}
		
		$StopButton.Enabled = $true
		$RunButton.Enabled = $false
		$i = $sync.InstIndex
		Invoke-Expression -Command "`$sync.StopInst$i = `$sync.BtnRunInst$i = `$false; `$sync.BtnStopInst$i = `$true"
		
		ShowEvent $false "`r`n`t Preparing main script block..."
		
		if ($objDomainUser.Checked) {
			if ($objUsername.Text.Split("\")[0] -eq ".") { $UserName = "LOCALHOST\" + $objUsername.Text.Split("\")[1] }
			else { $UserName = $objUsername.Text }
			
			$Password = ConvertTo-SecureString $objPassword.Text -AsPlainText -Force
			$Cred = New-Object System.Management.Automation.PSCredential -ArgumentList $Username, $Password
		}
		else { $Cred = '' }
		
		$query = @{
			Computers = [string[]]$objListBox.Items
			Computer = ''
			Instance = $sync.InstIndex
			
			Domain = $objUsername.Text.Split("\")[0]
			WithCred = $objDomainUser.Checked
			Cred = $Cred
			NoCredVerify = $objNoCredsVerify.Checked
			LocalCred = $objUsername.Text.Split("\")[0] -eq "."
			Username = $objUsername.Text
			Password = $objPassword.Text
			
			HW = $objOptHW.Checked
			Device = $objOptDevice.Checked
			OS = $objOptOS.Checked
			LTime = $objOptLTime.Checked
			BTime = $objOptBTime.Checked
			UTime = $objOptUTime.Checked
			Hotfix = $objOptHotfix.Checked
			HotfixDays = $objHotFixDays.Text
			Reboot = $objOptReboot.Checked
			Service = $objOptService.Checked
			Cluster = $objOptCluster.Checked
			Disk = $objOptDisk.Checked
			SMB = $objOptSMB.Checked
			RDP = $objOptRDP.Checked
			
			Tasks = $objSelectQueries.Text
			Timeout = $objTimeout.Text
			RefreshTime = 3
			
			ScriptCMD = $optCMD.Checked
			ScriptWMI = $optScriptWMI.Checked
			
			ScriptToken = $ScriptToken -replace """", $("""" * 3)
			ScriptExt = $ScriptExt
			ScriptBase64 = $ScriptBase64
			ScriptArg = $ScriptArguments -replace """", $("""" * 3)
			
			OutFolder = $workdir
			Filename = $workdir + "\Report-" + (Get-Date).ToFileTime() + ".html"
			
			SendMail = $objSendMail.Checked
			MailUser = $objFromAddress.Text
			MailPass = $objMailPass.Text
			MailTo = $mails -join ', '
			SmtpServer = $objSmtpServer.Text
			SmtpPort = $objSmtpPort.Text
		}
		
		#### Reusable Runspace Reference: https://hinchley.net/articles/creating-a-windows-form-using-powershell-runspaces/
		
		$Instance = [PowerShell]::Create().AddScript($RunspaceCode).AddArgument($query)
		$Runspace = [RunspaceFactory]::CreateRunspace()
		$Runspace.ApartmentState = "STA"
		$Runspace.ThreadOptions = "ReuseThread"
		$Runspace.Open()
		$Runspace.SessionStateProxy.SetVariable("sync", $sync)
		
		$Instance.Runspace = $Runspace
		$Instance.BeginInvoke()
		
		$objLinkFolder.Show()
	})
}

#### Consolidate script block for selected instance and execute in a runspace. ####

$RunspaceCode = {
	Param ($query)
	$BeginTime = Get-Date
	$Timeout = $query.Timeout
	$nHosts = ($query.Computers | Measure-Object).count
	
	Function StopProcess([int]$i) {
		if ($i -eq 0 -and [System.Console]::KeyAvailable) {
			return (($Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')).VirtualKeyCode -eq 123)
		}
		else {
			Invoke-Expression -Command "return `$sync.StopInst$i"
		}
	}
	
	Function EnableButton([int]$i) {
		if ($i -ne 0) {
			Invoke-Expression -Command "`$sync.BtnRunInst$i = `$true; `$sync.BtnStopInst$i = `$false"
			
			if ($sync.InstIndex -eq $i) {
				$sync.RunButton.Enabled = $true
				$sync.StopButton.Enabled = $false
			}
		}
	}
	
	Function ShowLog ([int]$i, [bool]$append, [String]$text) {
		if ($i -eq 0) {
			if ($append) {
				Write-Host $text -NoNewline
			}
			else {
				Clear-Host
				Write-Host "`r`n`t Press F12 to terminate the script and wait 3 seconds for next cycle.`r`n" -ForegroundColor Yellow
				Write-Host $text -NoNewline
			}
		}
		else {
			Invoke-Expression -Command "if (`$append) {`$sync.Log$i.Text += `$text} else {`$sync.Log$i.Text = `$text}"
		}
	}
	
	if ($query.WithCred -and -not $query.NoCredVerify -and -not $query.LocalCred) {
		ShowLog $query.Instance $TRUE "`r`n`t Verifying domain credentials..."
		
		$Error.Clear()
		$context = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext("domain", $query.Domain, $query.UserName, $query.Password)
		Try { $DSTest = [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($context) } Catch {}
		
		if ($DSTest) {
			ShowLog $query.Instance $TRUE "`r`n`t Credentials are accepted."
		}
		elseif ($Error -like "*cannot be contacted*") {
			ShowLog $query.Instance $TRUE ("`r`n`t The specified domain does not exist or cannot be contacted. Try again with full domain name.`r`n`r`n" + [String]$Error)
			EnableButton $query.Instance
			return $null
		}
		elseif ($Error -like "*logon failure*") {
			ShowLog $query.Instance $TRUE ("`r`n`t Logon failure: Wrong user name or bad/expired password.`r`n`r`n" + [String]$Error)
			EnableButton $query.Instance
			return $null
		}
		else {
			ShowLog $query.Instance $TRUE ("`r`n`t Unknown error occured while verifying domain account:`r`n`r`n" + [String]$Error)
			EnableButton $query.Instance
			return $null
		}
	}
	
	if (StopProcess $query.Instance) {
		ShowLog $query.Instance $TRUE "`r`n`t Further execution is cancelled."
		EnableButton $query.Instance
		return $null
	}
	
	ShowLog $query.Instance $TRUE "`r`n`t Preparing jobs..."
	
	#### Build HTML file with JavaScript management buttons ####
	
	$NQ = [int]$query.HW + [int]$query.OS + [int]$query.LTime + [int]$query.BTime + [int]$query.UTime + [int]$query.Reboot + [int]$query.Hotfix + [int]$query.Service + `
		[int]$query.Cluster + [int]$query.Device + [int]$query.Disk + [int]$query.SMB + [int]$query.RDP + [int][bool]$query.ScriptBase64 + 4
	
	$HTML_MAIN = @"
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN"
"http://www.w3.org/TR/html4/strict.dtd">

<!--
HTML file generated by Powershell script SiRex.ps1 v1.09 Stable
Developer: PS-Solutions.net | support@ps-solutions.net
-->

<html>
<head>

<title>System Report</title>

<style type="text/css">
table {
	border-collapse: collapse;
	text-align: center;
}

td {
	font-family: "Trebuchet MS", Arial, Helvetica, sans-serif;
	font-size: 11px;
	color: #000;
	background-color: #FFF;
	border: 1px solid black;
	white-space: nowrap;
}

th {
	font-family: "Trebuchet MS", Arial, Helvetica, sans-serif;
	font-size: 13px;
	color: #FFF;
	background-color: #09F;
	border: 1px solid black;
	white-space: nowrap;
}

.bgyellow { background-color: #FF0 }

.HCInfoRed {
	color: #000;
	background-color: #FF4500;
}

.HCInfoTextRed {
	font-weight: bold;
	color: #FF0000;
}

.tooltip {
	position: relative;
	display: inline-block;
	border-bottom: 1px dotted black;
}

.tooltip .tooltiptext {
	visibility: hidden;
	width: 440px;
	background-color: #012456;
	color: white;
	text-align: left;
	border-radius: 6px;
	padding: 5px;
	position: absolute;
	z-index: 1;
	bottom: 150%;
	left: 50%;
	margin-left: -60px;
	opacity: 0;
	transition: opacity 0.3s;
	font-family:Lucida Console;
	white-space: normal;
}

.tooltip .tooltiptext::after {
	content: "";
	position: absolute;
	top: 100%;
	left: 15%;
	margin-left: -15px;
	border-width: 5px;
	border-style: solid;
	border-color: #555 transparent transparent transparent;
}

.tooltip:hover .tooltiptext {
	visibility: visible;
	opacity: 1;
}

.PsScript {
	font-size: 12px;
	text-align: left;
	background-color:#012456;
	color:white;
	white-space: pre-wrap;
	font-family:Lucida Console;
	overflow-x:scroll;
	overflow-y:scroll;
	padding: 5px;
}

.ScriptInfo {
	display: none;
	position: fixed;
	top: 5px;
	left: 5px;
	z-index: 9;
}

.form-popup {
	display: none;
	position: fixed;
	top: 30px;
	right: 60px;
	width: 365px;
	border: 3px solid #f1f1f1;
	z-index: 9;
}

.form-container {
	max-width: 1920;
	padding: 5px;
	background-color: white;
}

.form-container input[type=text], .form-container input[type=password] {
	width: 95%;
	padding: 10px;
	margin: 5px 0 5px 0;
	border: none;
	background: #f1f1f1;
}

.form-container input[type=text]:focus, .form-container input[type=password]:focus {
	background-color: #ddd;
	outline: none;
}

.form-container .btn {
	font-size: 16px;
	background-color: red;
	color: white;
	padding: 10px 20px;
	border: none;
	cursor: pointer;
	width: 100%;
	margin-top: 10px;
	opacity: 0.6;
}

.form-container .cancel { background-color: #4CAF50; }
.form-container .btn:hover, .open-button:hover { opacity: 1; }

</style>

<script type="text/javascript" language="javascript">

var login = username = password = Computer = "";
var firstrun = true;

function choice() {
	if (document.getElementById("localuser").checked) {
		document.getElementById("username").disabled = true;
		document.getElementById("password").disabled = true;
		
		username = document.getElementById("username").value;
		password = document.getElementById("password").value;
		document.getElementById("username").value = login;
		document.getElementById("password").value = "";
		document.getElementById("password").placeholder = "<session password>";
	}
	
	if (document.getElementById("domainuser").checked) {
		document.getElementById("username").disabled = false;
		document.getElementById("password").disabled = false;
		document.getElementById("username").value = username;
		document.getElementById("password").value = password;
		document.getElementById("password").placeholder = "Enter Password";
	}
}

function ShowPwd() {
	if (document.getElementById("password").type === "password") {
		document.getElementById("password").type = "text";
	}
	else { document.getElementById("password").type = "password"; }
}

function openForm(host) {
	var WinNetwork = new ActiveXObject("WScript.Network");
	login = WinNetwork.UserDomain + "\\" + WinNetwork.UserName;
	document.getElementById("myForm").style.display = "block";
	Computer = host;
	document.getElementById("hostinfo").innerHTML = "Following computer will be rebooted:\r\n <b><i>" + Computer + "</i></b>";
	
	if (firstrun) { firstrun = false; choice(); }
}

function closeForm() { document.getElementById("myForm").style.display = "none"; }

function RebootCreds() {
	var wShell = new ActiveXObject("wscript.shell");
	var seconds = document.getElementById("timeout").value;
	var comment = document.getElementById("comment").value;
	var username = document.getElementById("username").value;
	
	var valid = (username.match(new RegExp("\\\\", "g")) || []).length;
	var domain = username.substring(0, username.indexOf('\\'));
	var user = username.substring(username.indexOf('\\') + 1);
	username = username.replace(".\\", "LOCALHOST\\");
	pass = document.getElementById("password").value;
	
	if (document.getElementById("domainuser").checked) {
		if ((user == "") || (pass == "") || (domain == "") || (valid != 1)) { document.getElementById("error").innerHTML = "Invalid credentials format."; }
		else { document.getElementById("error").innerHTML = ""; }
		
		if (!document.getElementById("error").innerHTML) {
			var command = "cmd /c powershell.exe -ExecutionPolicy Bypass -NoLogo -NonInteractive -NoProfile -command \"";
			command += "Write-Host \"\"\" ``r``n Initiating reboot of computer " + Computer + " with account " + username + " . . . ``r``n \"\"\" -ForegroundColor Green; `$Error.Clear();";
			command += "`$pass = ConvertTo-SecureString \"" + pass + "\" -AsPlainText -Force;";
			command += "`$acc = New-Object System.Management.Automation.PSCredential -ArgumentList \"" + username + "\", " + "`$pass;";
			command += "`$comp = Get-WmiObject -Class Win32_OperatingSystem -Computer " + Computer + " -Property __CLASS -Credential `$acc;";
			command += "if(!`$Error) {`$comp.psbase.Scope.Options.EnablePrivileges = \`$true;";
			command += "`$comp.Win32ShutdownTracker(" + seconds + ", \'" + comment + "\', 0, 6)};";
			command += "if(!`$Error) {Write-Host \"\"\" ``r``n Reboot has been initiated successfully. ``r``n \"\"\" -ForegroundColor Green; ping " + Computer + " -t}";
			command += "else {Write-Host \"\"\" Reboot is not initiated. Check above errors. ``r``n \"\"\" -ForegroundColor Yellow};\" & pause";
			
			wShell.Run(command); closeForm();
		}
	}
	else {
		document.getElementById("error").innerHTML = "";
		var command = "cmd /c echo. & echo. Initiating reboot of computer " + Computer + " . . . & echo. & shutdown /r /f /m \\\\" + Computer + " /t " + seconds + " /c \"" + comment + "\" /d p:0:0" + " && ";
		command += "(echo Computer " + Computer + " has been rebooted. & ping " + Computer + " -t) & echo. & pause";
		
		if ((seconds == "") || (comment == "")) { document.getElementById("error").innerHTML = "Reason for reboot and timeout must be specified."; }
		else { wShell.Run(command); closeForm(); }
	}
}

function Explorer(Directory) {
	var wShell = new ActiveXObject("wscript.shell");
	wShell.Run("explorer " + Directory);
}

function Services(Computer) {
	var wShell = new ActiveXObject("wscript.shell");
	wShell.Run("services.msc /computer=" + Computer);
}

function RemoteDesktop(Computer) {
	var wShell = new ActiveXObject("wscript.shell");
	wShell.Run("mstsc /v:" + Computer);
}

function PingComputer(Computer) {
	var wShell = new ActiveXObject("wscript.shell");
	wShell.Run("cmd /c echo. & echo. Test connection to computer: " + Computer + " & echo. & ping " + Computer + " -t & echo. & pause");
}

function ShowScript(SID) {
	document.getElementById("ScriptText").innerHTML = document.getElementById(SID).innerHTML;
	document.getElementById("ScriptPopup").style.display = "block";
}

function ScriptClose() { document.getElementById("ScriptPopup").style.display = "none"; }

</script>
</head>

<body>

<div class="ScriptInfo" id="ScriptPopup">
	<form action="" class="form-container">
		<div class="PsScript" id="ScriptText"> </div>
		<button type="button" class="btn cancel" onclick="ScriptClose();" style="font-size:16px; text-align:center; padding:10px; width:300px;">Close</button>
	</form>
</div>

<div class="form-popup" id="myForm">
	<form action="" class="form-container">
		<div id="myFormheader" style="padding:5px; cursor:move; z-index:10; background-color:#2196F3; color:#fff;">Click here to move</div>
		<p id="hostinfo" style="font-size:16px; color:black; white-space:pre">Request form for reboot.</p>
		
		&nbsp; Reason for reboot:
		<input type="text" placeholder="Comment" id="comment" name="options" value="Maintenance">
		&nbsp; Timeout in seconds:
		<input type="text" placeholder="<digits only>" id="timeout" name="options" value="0" onkeypress='return event.charCode >= 48 && event.charCode <= 57'>
		
		<input type="radio" name="opt" value="" checked="checked" id="localuser" onchange="choice()"> Use Windows session credentials. <br> <br>
		<input type="radio" name="opt" value="" id="domainuser" onchange="choice()"> Reboot with credentials: <br>
		
		<input type="text" placeholder="domain\username  or  .\localadmin" id="username" name="psw">
		<input type="password" placeholder="Enter Password" id="password" name="psw">
		<input type="checkbox" onclick="ShowPwd()" id="checkbox"><i>Show Password</i>
		
		<p id="error" style="font-size:18px; color:red; white-space:pre"></p>
		
		<button type="button" class="btn" onclick="RebootCreds();">Reboot</button>
		<button type="button" class="btn cancel" onclick="closeForm();">Cancel</button>
	</form>
</div>

<script>
dragElement(document.getElementById("myForm"));

	function dragElement(elmnt) {
	var pos1 = 0, pos2 = 0, pos3 = 0, pos4 = 0;
	if (document.getElementById(elmnt.id + "header")) { document.getElementById(elmnt.id + "header").onmousedown = dragMouseDown; }
	else { elmnt.onmousedown = dragMouseDown; }

	function dragMouseDown(e) {
		e = e || window.event;
		e.preventDefault();
		pos3 = e.clientX;
		pos4 = e.clientY;
		document.onmouseup = closeDragElement;
		document.onmousemove = elementDrag;
	}

	function elementDrag(e) {
		if (elmnt.offsetTop < 0) { elmnt.style.top = "0px"; return 0; }
		if (elmnt.offsetLeft < 0) { elmnt.style.left = "0px"; return 0; }
		if (window.innerHeight - elmnt.offsetTop - elmnt.offsetHeight < 0) {elmnt.style.top = (window.innerHeight - elmnt.offsetHeight) + "px"; return 0; }
		if (window.innerWidth - elmnt.offsetLeft - elmnt.offsetWidth < 0) {elmnt.style.left = (window.innerWidth - elmnt.offsetWidth) + "px"; return 0; }
		
		e = e || window.event;
		e.preventDefault();
		pos1 = pos3 - e.clientX;
		pos2 = pos4 - e.clientY;
		
		pos3 = e.clientX;
		pos4 = e.clientY;
		elmnt.style.left = (elmnt.offsetLeft - pos1) + "px";
		elmnt.style.top = (elmnt.offsetTop - pos2) + "px";
	}

	function closeDragElement() { document.onmouseup = null; document.onmousemove = null; }
}

document.getElementsByTagName("BODY")[0].onresize = function() {
	var elmnt = document.getElementById("myForm");
	
	if (elmnt.offsetTop < 0) { elmnt.style.top = "0px"; }
	if (elmnt.offsetLeft < 0) { elmnt.style.left = "0px"; }
	if (window.innerHeight - elmnt.offsetTop - elmnt.offsetHeight < 0) {elmnt.style.top = (window.innerHeight - elmnt.offsetHeight) + "px";}
	if (window.innerWidth - elmnt.offsetLeft - elmnt.offsetWidth < 0) {elmnt.style.left = (window.innerWidth - elmnt.offsetWidth) + "px"; }
	
	var elmnt2 = document.getElementById("ScriptText");
	elmnt2.style.height = (window.innerHeight - 90) + "px";
	elmnt2.style.width = (window.innerWidth - 60) + "px";
	
	var elmnt3 = document.getElementById("ScriptPopup");
	elmnt3.style.height = (window.innerHeight) + "px";
	elmnt3.style.width = (window.innerWidth) + "px";
}

document.getElementById("ScriptText").style.height = (window.innerHeight - 90) + "px";
document.getElementById("ScriptText").style.width = (window.innerWidth - 60) + "px";

</script>

<table cellpadding="3">
  <tr>
	<th colspan="$NQ" scope="col">System Report. Total Computers: $nHosts </th>
  </tr>

  <tr>
	<th scope="col"> No. </th>
	<th scope="col"> Computer </th>

"@
	
	if ($query.HW) { $HTML_MAIN += "<th scope=""col""> Hardware </th> `r`n" }
	if ($query.OS) { $HTML_MAIN += "	<th scope=""col""> Operating System </th> `r`n" }
	if ($query.LTime) { $HTML_MAIN += "	<th scope=""col""> Local Time </th> `r`n" }
	if ($query.BTime) { $HTML_MAIN += "	<th scope=""col""> Boot Time </th> `r`n" }
	if ($query.UTime) { $HTML_MAIN += "	<th scope=""col""> Up Time </th> `r`n" }
	if ($query.Reboot) { $HTML_MAIN += "	<th scope=""col""> <div class=""tooltip""> RebootReq? <span class=""tooltiptext""> Check if installed hotfix requires reboot. </span></div> </th> `r`n" }
	if ($query.Hotfix) { $HTML_MAIN += "	<th scope=""col""> HotFixes $($query.HotfixDays) Days Back </th> `r`n" }
	if ($query.Cluster) { $HTML_MAIN += "	<th scope=""col""> <div class=""tooltip""> IsCluster? <span class=""tooltiptext""> Check if cluster service is present and get status. </span></div> </th> `r`n" }
	if ($query.Service) { $HTML_MAIN += "	<th scope=""col""> Services: Auto/Pending </th> `r`n" }
	if ($query.Device) { $HTML_MAIN += "	<th scope=""col""> Hardware Errors </th> `r`n" }
	if ($query.Disk) { $HTML_MAIN += "	<th scope=""col""> Freespace </th> `r`n" }
	if ($query.SMB) { $HTML_MAIN += "	<th scope=""col""> SMB </th> `r`n" }
	if ($query.RDP) { $HTML_MAIN += "	<th scope=""col""> RDP </th> `r`n" }
	if ([bool]$query.ScriptBase64) { $HTML_MAIN += "	<th scope=""col""> Script </th> `r`n" }
	$HTML_MAIN += "	<th scope=""col""> Ping </th> `r`n"
	
	$HTML_MAIN += "	<th scope=""col"">Administration</th>`r`n  </tr>`r`n`r`n"
	[System.IO.File]::WriteAllText($query.Filename, $HTML_MAIN, [System.Text.Encoding]::UTF8)
	
	Invoke-Expression -Command "`$sync.LinkFile$($query.Instance) = '$($query.Filename)'"
	
	if ($sync.InstIndex -eq $query.Instance) {
		$sync.OutFile.Text = $query.Filename
	}
	
	#### Prepare main script block for later execution ####
	
	$MainBlock = {
		Param($query)
		$step = 0
		$processes = 2 + [int]$query.HW + [int]($query.OS -or $query.LTime -or $query.BTime -or $query.UTime) + [int]$query.Reboot + [int]$query.Hotfix + `
			[int]($query.Service -or $query.Cluster) + [int]$query.Device + [int]$query.Disk + [int]$query.SMB + [int]$query.RDP + [int][bool]$query.ScriptBase64 + [int]($query.ScriptBase64 -and $query.ScriptWMI)
		
		$PID; "$step`/$processes"; "Start Point"
		
		$HCol = 1 + [int]$query.HW + [int]$query.OS + [int]$query.LTime + [int]$query.BTime + [int]$query.UTime + [int]$query.Reboot + [int]$query.Hotfix + `
			[int]$query.Service + [int]$query.Cluster + [int]$query.Device + [int]$query.Disk + [int]$query.SMB + [int]$query.RDP + [int][bool]$query.ScriptBase64
		
		[String]$HTML_Body = $Explorer = ''
		
		$Computer = $query.Computer
		$WithCred = $query.WithCred
		
		$JSButtons = {
			"    <td scope=col> `r`n"
			"      <button onclick=""Services('$Computer')""> Services </button> &nbsp; `r`n"
			
			if ($Explorer) { "      <button onclick=""Explorer('$Explorer')""> $HostName`: Explorer </button> <br> <br> `r`n" }
			else { "      $HostName`: No Explorer <br> <br> `r`n" }
			
			"      <button onclick=""RemoteDesktop('$Computer')""> RDP </button> &nbsp; `r`n"
			"      <button onclick=""PingComputer('$Computer')""> Ping -t </button> &nbsp; `r`n"
			"      <button onclick=""openForm('$Computer')""> Reboot... </button> </td> `r`n"
			"  </tr> `r`n`r`n"
		}
		
		#### Check DNS Record ####
		
		$step++; "$step`/$processes";  "DNS Record"
		
		[String]$DNSHostName = [String]$DnsIP = [String]$DNSAlias = ''
		
		if ($Computer -as [System.Net.IPAddress]) { $HostName = $Computer }
		else { $HostName = $Computer.Split('.')[0] }
		
		$Error.Clear()
		Try { $DNSResolution = [System.Net.Dns]::GetHostEntry($Computer) } Catch {}
		
		if ($Error) {
			if ($Computer -as [System.Net.IPAddress]) { $HostNetInfo = $Computer }
			else {	
				$HTML_Body += "    <td scope=col class=HCInfoRed> <div class=""tooltip""> $HostName <span class=""tooltiptext""> $Computer </span></div> </td> `r`n"
				$HTML_Body +=("    <td scope=col class=HCInfoRed> <div class=""tooltip""> DNS Error <span class=""tooltiptext""> $Error </span></div> </td> `r`n") * $HCol
				$HTML_Body += Invoke-Command -ScriptBlock $JSButtons
				
				Return $HTML_Body
			}
		}
		else {
			[String]$DNSHostName = $DNSResolution.HostName
			[String]$DnsIP = $DNSResolution.AddressList.IPAddressToString -join ', '
			
			if ($Computer -as [System.Net.IPAddress]) { [String]$DNSAlias = 'n/a' }
			else {
				If ($DNSHostName -ne $Computer) { [String]$DNSAlias = $Computer }
				else { [String]$DNSAlias = 'n/a' }
			}
			
			$HostNetInfo = "FQDN: " + $DNSHostName + "<br>IPs: " + $DnsIP + "<br>Alias: " + $DNSAlias
		}
		
		$HTML_Body += "    <td scope=col><div class=""tooltip""> $HostName <span class=""tooltiptext""> $HostNetInfo </span></div></td> `r`n"
		
		#### Test if computer responds to ping request ####
		
		if ($query.WithCred) {
			$Cred = $query.Cred
			
			if ($query.LocalCred) {
				$Error.Clear()
				Try { Get-WmiObject -Class Win32_TimeZone -ComputerName $Computer -Credential $Cred } Catch {}
				
				if ($Error) {
					if ($Error -like "*access*") { $CredError = "<div class=""tooltip""> Access Denied <span class=""tooltiptext""> $Error </span></div>" }
					elseif ($Error -like "*rpc*") { $CredError = "<div class=""tooltip""> RPC Error <span class=""tooltiptext""> $Error </span></div>" }
					else { $CredError = "<div class=""tooltip""> Unhandled Error <span class=""tooltiptext""> $Error </span></div>" }
					
					$HTML_Body += ("    <td scope=col class=HCInfoRed> $CredError </td> `r`n") * $HCol
					$HTML_Body += Invoke-Command -ScriptBlock $JSButtons
					$HTML_Body += "  </tr> `r`n`r`n"
					
					Return $HTML_Body
				}
			}
		}
		
		#### Get System Hardware Info ###
		
		if ($query.HW) {
			$step++; "$step`/$processes"; "HW Info"
			
			$System = $NULL
			$Error.Clear()
			Try {
				if ($WithCred) {
					$System = Get-WmiObject -Class Win32_ComputerSystemProduct -ComputerName $Computer -Credential $Cred -Property Vendor, Name, Version -ErrorAction SilentlyContinue
					$Bios = Get-WmiObject -Class Win32_BIOS -ComputerName $Computer -Credential $Cred -Property SerialNumber
				}
				else {
					$System = Get-WmiObject -Class Win32_ComputerSystemProduct -ComputerName $Computer -Property Vendor, Name, Version -ErrorAction SilentlyContinue
					$Bios = Get-WmiObject -Class Win32_BIOS -ComputerName $Computer -Property SerialNumber
				}
				### Class Win32_ComputerSystem has no Hardware Version property but includes: PartOfDomain, Domain, Workgroup
			} Catch {}
			
			if ($Error) {
				if ($Error -like "*access*") { $HWInfo = "<div class=""tooltip""> Access Denied <span class=""tooltiptext""> $Error </span></div>" }
				elseif ($Error -like "*rpc*") { $HWInfo = "<div class=""tooltip""> RPC Error <span class=""tooltiptext""> $Error </span></div>" }
				else { $HWInfo = "<div class=""tooltip""> Unhandled Error <span class=""tooltiptext""> $Error </span></div>" }
				
				$HTML_Body += "    <td class=HCInfoRed scope=col> $HWInfo </td> `r`n"
			}
			else {
				$HWInfo = "Vendor: " + $System.Vendor + " <br> Model: " + $System.Name + " <br> Version: " + $System.Version + " <br> BIOS S/N: " + $Bios.SerialNumber
				$HTML_Body += "    <td scope=col> $HWInfo </td> `r`n"
			}
		}
		
		#### Get OS Info and/or Local Date, Uptime ###
		
		if ($query.OS -or $query.LTime -or $query.BTime -or $query.UTime) {
			$step++; "$step`/$processes"; "OS Info"
			
			$Error.Clear()
			$System = $NULL
			
			$prop = ''
			if ($query.OS) { $prop = "Caption, OSArchitecture, ServicePackMajorVersion, ServicePackMinorVersion" }
			
			if ($query.LTime) {
				if ($prop -eq '') { $prop = "LocalDateTime" }
				else { $prop += ", LocalDateTime" }
			}
			
			if ($query.BTime) {
				if ($prop -eq '') { $prop = "LastBootUpTime" }
				else { $prop += ", LastBootUpTime" }
			}
			
			if ($query.UTime) {
				if ($prop -eq '') { $prop = "LocalDateTime, LastBootUpTime" }
				else { $prop += ", LocalDateTime, LastBootUpTime" }
			}
			
			Try {
				if ($WithCred) {
					$System = Get-WmiObject -Class Win32_OperatingSystem -ComputerName $Computer -Credential $Cred -Property $prop -ErrorAction SilentlyContinue
				}
				else {
					$System = Get-WmiObject -Class Win32_OperatingSystem -ComputerName $Computer -Property $prop -ErrorAction SilentlyContinue
				}
			} Catch {}
			
			if ($Error) {
				If ($Error -like "*access*") {
					$OSInfo = "<div class=""tooltip""> Access Denied <span class=""tooltiptext""> $Error </span></div>"
				}
				elseif ($Error -like "*rpc*") {
					$OSInfo = "<div class=""tooltip""> RPC Error <span class=""tooltiptext""> $Error </span></div>"
				}
				else {
					$OSInfo = "<div class=""tooltip""> Unhandled Error <span class=""tooltiptext""> $Error </span></div>"
				}
				
				if ($query.OS) { $HTML_Body += "    <td class=HCInfoRed scope=col> $OSInfo </td> `r`n" }
				if ($query.LTime) { $HTML_Body += "    <td class=HCInfoRed scope=col> $OSInfo </td> `r`n" }
				if ($query.BTime) { $HTML_Body += "    <td class=HCInfoRed scope=col> $OSInfo </td> `r`n" }
				if ($query.UTime) { $HTML_Body += "    <td class=HCInfoRed scope=col> $OSInfo </td> `r`n" }
			}
			else {
				if ($query.OS) {
					[String[]]$tmp_osinfo = $System.Caption.Split(" ")
					$OSInfo = [String]$tmp_osinfo[0..2] + "<br>" + $tmp_osinfo[3..($tmp_osinfo.Count - 1)] + " " + `
						$System.OSArchitecture + "<br>" + "Service Pack " + $System.ServicePackMajorVersion + "." + $System.ServicePackMinorVersion
					
					$HTML_Body += "    <td scope=col> $OSInfo </td> `r`n"
				}
				
				if ($query.LTime -or $query.UTime) {
						$LocalTime = $system.ConvertToDateTime($system.LocalDateTime).ToString("dd'/'MM'/'yyyy <br> HH':'mm':'ss")
						if ($query.LTime) { $HTML_Body += "    <td scope=col> $LocalTime </td> `r`n" }
					}
				
				if ($query.BTime -or $query.UTime) {
					$BootTime = $system.ConvertToDateTime($system.LastBootUpTime).ToString("dd'/'MM'/'yyyy <br> HH':'mm':'ss")
					if ($query.BTime) { $HTML_Body += "    <td scope=col> $BootTime </td> `r`n" }
				}
				
				if ($query.UTime) {
					$ut = $system.ConvertToDateTime($system.LocalDateTime) - $system.ConvertToDateTime($system.LastBootUpTime)
					$Uptime = [String]$ut.days + " Days <br>" + [String]$ut.Hours.ToString("00:") + [String]$ut.Minutes.ToString("00")
					
					if ($ut.days -gt 0) { $HTML_Body += "    <td class=bgyellow scope=col> $Uptime </td> `r`n" }
					else { $HTML_Body += "    <td scope=col> $Uptime </td> `r`n" }
				}
			}
		}
		
		#### Check if reboot is required related to installed HotFix ####
		
		if ($query.Reboot) {
			$step++; "$step`/$processes"; "Pend.Reboot"
			
			$WMI_Reg = $WUAUReboot = $RebootRequired = $NULL
			$Error.Clear()
			
			Try {
				if ($WithCred) { $WMI_Reg = Get-WmiObject -List StdRegProv -Namespace root\default -ComputerName $Computer -Credential $Cred -ErrorAction SilentlyContinue }
				else { $WMI_Reg = Get-WmiObject -List StdRegProv -Namespace root\default -ComputerName $Computer -ErrorAction SilentlyContinue }
			}	
			Catch {}
			
			if ($Error) {
				if ($Error -like "*access*") { $RebootRequired = "<div class=""tooltip""> Access Denied <span class=""tooltiptext""> $Error </span></div>" }
				elseif ($Error -like "*rpc*") { $RebootRequired = "<div class=""tooltip""> RPC Error <span class=""tooltiptext""> $Error </span></div>" }
				else { $RebootRequired = "<div class=""tooltip""> Unhandled Error <span class=""tooltiptext""> $Error </span></div>" }
				
				$HTML_Body += "    <td class=HCInfoRed scope=col> $RebootRequired </td> `r`n"
			}
			else {
				$HKLM = [UInt32] "0x80000002"
				$WUAUReboot = $WMI_Reg.EnumKey($HKLM,"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\")
				$RebootRequired = $WUAUReboot.sNames -contains "RebootRequired"
				
				if ($RebootRequired -match $True ) { $HTML_Body += "    <td class=bgyellow scope=col> YES </td> `r`n" }
				elseif ($RebootRequired -match $False ) { $HTML_Body += "    <td scope=col> no </td> `r`n" }
				else { $HTML_Body += "    <td class=bgyellow scope=col> No Info </td> `r`n" }
				
				#$WMI_Reg = [WMIClass] "\\$Computer\root\default:StdRegProv"
				#$WUAUReboot = $WMI_Reg.EnumKey($HKLM,"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\")
				#$RebootRequired = $WUAUReboot.sNames -contains "RebootRequired"
				
				#Get-Item "HKLM:SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired"
			}
		}
		
		#### Get Installed Hotfix ####
		
		if ($query.Hotfix) {
			$step++; "$step`/$processes"; "HotFix"
			
			$HotFix = $FilterHotFix = @()
			[String]$LastHotFix = ''
			$Error.Clear()
			
			Try {
				if ($WithCred) {
					$HotFix = Get-WmiObject -Class win32_reliabilityRecords -ComputerName $Computer -Credential $Cred `
						-Filter "sourcename = 'Microsoft-Windows-WindowsUpdateClient'" -Property TimeGenerated, Message -ErrorAction SilentlyContinue `
						| Where-Object {([regex]::Match($_.Message, 'KB\d{4,}')).Value} `
						| Select-Object @{LABEL = "Date"; EXPRESSION = {$_.ConvertToDateTime($_.timegenerated)}}, `
							@{LABEL = "HotFix"; EXPRESSION = {[String]([regex]::Match($_.Message, 'KB\d{4,}')).Value}}, `
							@{LABEL = "Status"; EXPRESSION = {$_.Message.Split(" :")[1]}}, `
							@{LABEL = "Message"; EXPRESSION = {$_.Message}} `
						| Sort-Object Date -Descending
				}
				else {
					$HotFix = Get-WmiObject -Class win32_reliabilityRecords -ComputerName $Computer `
						-Filter "sourcename = 'Microsoft-Windows-WindowsUpdateClient'" -Property TimeGenerated, Message -ErrorAction SilentlyContinue `
						| Where-Object {([regex]::Match($_.Message, 'KB\d{4,}')).Value} `
						| Select-Object @{LABEL = "Date"; EXPRESSION = {$_.ConvertToDateTime($_.timegenerated)}}, `
							@{LABEL = "HotFix"; EXPRESSION = {[String]([regex]::Match($_.Message, 'KB\d{4,}')).Value}}, `
							@{LABEL = "Status"; EXPRESSION = {$_.Message.Split(" :")[1]}}, `
							@{LABEL = "Message"; EXPRESSION = {$_.Message}} `
						| Sort-Object Date -Descending
				}
			} Catch {}
			
			if ($Error -like "*access*") {
				$LastHotFix = "<div class=""tooltip""> Access Denied <span class=""tooltiptext""> $Error </span></div>"
				$HTML_Body += "    <td class=HCInfoRed scope=col> $LastHotFix </td> `r`n"
			}
			elseif ($HotFix) {
				$FilterHotFix = $HotFix | Where-Object {$_.Date -ge (Get-Date).AddDays(- $query.HotfixDays)}
				
				if ($FilterHotFix) {
					$LastHotFix = $FilterHotFix | ForEach-Object { `
						if ($_.Status -ne "Successful") { "<div class=""tooltip""> <font color=""red"" style=""background-color:yellow"">" + $_.HotFix + $_.Date.ToString("' -' dd'/'MM'/'yyyy '- '") + $_.Status + "</font> <span class=""tooltiptext"">" + $_.Message + " </span></div>" + " <br> " }
						else { "<div class=""tooltip"">" + $_.HotFix + $_.Date.ToString("' -' dd'/'MM'/'yyyy '- '") + $_.Status + "<span class=""tooltiptext"">" + $_.Message + " </span></div>" + " <br> " } }
				}
				else {
					$LastHotFix = "No Info for last $($query.HotfixDays) days <br> Last 5 patches installed on: <br> "
					$LastHotFix += $HotFix | Select-Object -First 5 | ForEach-Object { `
						if ($_.Status -ne "Successful") { "<div class=""tooltip""> <font color=""red"">" + $_.HotFix + $_.Date.ToString("' -' dd'/'MM'/'yyyy '- '") + $_.Status + "</font> <span class=""tooltiptext"">" + $_.Message + " </span></div>" + " <br> " }
						else { "<div class=""tooltip"">" + $_.HotFix + $_.Date.ToString("' -' dd'/'MM'/'yyyy '- '") + $_.Status + "<span class=""tooltiptext"">" + $_.Message + " </span></div>" + " <br> " } }
				}
				
				if ($LastHotFix -like "*missing*" -or $LastHotFix -like "*info*") { $HTML_Body += "    <td class=bgyellow scope=col> $LastHotFix </td> `r`n" }
				else { $HTML_Body += "    <td scope=col> $LastHotFix </td> `r`n" }
			}
			else {
				$Error.Clear()
				$HotFix =@()
				
				Try {
					if ($WithCred) {
						$HotFix = Get-WmiObject -Class Win32_QuickFixEngineering -ComputerName $Computer -Credential $Cred -Property HotFixID, InstalledOn -ErrorAction SilentlyContinue | select HotFixID, `
							@{LABEL = "InstalledOn";EXPRESSION = {if ($_.InstalledOn -match '^[0-9A-Fa-f]+$') {[DateTime]::FromFiletime([Int64]::Parse([Convert]::ToInt64($_.InstalledOn,16)))} else {[DateTime]$_.InstalledOn}}}
					}
					else {
						$HotFix = Get-WmiObject -Class Win32_QuickFixEngineering -ComputerName $Computer -Property HotFixID, InstalledOn -ErrorAction SilentlyContinue | select HotFixID, `
							@{LABEL = "InstalledOn";EXPRESSION = {if ($_.InstalledOn -match '^[0-9A-Fa-f]+$') {[DateTime]::FromFiletime([Int64]::Parse([Convert]::ToInt64($_.InstalledOn,16)))} else {[DateTime]$_.InstalledOn}}}
					}
				}
				Catch {}
				
				if ($Error) {
					if ($Error -like "*access*") { $LastHotFix = "<div class=""tooltip""> Access Denied <span class=""tooltiptext""> $Error </span></div>" }
					elseif ($Error -like "*rpc*") { $LastHotFix = "<div class=""tooltip""> RPC Error <span class=""tooltiptext""> $Error </span></div>" }
					else { $LastHotFix = "<div class=""tooltip""> Unhandled Error <span class=""tooltiptext""> $Error </span></div>" }
				}
				elseif (-not $HotFix) {
					$LastHotFix = "No KB Info"
				}
				else {
					if ($HotFix[0].InstalledOn) { $DatePresent = $True } else { $DatePresent = $False }
					
					if ($DatePresent) {
						$FilterHotFix = $HotFix | Sort-Object InstalledOn -Descending | Where-Object {$_.InstalledOn -ge (Get-Date).AddDays(- $query.HotfixDays)}
						
						if ($FilterHotFix) { $LastHotFix = $FilterHotFix | ForEach-Object {
							
							$_.HotFixID + " - " + $_.InstalledOn.ToString("dd'/'MM'/'yyyy ") + " <br> "}
						}
						else {
							$LastHotFix = "No info for last $($query.HotfixDays) days <br> Last 5 patches installed on: <br> "
							$LastHotFix += $HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 5 | ForEach-Object {$_.HotFixID + " - " + $_.InstalledOn.ToString("dd'/'MM'/'yyyy ") + " <br> "}
						}
					}
					else {
						$LastHotFix = "Missing Install Date <br> Last 5 by HotFix ID: <br> "
						$LastHotFix += $HotFix | Sort-Object HotFixID -Descending | Select-Object -First 5 | Foreach-Object {$_.HotFixID + " <br> "}
					}
				}
				
				if (($LastHotFix -like "*error*") -or ($LastHotFix -like "*access*")) { $HTML_Body += "    <td class=HCInfoRed scope=col> $LastHotFix </td> `r`n" }
				elseif ($LastHotFix -like "*missing*" -or $LastHotFix -like "*info*") { $HTML_Body += "    <td class=bgyellow scope=col> $LastHotFix </td> `r`n" }
				else { $HTML_Body += "    <td scope=col> $LastHotFix </td> `r`n" }
			}
		}
		
		#### Check Automatic Service in Stopped or Any Other in Pending Status ####
		
		if ($query.Service -or $query.Cluster) {
			$step++; "$step`/$processes"; "Services"
			
			$AllServices = $Services = $ScReport = $ScError = $IsCluster = $ClInfo = @()
			$Error.Clear()
			
			Try {
				if ($WithCred) {
					$AllServices = Get-WmiObject Win32_Service -ComputerName $Computer -Credential $Cred -Property StartMode, State, DisplayName -ErrorAction SilentlyContinue
				}
				else {
					$AllServices = Get-WmiObject Win32_Service -ComputerName $Computer -Property StartMode, State, DisplayName -ErrorAction SilentlyContinue
				}
			} Catch {}
			
			if ($Error) {
				if ($Error -like "*access*") { $ScReport = "<div class=""tooltip""> Access Denied <span class=""tooltiptext""> $Error </span></div>" }
				elseif ($Error -like "*rpc*") { $ScReport = "<div class=""tooltip""> RPC Error <span class=""tooltiptext""> $Error </span></div>" }
				else { $ScReport = "<div class=""tooltip""> Unhandled Error <span class=""tooltiptext""> $Error </span></div>" }
				
				if ($query.Cluster) { $HTML_Body += "    <td class=HCInfoRed scope=col align=""center""> $ScReport </td> `r`n" }
				if ($query.Service) { $HTML_Body += "    <td class=HCInfoRed scope=col align=""center""> $ScReport </td> `r`n" }
			}
			else {
				$Services = $AllServices | Where-Object { [bool]$_.DisplayName -or [bool]$_.State -or [bool]$_.StartMode }
				$ScError = $Services | Where-Object { ($_.StartMode -eq "Auto" -and $_.State -ne "Running") -or ($_.State -ne "Stopped" -and $_.State -ne "Running") }
				
				if ($query.Cluster) {
					$IsCluster = $Services | Where-Object { $_.DisplayName -eq "Cluster Service" }
					
					if ($IsCluster) {
						$ClInfo = "YES<br>" + $IsCluster.StartMode + "<br>" + $IsCluster.State
						$HTML_Body += "    <td class=HCInfoTextRed scope=col> $ClInfo </td> `r`n"
					}
					else { $HTML_Body += "    <td scope=col> no </td> `r`n" }
				}
				
				if ($query.Service) {
					if (-not $ScError) { $ScReport = '' }
					else {
						$ScReport += $ScError | ForEach-Object {
							if ($_.State -ne "Stopped" -and $_.State -ne "Running") {
								"<font color=""red"" style=""background-color:yellow"">" + $_.DisplayName + " : " + $_.StartMode + " : " + $_.State + "</font> <br> "
							}
							else{
								$_.DisplayName + " : " + $_.StartMode + " : " + $_.State + " <br> "
							}
						}
					}
					
					$HTML_Body += "    <td scope=col align=""right""> $ScReport </td> `r`n"
				}
			}
		}
		
		#### Check for Errors in Device Manager ####
		
		if ($query.Device) {
			$step++; "$step`/$processes"; "Devices"
			
			$AllDevices = $ErrorDevices = $Devices = $NULL
			$Error.Clear()
			
			Try {
				if ($WithCred) {
					$AllDevices = Get-WmiObject CIM_LogicalDevice -ComputerName $Computer -Credential $Cred -Property Name, Status, ConfigManagerErrorCode -ErrorAction SilentlyContinue
				}
				else {
					$AllDevices = Get-WmiObject CIM_LogicalDevice -ComputerName $Computer -Property Name, Status, ConfigManagerErrorCode -ErrorAction SilentlyContinue
				}
			} Catch {}
			
			if ($Error) {
				if ($Error -like "*access*") { $Devices = "<div class=""tooltip""> Access Denied <span class=""tooltiptext""> $Error </span></div>" }
				elseif ($Error -like "*rpc*") { $Devices = "<div class=""tooltip""> RPC Error <span class=""tooltiptext""> $Error </span></div>" }
				else { $Devices = "<div class=""tooltip""> Unhandled Error <span class=""tooltiptext""> $Error </span></div>" }
				
				$HTML_Body += "    <td class=HCInfoRed scope=col> $Devices </td> `r`n"
			}
			else {
				### Check hardware deveices for errors. Disabled devices (ErrorCode=22) are excluded.
				$ErrorDevices = $AllDevices | Where-Object {[bool]$_.ConfigManagerErrorCode -and [int]$_.ConfigManagerErrorCode -ne 22}
				
				if (-not $ErrorDevices) { $Devices = '' }
				else { $Devices = $ErrorDevices | Foreach-Object {$_.Name + " : " + $_.Status + " : " + $_.ConfigManagerErrorCode + " <br> "} }
				
				$HTML_Body += "    <td scope=col> $Devices </td> `r`n"
			}
		}
		
		#### Check System Volume Free Space and SMB Test ####
		
		if ($query.Disk -or $query.SMB) {
			$step++; "$step`/$processes"; "Boot Volume"
			
			$prop = "BootVolume, DriveLetter, "
			if ($query.Disk) { $prop += "Capacity, FreeSpace" }
			
			$LogicalDisk = $PercentFree = $SystemDrive = $FreeSpace = $UNCPath = $Explorer = $NULL
			$Error.Clear()
			
			Try {
				if ($WithCred) {
					$LogicalDisk = Get-WmiObject Win32_Volume -Computername $Computer -Credential $Cred -Property $prop -ErrorAction SilentlyContinue | Where-Object { $_.BootVolume -eq $true }
				}
				else {
					$LogicalDisk = Get-WmiObject Win32_Volume -Computername $Computer -Property $prop -ErrorAction SilentlyContinue | Where-Object { $_.BootVolume -eq $true }
				}
			} Catch {}
			
			if ($Error) {
				$step += [int]$query.Disk + [int]$query.SMB
				
				if ($Error -like "*access*") { $LogicalDisk = "<div class=""tooltip""> Access Denied <span class=""tooltiptext""> $Error </span></div>" }
				elseif ($Error -like "*rpc*") { $LogicalDisk = "<div class=""tooltip""> RPC Error <span class=""tooltiptext""> $Error </span></div>" }
				else { $LogicalDisk = "<div class=""tooltip""> Unhandled Error <span class=""tooltiptext""> $Error </span></div>" }
				
				if ($query.Disk) { $HTML_Body += "    <td class=HCInfoRed scope=col> $LogicalDisk </td> `r`n" }
				if ($query.SMB) { $HTML_Body += "    <td class=bgyellow scope=col> No Info </td> `r`n" }
				
			}
			else {
				$SystemDrive = $LogicalDisk.DriveLetter.Split(':')[0]
				$Explorer = "\\\\" + $Computer + "\\" + $SystemDrive + "`$"
				
				if ($query.Disk) {
					[float]$PercentFree = [Math]::Round(100 * $LogicalDisk.FreeSpace / $LogicalDisk.Capacity , 2)
					$FreeSpace = [String][Math]::Round($LogicalDisk.FreeSpace / 1024 / 1024 / 1024 , 2) + " GB"
					
					if ($PercentFree -le 10) {$HTML_Body += "    <td class=HCInfoRed scope=col> $SystemDrive`: $FreeSpace<br> $PercentFree `% </td> `r`n" }
					else { $HTML_Body += "    <td scope=col> $SystemDrive`: $FreeSpace<br> $PercentFree `% </td> `r`n" }
				}
				
				if ($query.SMB) {
					if ($query.Disk -and $query.SMB) { $step++ }; "$step/$processes"; "SMB Test"
					
					$UNCPath = "\\$Computer\$SystemDrive`$"
					$NetUse = ''
					
					if ($WithCred) {
						[String]$NetUse = cmd /c NET USE 2>&1
						if ($NetUse -notlike "*$UNCPath*") {
							[String]$NetUse = cmd /c NET USE $UNCPath /USER:$($query.Username) $($query.Password) /PERSISTENT:NO 2>&1
							Start-Sleep 1
						}
					}
					
					if ($query.SMB) {
						if (Test-Path -Path $UNCPath) { $HTML_Body += "    <td scope=col> Passed </td> `r`n" }
						else { $HTML_Body += "    <td class=HCInfoRed scope=col> Failed </td> `r`n" }
					}
				}
			}
		}
		
		#### RDP Connection Test ####
		
		if ($query.RDP) {
			$step++; "$step/$processes"; "RDP Test"
			$Error.Clear()
			
			Try { $socket = New-Object Net.Sockets.TcpClient($Computer, 3389) } Catch {}
			
			if ($Error) { $HTML_Body += "    <td class=HCInfoRed scope=col> Failed </td> `r`n" }
			else {
				$HTML_Body += "    <td scope=col> Passed </td> `r`n" 
				$socket.Close()
			}
		}
		
		#### Execute Remote Script ####
		if ($query.ScriptBase64) {
			#### https://docs.microsoft.com/en-us/windows/desktop/wmisdk/connecting-to-wmi-on-a-remote-computer-by-using-powershell
			#### https://unit42.paloaltonetworks.com/unit42-pulling-back-the-curtains-on-encodedcommand-powershell-attacks/
			# New-EventLog LogName Application Source SiRex
			# Write-EventLog LogName Application Source My Script EntryType Information EventID 65535 Message This is a test message.
			#(48..57) + (65..90) + (97..122) | Get-Random -Count 64 | ForEach-Object {$ScriptID += [char]$_}
			
			Try {
				if ($WithCred) {
					$SystemDrive = (Get-WmiObject Win32_Volume -Computername $Computer -Credential $Cred -Property BootVolume, DriveLetter -ErrorAction SilentlyContinue | Where-Object { $_.BootVolume -eq $true }).DriveLetter.Split(':')[0]
				}
				else {
					$SystemDrive = (Get-WmiObject Win32_Volume -Computername $Computer -Property BootVolume, DriveLetter -ErrorAction SilentlyContinue | Where-Object { $_.BootVolume -eq $true }).DriveLetter.Split(':')[0]
				}
			} Catch {}
			
			$ScriptID = 'Host-' + $HostName + "_IID-" + (Get-Host).InstanceId
			$ScriptBase64 = $query.ScriptBase64 -split "," -match "\S"
			$ScriptToken = $query.ScriptToken
			$ScriptArguments = $query.ScriptArg
			
			if (-not [bool]$SystemDrive) {
				$SystemDrive = "&lt;SysVolume&gt;"
				$UNCPath = "\\$Computer\$SystemDrive"
			}
			
			if ($query.ScriptExt) {
				$Ext = $ScriptType = $query.ScriptExt
			}
			elseif ($query.ScriptCMD) {
				$Ext = "bat"
				$ScriptType = "CMD"
			}
			else {
				$Ext = "ps1"
				$ScriptType = "PS"
			}
			
			$FileName = (Get-Date).ToFileTime()
			$ScriptFile = "Temp\SiRex\$ScriptType-$FileName.$Ext"
			$ScriptLog = "Temp\SiRex\$ScriptType-$FileName.log"
			
			if ($query.ScriptWMI) {
				$step++; "$step/$processes"; "$ScriptType-WMI"
				$ExecMethod = "WMI Class Win32_Process"
			}
			else {
				$step++; "$step/$processes"; "$ScriptType-Invoke"
				$ExecMethod = "Cmdlet Invoke-Command"
			}
			
			if ($query.ScriptWMI) { #### Execution Method: Win32_Process
				$Result = "Computer: $Computer`r`nScript: $SystemDrive`:\$ScriptFile`r`nType: $ScriptType`r`nMethod: $ExecMethod`r`n`r`n"
				$Result += "Log file is expected in below location.`r`nLocal: $SystemDrive`:\$ScriptLog`r`n"
				$Result += "UNC: $UNCPath\$ScriptLog`r`n`r`n"
			
				if ($WithCred) {
					$Process = Get-WmiObject -ComputerName $Computer -Credential $Cred -Query "SELECT * FROM Meta_Class WHERE __Class = 'Win32_Process'" -namespace "root\cimv2" -Impersonation Impersonate
				}
				else {
					$Process = Get-WmiObject -ComputerName $Computer -Query "SELECT * FROM Meta_Class WHERE __Class = 'Win32_Process'" -namespace "root\cimv2" -Impersonation Impersonate
				}
				
				$Command = "powershell.exe -ExecutionPolicy Bypass -NoLogo -NonInteractive -NoProfile -WindowStyle Hidden -command """
				$Command += "New-Item `$Env:SystemDrive\$ScriptLog -ItemType File -Force;"
				$Command += "New-Item `$Env:SystemDrive\$ScriptFile -ItemType File -Force"
				$ExitCode = ($Process.Create($Command)).ReturnValue
				
				if ($ExitCode -eq 0) {
					for ($i = 0; $i -lt $ScriptBase64.Count; $i++ ) {
						$block = $ScriptBase64[$i]
						$length = $i * 20480
						
						$Command = "powershell.exe -ExecutionPolicy Bypass -NoLogo -NonInteractive -NoProfile -WindowStyle Hidden -command """
						$Command += "while ((Get-Item `$Env:SystemDrive\$ScriptFile).Length -ne $length -or [bool]`$Error) { Start-Sleep 1;`$Error.Clear() };"
						$Command += "`$a='[System.Convert]::FromBa';`$a+='se64String(''$block'')';iex `$a | Add-Content `$Env:SystemDrive\$ScriptFile -Encoding Byte"""
						
						$ExitCode = ($Process.Create($Command)).ReturnValue
						if ($ExitCode -ne 0) { break }
						Start-Sleep 1
					}
				}
				
				if ($ExitCode -eq 0) {
					$CMDLength = ($ScriptBase64.Count - 1) * 20480 + ([System.Convert]::FromBase64String(($ScriptBase64[-1]))).Count
					
					$Command = "powershell.exe -ExecutionPolicy Bypass -NoLogo -NonInteractive -NoProfile -WindowStyle Hidden -command "" Set-Location `$Env:SystemDrive\; "
					$Command += "[System.Console]::InputEncoding = [System.Console]::OutputEncoding = `$OutputEncoding = [System.Text.Encoding]::UTF8; `$Error.Clear();"
					$Command += "while ((Get-Item `$Env:SystemDrive\$ScriptFile).Length -ne $CMDLength -or [bool]`$Error) { Start-Sleep 1;`$Error.Clear() };"
					$Command += "cmd /c echo.>.\$ScriptFile:Zone.Identifier;"
					
					if ($query.ScriptCMD) {
						$Command += "((cmd /c $ScriptToken .\$ScriptFile $ScriptArguments 2>&1) | Out-String) -replace '&', '&amp;' -replace '<', '&lt;' -replace '>', '&gt;' "
					}
					else {
						$Command += "(($ScriptToken .\$ScriptFile $ScriptArguments) | Out-String) -replace '&', '&amp;' -replace '<', '&lt;' -replace '>', '&gt;' "
					}
					
					$Command += "| Add-Content `$Env:SystemDrive\$ScriptLog -Encoding UTF8;"
					$Command += "'<font color=' + [char]34 + 'red' + [char]34 + ' style=' + [char]34 + 'background-color:black;' + [char]34 + '>' + ((`$Error | Out-String) -replace '&', '&amp;' -replace '<', '&lt;' -replace '>', '&gt;') + '</font>' "
					$Command += "| Add-Content `$Env:SystemDrive\$ScriptLog -Encoding UTF8"""
					
					$p = $Process.Create($Command)
					$ExitCode = $p.ReturnValue
					$ProcessId = $p.ProcessId
				}
				
				switch ($ExitCode) {
					0 { $Result += "Exit Code: 0`r`nStatus: Successful completion" }
					2 { $Result += "Exit Code: 2`r`nStatus: Access denied" }
					3 { $Result += "Exit Code: 3`r`nStatus: Insufficient privilege" }
					8 { $Result += "Exit Code: 8`r`nStatus: Unknown failure" }
					9 { $Result += "Exit Code: 9`r`nStatus: Path not found" }
					21 { $Result += "Exit Code: 21`r`nStatus: Invalid parameter" }
					default { $Result += "Exit Code: $ExitCode`r`nStatus: Other &lt;Not defined&gt;" }
				}
				
				$Result += "`r`n`r`n"
				
				if ($ExitCode -ne 0) {
					$Result += "The script did not run due to internal failure.`r`n"
				}
				else {
					while ($true) {
						if ($WithCred) {
							$proc = Get-WmiObject Win32_Process -Computername $Computer -Credential $Cred -Property ProcessId -ErrorAction SilentlyContinue | Where-Object {$_.ProcessId -eq $ProcessId}
						}
						else {
							$proc = Get-WmiObject Win32_Process -Computername $Computer -Property ProcessId -ErrorAction SilentlyContinue | Where-Object {$_.ProcessId -eq $ProcessId}
						}
						
						if (-not $proc) {
							$Result += [System.IO.File]::ReadAllText("$UNCPath\$ScriptLog", [System.Text.Encoding]::UTF8)
							break
						}
						Start-Sleep 1
					}
				}
				#else {
				#	$Result += "Unable to get script output via SMB.`r`n"
				#}
				
				$HTML_Body +="<td class=col> <a href=""`#"" onclick=""ShowScript('$ScriptID');return false;"">$ScriptType-WMI</a> <div id=""$ScriptID"" style=""display:none;"">$Result</div></td>"
			}
			else { #### Execution Method: Cmdlet Invoke-Command
				[System.Console]::InputEncoding = [System.Console]::OutputEncoding = $OutputEncoding = [System.Text.Encoding]::UTF8
				$ScriptArguments = $ScriptArguments -replace """", $("""" * 2)
				$Error.Clear()
				
				$Command = "New-Item -Path `$Env:SystemDrive\Temp\SiRex -ItemType Directory -Force | Out-Null `r`n"
				$Command += "`$Bytes = [System.Convert]::FromBase64String('$ScriptBase64') `r`n"
				$Command += "cmd /c echo.>.\$ScriptFile:Zone.Identifier `r`n"
				$Command += "[System.IO.File]::WriteAllBytes(""`$Env:SystemDrive\$ScriptFile"", `$Bytes) `r`n"
				$Command += "`$OutputEncoding = [System.Text.Encoding]::UTF8; `$Error.Clear(); `r`n"
				$Command += "powershell.exe -ExecutionPolicy Bypass -command """
				$Command += "[System.Console]::InputEncoding = [System.Console]::OutputEncoding = ```$OutputEncoding = [System.Text.Encoding]::UTF8; ```$Error.Clear();"
				
				if ($query.ScriptCMD) {
					$Command += "((cmd /c $ScriptToken `$Env:SystemDrive\$ScriptFile $ScriptArguments 2>&1) | Out-String) "
				}
				else {
					$Command += "(($ScriptToken `$Env:SystemDrive\$ScriptFile $ScriptArguments) | Out-String) "
				}
				
				$Command += "| Add-Content `$Env:SystemDrive\$ScriptLog -Encoding UTF8;""`r`n"
				$Command += "[System.IO.File]::ReadAllLines(""`$Env:SystemDrive\$ScriptLog"", [System.Text.Encoding]::UTF8) | Out-String"
				
				if ($WithCred) {
					$Output += (Invoke-Command -ScriptBlock ([ScriptBlock]::Create($command)) -ComputerName $Computer -Credential $Cred) | Out-String
				}
				else {
					$Output += (Invoke-Command -ScriptBlock ([ScriptBlock]::Create($command)) -ComputerName $Computer) | Out-String
				}
				
				$Result = "Computer: $Computer`r`nType: $ScriptType`r`nMethod: $ExecMethod`r`n`r`n"
				$Result += $Output -replace '&', '&amp;' -replace '<', '&lt;' -replace '>', '&gt;' 
				
				if ($Error) { $Result += "<font color=""red"" style=""background-color:black;"">""" + ($Error | Out-String) + "</font>" }
				
				$HTML_Body +="<td class=col> <a href=""`#"" onclick=""ShowScript('$ScriptID');return false;"">$ScriptType-Invoke</a> <div id=""$ScriptID"" style=""display:none;"">$Result</div></td>"
			}
		}
		
		if ($NetUse -like "*completed successfully*") {	cmd /c NET USE $UNCPath /DELETE 2>&1 | Out-Null }
		
		$step++; "$step`/$processes"; "Ping Test"
		if (Test-Connection -ComputerName $Computer -Count 2 -TimeToLive 254 -Quiet) { $HTML_Body += "    <td scope=col> Passed </td> `r`n" }
		else { $HTML_Body += "    <td class=HCInfoRed scope=col> Failed </td> `r`n" }
		
		$HTML_Body + (Invoke-Command -ScriptBlock $JSButtons)
		
	}	#### End of main script block
	
	
	#### Multitasking: Schedule PS-Jobs ####
	
	$HTML_Timeout = {
		"  <tr class=HCInfo> `r`n"
		"    <td scope=col> $counter </td> `r`n"
		"    <td scope=col> <div class=""tooltip""> $HostName <span class=""tooltiptext""> $HostNetInfo </span></div> </td> `r`n"
		("    <td scope=col class=HCInfoRed> <div class=""tooltip""> Terminated <span class=""tooltiptext""> Terminated due to timeout of $Timeout minutes. </span></div> </td> `r`n") * ($NQ - 3)
		
		"    <td scope=col> `r`n"
		"      <button onclick=""Services('$Computer')""> Services </button> &nbsp; `r`n"
		
		"      $HostName`: No Explorer <br> <br> `r`n"
		"      <button onclick=""RemoteDesktop('$Computer')""> RDP </button> &nbsp; `r`n"
		"      <button onclick=""PingComputer('$Computer')""> Ping -t </button> &nbsp; `r`n"
		"      <button onclick=""openForm('$Computer')""> Reboot... </button> </td> `r`n"
		"  </tr> `r`n`r`n"
	}
	
	$JobArray = $JobStats = $EndedJobs = $RunJobs = $Jobs = @()
	$SrvIndex = $nHosts - 1
	$njobs = $counter = 0
	$i = -1
	
	while ($TRUE) {
		if (StopProcess $query.Instance) {
			ShowLog $query.Instance $TRUE ("`r`n`t Terminating all running jobs for Instance-" + $query.Instance  + " . . . ")
			if ($JobArray) { $JobArray | Remove-Job -Force }
			ShowLog $query.Instance $TRUE "Done.`r`n`t All jobs have been terminated."
			EnableButton $query.Instance
			return $null
		}
		
		if ($JobArray) { [int]$njobs = ($JobArray | Where-Object {(Get-Job -Id $_.Id).State -eq "Running"} | Measure-Object).Count }
		
		while ($i -lt $SrvIndex -and $njobs -lt $query.Tasks) {
			$query.Computer = $query.Computers[++$i]
			$JobArray += Start-Job -ScriptBlock $MainBlock -ArgumentList $query.Clone()
			
			$Date = Get-Date
			$JobStats += $JobArray[-1] | Select-Object Id, @{L="BeginTime"; E={$Date}}, @{L="Query"; E={[String]($i+1) + "/" + $nHosts}}, @{L="ComputerName"; E={$query.Computers[$i]}}
			
			$njobs++
		}
		
		$Date = Get-Date
		
		$Jobs = $JobProgress = $RunJobs = $FinishJobs = $TimeoutJob = @()
		
		$Jobs = $JobStats | Select-Object Id, Query, ComputerName, BeginTime, @{L="Status"; E={(Get-Job -Id $_.Id).State}}, `
			@{L="HasData"; E={(Get-Job -Id $_.Id).HasMoreData}}, @{L="Timer"; E={$Date - $_.BeginTime}}
		
		$RunJobs = $Jobs | Where-Object {$_.Status -eq "Running"}
		
		if ($RunJobs) {
			foreach ($run in $RunJobs) {
				$info = $NULL
				[String[]]$info = Receive-Job -Id $run.Id -Keep
				$timer = $run.Timer
				$runtime = $timer.Hours.ToString("00:") + $timer.Minutes.ToString("00:") + $timer.Seconds.ToString("00")
				
				if(($info | Measure-Object).Count -ge 3) {
					
					$JobProgress += New-Object -TypeName psobject -Property @{
						Id = $run.Id
						PID = if ($info[0] -match '^(\d{1,})+$') { $info[0] } else { 'n/a' }
						Query = $run.Query
						Status = $run.Status
						ComputerName = $run.ComputerName
						Steps = if ($info[-2] -match '(^\d{1,2})+(["/"])+(\d{1,2})+$') {$info[-2]} else { 'n/a' }
						Description = if ($info[-1] -notmatch "^[\s\<]" ) { $info[-1] } else { 'n/a' }
						RunTime = $runtime
					}
				}
				else {
					$JobProgress += New-Object -TypeName psobject -Property @{
						Id = $run.Id
						PID = 'n/a'
						Query = $run.Query
						Status = $run.Status
						ComputerName = $run.ComputerName
						Steps = 'n/a'
						Description = 'n/a'
						RunTime = $runtime
					}
				}
			}
		}
		
		if ($JobProgress) { ShowLog $query.Instance $FALSE (($JobProgress | Format-Table PID, Query, Status, ComputerName, Steps, Description, RunTime -Autosize | Out-String).Trim() + "`r`n") }
		
		$FinishJobs = $Jobs | Where-Object {$_.Status -eq "Completed" -and $_.HasData -match $true}
		
		if ($FinishJobs) {
			foreach ($job in $FinishJobs) {
				$timer = $job.Timer
				$runtime = $timer.Hours.ToString("00:") + $timer.Minutes.ToString("00:") + $timer.Seconds.ToString("00")
				
				$EndedJobs += $job | Select-Object Query, @{l="Status"; E={'Finish'}}, ComputerName, @{l="Steps"; E={"done"}}, @{l="Description"; E={"Completed"}}, @{l="TimeElapsed"; E={$runtime}}
				
				$counter++
				$HTML_Temp = "  <tr class=HCInfo> `r`n" + "    <td scope=col> $counter </td> `r`n" + (Receive-Job -Id $job.Id)[-1]
				[System.IO.File]::AppendAllText($query.Filename, $HTML_Temp, [System.Text.Encoding]::UTF8)
			}
		}
		
		if ($RunJobs) { $TimeoutJob = $RunJobs | Where-Object { ($Date - $_.BeginTime).TotalMinutes -gt $Timeout } | Select-Object -First 1 }
		
		if ($TimeoutJob) {
			$HostNetInfo = $Computer = $TimeoutJob.ComputerName.ToString()
			ShowLog $query.Instance $TRUE ("`r`n`t The specified timeout exceeds the threshold for computer: " + $Computer + "`r`n`t Terminating the job . . . ")
			Stop-Job -Id $TimeoutJob.Id
			
			$EndedJobs += $JobProgress | Where-Object {$TimeoutJob.Id -eq $_.Id} | Select-Object Query, @{L="Status"; E={"STOPED"}}, ComputerName, Steps, Description, @{l="TimeElapsed"; E={$_.RunTime}}
			
			if ([bool]($Computer -as [ipaddress])) { $HostName = $Computer }
			else { $HostName = $Computer.Split('.')[0] }
			
			$counter++
			[System.IO.File]::AppendAllText($query.Filename, $(Invoke-Command -ScriptBlock $HTML_Timeout), [System.Text.Encoding]::UTF8)
		}
		
		if (-not $RunJobs -and $i -eq $SrvIndex) {
			ShowLog $query.Instance $FALSE (($EndedJobs | Format-Table -Autosize | Out-String).Trim() + "`r`n")
			Break
		}
		
		Start-Sleep $query.RefreshTime
	}
	$JobArray | Remove-Job -Force
	
	ShowLog $query.Instance $TRUE "`r`nOutput file: $($query.Filename)`r`n"
	ShowLog $query.Instance $TRUE "`r`n`t Collecting Statistics . . . "
	
	$HTML_Temp = "</table> <br> <br> `r`n`r`n"
	$HTML_Temp += "<footer style=""font-family:Trebuchet MS, Arial, Helvetica, sans-serif; font-size:11px; text-align:left;"">`r`n`r`n"
	$HTML_Temp += "Generated by PowerShell script <a href=""https://ps-solutions.net/index.php/projects/sirex/"">SiRex.ps1</a> v1.09 Stable. Copyright <a href=""https://ps-solutions.net"">PS-Solutions.net</a> <br>`r`n"
	$HTML_Temp += "Powershell version: " + $PSVersionTable.PSVersion.ToString() + "<br>`r`n"
	$HTML_Temp += "Ran from computer: " + $env:COMPUTERNAME + "<br>`r`n"
	$HTML_Temp += "Ran by: " + [System.DirectoryServices.AccountManagement.UserPrincipal]::Current.DisplayName + "<br>`r`n"
	$HTML_Temp += "Login: " + $env:USERDOMAIN + '\' + $env:USERNAME + "<br>`r`n"
	
	if ($query.WithCred) { $HTML_Temp += "Ran with alternative credentials: " + $query.UserName + "<br>`r`n" }
	else { $HTML_Temp += "Ran with alternative credentials: no <br>`r`n" }
	
	$HTML_Temp += "Report generated on: " + $BeginTime.ToString("dd'/'MM'/'yyyy HH':'mm':'ss") + "<br>`r`n"
	$HTML_Temp += "Time Zone: " + [System.TimeZoneInfo]::Local.DisplayName.Split('()')[1] + "<br>`r`n"
	
	$EndTime = Get-Date
	$Elapsed = $EndTime - $BeginTime
	$FinishTime = "Elapsed time: " + $Elapsed.Days + " Days, " + $Elapsed.Hours.ToString("00:") + $Elapsed.Minutes.ToString("00:") + $Elapsed.Seconds.ToString("00") + "`r`n"
	
	$HTML_Temp += $FinishTime
	$HTML_Temp += "</footer> </body> </html>"
	[System.IO.File]::AppendAllText($query.Filename, $HTML_Temp, [System.Text.Encoding]::UTF8)
	
	Set-ItemProperty -Path $query.Filename -Name IsReadOnly -Value $true
	
	ShowLog $query.Instance $TRUE ("Completed.`r`n`t " + $FinishTime)
	
	if ($Error) { $Errors = ($Error | Out-String) + "`r`n"}
	else { $Errors = '' }
	
	#### Reference 1: https://stackoverflow.com/questions/11156452/powershell-scripting-an-email-from-exchange
	#### Reference 1: https://www.reddit.com/r/Office365/comments/4rhhqh/powershell_sentmailmessage_with_office_365/
	
	if ($query.SendMail) {
		if (StopProcess $query.Instance) {
			ShowLog $query.Instance $TRUE "`r`n`t Sending mail has been cancelled."
			EnableButton $query.Instance
			return $null
		}
		
		ShowLog $query.Instance $TRUE ("`r`n`t Sending e-mail...`r`n`t From: " + $query.MailUser + "`r`n`t To: " + $query.MailTo + "`r`n")
		
		$Error.Clear()
		if ($query.SmtpServer) {
			ShowLog $query.Instance $TRUE "`t SMTP: $($query.SmtpServer)`:$($query.SmtpPort) `r`n"
			
			$Message = New-Object System.Net.Mail.MailMessage
			$Message.From = $query.MailUser
			$Message.To.Add($query.MailTo)
			$Message.Subject = "System Report"
			$Message.IsBodyHtml = $true
			$Message.Body = "<p>System report has been sent from script SiRex.ps1 v1.09 Stable</p>"
			$Attachment = New-Object System.Net.Mail.Attachment($query.Filename, 'text/plain')
			$Message.Attachments.Add($Attachment)
			
			$Client = New-Object System.Net.Mail.SmtpClient($query.SmtpServer, $query.SmtpPort)
			$Client.Timeout = 66000
			$Client.EnableSsl = $true
			$Client.Credentials = New-Object System.Net.NetworkCredential($query.MailUser, $query.MailPass)
			Try { $Client.Send($Message) } Catch{}
			
			if ($Error) {
				$Errors += ($Error | Out-String) + "`r`n"
				ShowLog $query.Instance $TRUE ("`r`n`t Failure sending an e-mail. Check below errors:" + ($Error | ForEach-Object {"`r`n`r`n" + [String]$_}) )
			}
			else { ShowLog $query.Instance $TRUE "`r`n`t E-mail has been sent successfully.`r`n`t Check your mailbox whether the recipient's domain has rejected the message.`r`n" }
			
			$Message.Dispose()
			$Attachment.Dispose()
			$Client.Dispose()
		}
		else { ShowLog $query.Instance $TRUE "`r`n`t E-mail will not be sent due to unresolved SMTP server.`r`n" }
	}
	
	if ($Errors) {
		ShowLog $query.Instance $TRUE "`r`n`t WARNING: ERRORS FOUND. If below errors are internal report them to the dev.`r`n`r`n"
		ShowLog $query.Instance $TRUE $Errors
	}
	
	EnableButton $query.Instance
}

if ($CommandLine) {
	Invoke-Command -ScriptBlock $RunspaceCode -ArgumentList $query
}
else {
	Add-Type -Name Window -Namespace Console -MemberDefinition '
[DllImport("Kernel32.dll")]
public static extern IntPtr GetConsoleWindow();

[DllImport("user32.dll")]
public static extern bool ShowWindow(IntPtr hWnd, Int32 nCmdShow);
'
	$consolePtr = [Console.Window]::GetConsoleWindow()
	[void] [Console.Window]::ShowWindow($consolePtr, 0) #0 hide
	[void] $objForm.ShowDialog()
	[void] [Console.Window]::ShowWindow($consolePtr, 5) #5 show
}
