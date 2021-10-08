/*
//==================================
// AUTHOR       : Marco Todorov
// CREATE DATE  : 10/2/2021
// LAST MODIFIED: 10/7/2021
// PURPOSE      : Automate and simplify operations to secure Windows 10
// SPECIAL NOTES: Made for Cyberpatriot 2021
// VERSION      : 0.69.420
// ===============================
// TODO:
// Add Windows Defender settings
// Continue reg edit to sys tab
// Add system integrety scan in sys tab
// Set password requirements
// TOGGLE REMOTE DESKTOP
// Rename admin? rename guest?
// group policy is allowing modifications to the firewall
// Password policy
// AUDITING
// user rights?
// so many registry keys bruh
//==================================
*/

#SingleInstance Force
SetTitleMatchMode, 2
#NoEnv
SendMode Input
if not A_IsAdmin
	Run *RunAs "%A_ScriptFullPath%"

Gui,Add,Tab3,x10 y10 w300 h200 ,Hash||Users|System|   ;create a tab control
Gui,Color, c9c9c9
;#######################														HASH TAB
Gui,Tab,Hash   ; enter tab 1
Gui,Add, DropDownList, x20 y40 w70 vHASH, SHA1|SHA256|SHA384|SHA512|MD2|MD4|MD5
Gui,Add, Edit, x95 y40 w205 vhInput, File Directory
Gui,Add, Button, x19 y70 w281 gexportHash, Export
Gui,Add, Edit, x20 y100 w280 h100 vhOutput, Output
;#######################														USER TAB
Gui,Tab, 2 ; enter tab 2 by using its position in the list of tabs
Gui,Add, Edit, x20 y95 w280 h105 vuOutput, Output
Gui,Add,Button, x100 y39 genterAdmins, A
Gui,Add,Button, x120 y39 genterUsers, U
Gui,Add,Button, x141 y39 genterUsersAndAdmins, B
Gui,Add,Button, x165 y39 gviewAdmins, vA
Gui,Add,Button, x189 y39 gviewUsers, vU
Gui,Add,Button, x220 y39 guReset, Reset
Gui,Add,Button, x267 y39 guHelp, Help
Gui,Add,Button,x20 y65 grPass,Secure Passwords
Gui,Add,Button,x123 y65 grPerms,Set Perms
Gui,Add,Edit,x186 y66 w40 vnewUser
Gui,Add,Button,x230 y65 gCreateUser, Cu
Gui,Add,Button,x255 y65 gAddUserToUsers, Au
Gui,Add,Button,x280 y65 gAddUserToAdmins, Aa
Gui,Add,Button, x20 y40 w70 guAll, Exec All
;#######################														SYSTEM TAB
Gui,Tab, System ; enter tab 3
Gui,Add,text,x15 y190 w200 vscurrP,
Gui,Add,Button, x20 y40 w70 gsAll, Exec All
Gui,Add,Button, x20 y65 w70 gsFiles, Scan Files
Gui,Add,Button, x20 y90 w50 gsRDP, RDP
Gui,Add,Button, x70 y90 w20 gsoRDP,
Gui,Add,Button, x20 y115 w70 gsHost, Clear Hosts
Gui,Add,Button, x20 y140 w70 gsReg, Reg
Gui,Add,Button, x20 y165 w50 gsrReg, Rem Reg
Gui,Add,Button, x70 y165 w20 gsorReg,
Gui,Add,Button, x95 y40 w50 gsFeatures, R Feats
Gui,Add,Button, x145 y40 w20 gsoFeatures,
Gui,Add,Button, x95 y65 w70 gaUpdates, Auto Update
Gui,Add,Button, x95 y90 w70 gsIntegrity, Integrity
Gui,Add,Button, x95 y115 w70 gsFirewall, Firewall
Gui,Add,Button, x95 y140 w50 gsAudit, Audit
Gui,Add,Button, x145 y140 w20 goffAudit,
;#######################
Gui,Tab, ;exit the tabs
;Gui,Add,Text,x10 y220,bruh
Gui,Show,
return
;#######################														END OF WINDOW CONFIGURATION
;#######################														FUNCTIONS
exportHash:
	Gui, Submit
	runwait, %comspec% /k certutil -hashfile "%hInput%" %HASH% >> C:\hashTemp.txt & exit
	FileReadLine, hFinalOutput, C:\hashTemp.txt, 2
	GuiControl,,hOutput,%hFinalOutput%
	FileDelete, C:\hashTemp.txt
	Gui,Show,
return
sAll:
	findFiles()
	RDP()
	Host()
	Reg()
	remReg()
	dsblFeatures()
	autoUpdates()
	Firewall()
	Integrity()
	GuiControl,,scurrP, All Functions Executed
return

sorReg:
	GuiControl,,scurrP, Remote Registry On
	runwait, %comspec% /k net start RemoteRegistry & exit
	runwait, %comspec% /k sc config RemoteRegistry start=enabled & exit
	GuiControl,,scurrP,
return

sAudit:
	audit()
return

offAudit:
	runwait, %comspec% /k auditpol /set /category:* /success:disable
	runwait, %comspec% /k auditpol /set /category:* /failure:disable
return
soRDP:
	GuiControl,,scurrP, Enabling Remote Desktop Connection 
	RegWrite, REG_DWORD, HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server, fDenyTSConnections, 0
	RegWrite, REG_DWORD, HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server, AllowTSConnections, 1
	RegWrite, REG_DWORD, HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server, fAllowToGetHelp, 1
	RegWrite, REG_DWORD, HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp, UserAuthentication, 1
	runwait, %comspec% /k netsh advfirewall firewall set service type = remotedesktop mode = enable & exit
	runwait, %comspec% /k netsh advfirewall firewall set rule group="remote desktop" new enable=yes
	run, SystemPropertiesRemote.exe
	GuiControl,,scurrP,
return
sFirewall:
	Firewall()
return
sIntegrity:
	Integrity()
return
aUpdates:
	autoUpdates()
return
sFeatures:
	dsblFeatures()
return
srReg:
	remReg()
return
sReg:
	Reg()
return
sHost:
	Host()
return
sRDP:
	RDP()
return
sFiles:
	findFiles()
return
uReset:
	FileDelete, C:\tempAdminList.txt
	FileDelete, C:\tempUserList.txt
	GuiControl,,uOutput, User list and Admin list cleared
return
CreateUser:
	Gui, Submit
	s := SubStr(newUser,1,1)"ABCxyz" . 0 . Chr(0x0021)
	StringLen, l, newUser
	runwait, %comspec% /k net user %newUser% %s%%l% /add & exit
return
AddUserToUsers:
	Gui, Submit
	runwait, %comspec% /k net localgroup Users %newUser% /add & exit
return
AddUserToAdmins:
	Gui, Submit
	runwait, %comspec% /k net localgroup Administrators %newUser% /add & exit
return
uAll:
	IfNotExist, C:\tempUserList.txt
			IfNotExist, C:\tempAdminList.txt
				MsgBox, You must enter the authorized Users and Admins.
				Exit
	setSecurePasswords()
	setCorrectPermissions()
	GuiControl,,uOutput, Passwords have been secured`nCorrect permissions applied`nUnauthorized users removed
return
rPass:
	setSecurePasswords()
return
rPerms:
	setCorrectPermissions()
return
enterAdmins:
	clipboard := clipboard 
	FileAppend, %clipboard%`n, C:\tempAdminList.txt
	FileRead, admins, C:\tempAdminList.txt
	GuiControl,,uOutput,%admins%
	Gui,Show,
return
enterUsers:
	clipboard := clipboard 
	FileAppend, %clipboard%`n, C:\tempUserList.txt
	FileRead, users, C:\tempUserList.txt
	GuiControl,,uOutput,%users%
	Gui,Show,
return
enterUsersAndAdmins:
	clipboard := clipboard 
	FileAppend, %clipboard%`n, C:\tempUserList.txt
	FileAppend, %clipboard%`n, C:\tempAdminList.txt
return
viewAdmins:
	FileRead, admins, C:\tempAdminList.txt
	GuiControl,,uOutput,%admins%
	Gui,Show,
return
viewUsers:
	FileRead, users, C:\tempUserList.txt
	GuiControl,,uOutput,%users%
	Gui,Show,
return
uHelp:
	msgbox, A = Add clipboard to Admin list (this is rarely used)`nU = Add clipboard to User list`nB = Add clipboard to both lists`nvA = View Admin list`nvU = View User list`nReset = Resets values in the Admins and Users list`nCu = Create new user`nAu = Add user in small textbox to user group`nAa = Add user in small text box to admin group
return
parseREADME(Needle) { ;doesn't fucking work
	FileRead, readme, %input%
	return RegExReplace(readme, ".*?" Needle, "")
}


setSecurePasswords() {
	sLoops := usersLoop()
	Loop, %sLoops%
	{
	FileReadLine, user, C:\usersTemp.txt, 1
	user := RTrim(user)
	count += 1
	newPass := SubStr(user,1,1)"ABCxyz"count . 0 . Chr(0x0021)
	FileAppend, %user% : %newPass%`n, %A_ScriptDir%\userPassList.txt
	runwait, %comspec% /k net user "%user%" %newPass% & exit
	runwait, powershell -Command "(gc C:\usersTemp.txt | select -Skip 1) | sc C:\usersTemp.txt"
	}
	runwait, %comspec% /k del C:\usersTemp.txt & exit
	FileRead, userPassList, %A_ScriptDir%\userPassList.txt
	GuiControl,,uOutput,%userPassList%
return
}

setCorrectPermissions() {
	IfNotExist, C:\tempUserList.txt
		IfNotExist, C:\tempAdminList.txt
			MsgBox, You must enter the authorized Users and Admins.
			Exit
	pLoops := usersLoop()
	Loop, %pLoops%
	{
	FileReadLine, pUser, C:\usersTemp.txt, 1
	FileRead, pAdmins, C:\tempAdminList.txt
	FileRead, pUsers, C:\tempUserList.txt
	isAdmin := InStr(pAdmins, pUser, true)
	isUser := InStr(pUsers, pUser, true)
	pUser := RTrim(pUser)
	if (pUser != "Administrator") && (pUser != "Guest") && (pUser != "WDAGUtilityAccount") && (pUser != "DefaultAccount")
	{
		if (isAdmin = 0) ; if user is not a authorized admin
		{
		runwait, %comspec% /k net localgroup Administrators %pUser% /delete & exit
		runwait, %comspec% /k net localgroup Users %pUser% /add & exit
		}
		else if (isAdmin > 0) ; if user is a authorized admin
		{
		runwait, %comspec% /k net localgroup Administrators %pUser% /add & exit
		runwait, %comspec% /k net localgroup Users %pUser% /delete & exit
		}
		If (isUser = 0) ; if user is not an authorized user
		{
		runwait, %comspec% /k net user %pUser% /active:no & exit
		}
	}
	runwait, powershell -Command "(gc C:\usersTemp.txt | select -Skip 1) | sc C:\usersTemp.txt"
	}
	return
}

usersLoop() {
	Runwait, PowerShell.exe get-localuser | Select-Object Name | Out-File -FilePath C:\temp.txt | powershell -NoProfile -Command "Get-Content -Path C:\temp.txt | Select-Object -Skip 3" | Out-File -FilePath C:\usersTemp.txt | powershell Remove-Item C:\temp.txt
	Loop, Read, C:\usersTemp.txt 
	{
	totalLines = %A_Index%
	}
	totalLines -= 2
	return %totalLines%
}

findFiles() {
	GuiControl,,scurrP, Finding Bad Files
	FileRemoveDir, %A_Desktop%\ScannedFiles, 1
	FileCreateDir, %A_Desktop%\ScannedFiles
	audio := "mp3,ac3,aac,aiff,flac,m4a,m4p,midi,mp2,m3u,ogg,vqf,wav"
	videos := "wma,mp4,avi,mpeg4,webm"
	images := "jpeg,jpg,bmp,png,gif,pdf"
	htools = hashcat,Cain,nmap,keyloggerArmitage,Metasploit,Shellter
	excludeDir = AppData,C:\Windows,C:\Program Files,C:\CyberPatriot,ProgramData,thumbnails
	Loop Files, C:\*, FR  ; Recurse into subfolders.
	{
		If A_LoopFileLongPath contains %excludeDir%
			continue
		else if A_LoopFileExt in %images%
			FileAppend, %A_LoopFileFullPath%`n, %A_Desktop%\ScannedFiles\images.txt
		else if A_LoopFileExt in %audio%
			FileAppend, %A_LoopFileFullPath%`n, %A_Desktop%\ScannedFiles\audio.txt
		else if A_LoopFileExt in %videos%
			FileAppend, %A_LoopFileFullPath%`n, %A_Desktop%\ScannedFiles\videos.txt
		else if A_LoopFileName contains %htools%
			FileAppend, %A_LoopFileFullPath%`n, %A_Desktop%\ScannedFiles\htools.txt
	}
	GuiControl,,scurrP,
}

RDP() {
	GuiControl,,scurrP, Disabling Remote Desktop Connection 
	RegWrite, REG_DWORD, HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server, fDenyTSConnections, 1
	RegWrite, REG_DWORD, HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server, AllowTSConnections, 0
	RegWrite, REG_DWORD, HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server, fAllowToGetHelp, 0
	RegWrite, REG_DWORD, HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp, UserAuthentication, 0
	runwait, %comspec% /k netsh advfirewall firewall set service type = remotedesktop mode = disable & exit
	runwait, %comspec% /k netsh advfirewall firewall set rule group="remote desktop" new enable=no
	GuiControl,,scurrP,
}

Host() {
	GuiControl,,scurrP, Editing Host Files
	runwait, %comspec% /k ipconfig /flushdns & exit
	fileRead, host, C:\Windows\System32\drivers\etc\hosts
	file := FileOpen("C:\Windows\System32\drivers\etc\hosts", "w")
	file.close()
	FileSetAttrib, +SR, C:\Windows\System32\drivers\etc\hosts
	GuiControl,,scurrP,
}

remReg() {
	GuiControl,,scurrP, Remote Registry Off
	runwait, %comspec% /k net stop RemoteRegistry & exit
	runwait, %comspec% /k sc config RemoteRegistry start=disabled & exit
	GuiControl,,scurrP,
}

autoUpdates() {
	GuiControl,,scurrP, Enabling Auto Updates
	RegWrite, REG_DWORD, HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update, AUOptions, 3
	Run ms-settings:windowsupdate-action
	WinWait, Settings
	WinMinimize
	GuiControl,,scurrP,
}

Integrity() {
	GuiControl,,scurrP, Scanning System Integrity
	run, %comspec% /k sfc.exe /scannow
}

Firewall() {
	GuiControl,,scurrP, Enabling Firewall
	eFirewall =
	(join&
	NetSh Advfirewall set allprofiles state on
	netsh advfirewall firewall set rule name="Remote Assistance (RA Server TCP-In)" new enable=no 
	netsh advfirewall firewall set rule name="netcat" new enable=no
	netsh advfirewall firewall set rule name="Remote Assistance (SSDP UDP-In)" new enable=no 
	netsh advfirewall firewall set rule name="Remote Assistance (TCP-In)" new enable=no 
	netsh advfirewall firewall set rule name="Telnet Server" new enable=no 
	netsh advfirewall firewall set rule name="Remote Assistance (DCOM-In)" new enable=no 
	netsh advfirewall firewall set rule name="Remote Assistance (PNRP-In)" new enable=no 
	netsh advfirewall firewall set rule name="Remote Assistance (SSDP TCP-In)" new enable=no 
	exit
	)
	runwait, %comspec% /k %eFirewall%
	GuiControl,,scurrP,
}
Reg() {
	GuiControl,,scurrP, Editing Registry Values
	RegWrite, REG_DWORD, HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System, EnableLUA, 1 ; UNFINISHED A TON LOOOOL DOGSHIT
	
	GuiControl,,scurrP,
}
audit() {
	runwait, %comspec% /k auditpol /set /category:* /success:enable
	runwait, %comspec% /k auditpol /set /category:* /failure:enable
}

soFeatures:
	GuiControl,,scurrP, Enabling Features
	oFeatures =
	(
	dism /online /enable-feature /featurename:IIS-WebServerRole
	dism /online /enable-feature /featurename:IIS-WebServer
	dism /online /enable-feature /featurename:IIS-CommonHttpFeatures
	dism /online /enable-feature /featurename:IIS-HttpErrors
	dism /online /enable-feature /featurename:IIS-HttpRedirect
	dism /online /enable-feature /featurename:IIS-ApplicationDevelopment
	dism /online /enable-feature /featurename:IIS-NetFxExtensibility
	dism /online /enable-feature /featurename:IIS-NetFxExtensibility45
	dism /online /enable-feature /featurename:IIS-HealthAndDiagnostics
	dism /online /enable-feature /featurename:IIS-HttpLogging
	dism /online /enable-feature /featurename:IIS-LoggingLibraries
	dism /online /enable-feature /featurename:IIS-RequestMonitor
	dism /online /enable-feature /featurename:IIS-HttpTracing
	dism /online /enable-feature /featurename:IIS-Security
	dism /online /enable-feature /featurename:IIS-URLAuthorization
	dism /online /enable-feature /featurename:IIS-RequestFiltering
	dism /online /enable-feature /featurename:IIS-IPSecurity
	dism /online /enable-feature /featurename:IIS-Performance
	dism /online /enable-feature /featurename:IIS-HttpCompressionDynamic
	dism /online /enable-feature /featurename:IIS-WebServerManagementTools
	dism /online /enable-feature /featurename:IIS-ManagementScriptingTools
	dism /online /enable-feature /featurename:IIS-IIS6ManagementCompatibility
	dism /online /enable-feature /featurename:IIS-Metabase
	dism /online /enable-feature /featurename:IIS-HostableWebCore
	dism /online /enable-feature /featurename:IIS-StaticContent
	dism /online /enable-feature /featurename:IIS-DefaultDocument
	dism /online /enable-feature /featurename:IIS-DirectoryBrowsing
	dism /online /enable-feature /featurename:IIS-WebDAV
	dism /online /enable-feature /featurename:IIS-WebSockets
	dism /online /enable-feature /featurename:IIS-ApplicationInit
	dism /online /enable-feature /featurename:IIS-ASPNET
	dism /online /enable-feature /featurename:IIS-ASPNET45
	dism /online /enable-feature /featurename:IIS-ASP
	dism /online /enable-feature /featurename:IIS-CGI
	dism /online /enable-feature /featurename:IIS-ISAPIExtensions
	dism /online /enable-feature /featurename:IIS-ISAPIFilter
	dism /online /enable-feature /featurename:IIS-ServerSideIncludes
	dism /online /enable-feature /featurename:IIS-CustomLogging
	dism /online /enable-feature /featurename:IIS-BasicAuthentication
	dism /online /enable-feature /featurename:IIS-HttpCompressionStatic
	dism /online /enable-feature /featurename:IIS-ManagementConsole
	dism /online /enable-feature /featurename:IIS-ManagementService
	dism /online /enable-feature /featurename:IIS-WMICompatibility
	dism /online /enable-feature /featurename:IIS-LegacyScripts
	dism /online /enable-feature /featurename:IIS-LegacySnapIn
	dism /online /enable-feature /featurename:IIS-FTPServer
	dism /online /enable-feature /featurename:IIS-FTPSvc
	dism /online /enable-feature /featurename:IIS-FTPExtensibility
	dism /online /enable-feature /featurename:TFTP
	dism /online /enable-feature /featurename:TelnetClient
	dism /online /enable-feature /featurename:TelnetServer
	exit
	)
	runwait, %comspec% /k %oFeatures%
	GuiControl,,scurrP,
return

dsblFeatures() {
	GuiControl,,scurrP, Disabling Weak Services
	batfeats =
	(join&
	dism /online /disable-feature /featurename:IIS-WebServerRole
	dism /online /disable-feature /featurename:IIS-WebServer
	dism /online /disable-feature /featurename:IIS-CommonHttpFeatures
	dism /online /disable-feature /featurename:IIS-HttpErrors
	dism /online /disable-feature /featurename:IIS-HttpRedirect
	dism /online /disable-feature /featurename:IIS-ApplicationDevelopment
	dism /online /disable-feature /featurename:IIS-NetFxExtensibility
	dism /online /disable-feature /featurename:IIS-NetFxExtensibility45
	dism /online /disable-feature /featurename:IIS-HealthAndDiagnostics
	dism /online /disable-feature /featurename:IIS-HttpLogging
	dism /online /disable-feature /featurename:IIS-LoggingLibraries
	dism /online /disable-feature /featurename:IIS-RequestMonitor
	dism /online /disable-feature /featurename:IIS-HttpTracing
	dism /online /disable-feature /featurename:IIS-Security
	dism /online /disable-feature /featurename:IIS-URLAuthorization
	dism /online /disable-feature /featurename:IIS-RequestFiltering
	dism /online /disable-feature /featurename:IIS-IPSecurity
	dism /online /disable-feature /featurename:IIS-Performance
	dism /online /disable-feature /featurename:IIS-HttpCompressionDynamic
	dism /online /disable-feature /featurename:IIS-WebServerManagementTools
	dism /online /disable-feature /featurename:IIS-ManagementScriptingTools
	dism /online /disable-feature /featurename:IIS-IIS6ManagementCompatibility
	dism /online /disable-feature /featurename:IIS-Metabase
	dism /online /disable-feature /featurename:IIS-HostableWebCore
	dism /online /disable-feature /featurename:IIS-StaticContent
	dism /online /disable-feature /featurename:IIS-DefaultDocument
	dism /online /disable-feature /featurename:IIS-DirectoryBrowsing
	dism /online /disable-feature /featurename:IIS-WebDAV
	dism /online /disable-feature /featurename:IIS-WebSockets
	dism /online /disable-feature /featurename:IIS-ApplicationInit
	dism /online /disable-feature /featurename:IIS-ASPNET
	dism /online /disable-feature /featurename:IIS-ASPNET45
	dism /online /disable-feature /featurename:IIS-ASP
	dism /online /disable-feature /featurename:IIS-CGI
	dism /online /disable-feature /featurename:IIS-ISAPIExtensions
	dism /online /disable-feature /featurename:IIS-ISAPIFilter
	dism /online /disable-feature /featurename:IIS-ServerSideIncludes
	dism /online /disable-feature /featurename:IIS-CustomLogging
	dism /online /disable-feature /featurename:IIS-BasicAuthentication
	dism /online /disable-feature /featurename:IIS-HttpCompressionStatic
	dism /online /disable-feature /featurename:IIS-ManagementConsole
	dism /online /disable-feature /featurename:IIS-ManagementService
	dism /online /disable-feature /featurename:IIS-WMICompatibility
	dism /online /disable-feature /featurename:IIS-LegacyScripts
	dism /online /disable-feature /featurename:IIS-LegacySnapIn
	dism /online /disable-feature /featurename:IIS-FTPServer
	dism /online /disable-feature /featurename:IIS-FTPSvc
	dism /online /disable-feature /featurename:IIS-FTPExtensibility
	dism /online /disable-feature /featurename:TFTP
	dism /online /disable-feature /featurename:TelnetClient
	dism /online /disable-feature /featurename:TelnetServer
	exit
	)
	runwait, %comspec% /k %batfeats%
	GuiControl,,scurrP,
}

guiClose:
	FileDelete, C:\tempAdminList.txt
	FileDelete, C:\tempUserList.txt
	FileDelete, C:\usersTemp.txt
	ExitApp