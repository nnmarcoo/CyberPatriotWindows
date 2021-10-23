/*
//==================================
// AUTHOR       : Marco Todorov
// CREATE DATE  : 10/2/2021
// LAST MODIFIED: 10/12/2021
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
SetWorkingDir, %A_Desktop%
SetTitleMatchMode, 2
#NoEnv
SendMode Input
if not A_IsAdmin
	Run *RunAs "%A_ScriptFullPath%"
htools = npcap,hashcat,Cain,nmap,keylogger,Armitage,Metasploit,Shellter,arp-scan,h0trace,hamap,hbraa,henum4linux,hike-scan,hintrace,hirpas,hlbd,hmaltego,hmasscan,hrecon-ng,hsslyze,hswaks,hunicornscan,hismtp,hpython3-shodan,hemailharvester,hinstaloader,hinspy,hsherlock,hcertgraph,hnmapsi4,hafl,hgvm,hinviteflood,hohrwurm,hprotos-sip,hrtpbreak,hrtpflood,hrtpinsertsound,hrtpmixsound,hsipp,hslowhttptest,hspike,hvoiphopper,hsiparmyknife,hsctpscan,hcisco-ocs,hcisco-torch,hcopy-router-config,hburpsuite,hgobuster,hpadbuster,hwfuzz,hwig,hwafw00f,hparsero,harmitage,hbeef-xss,hcommix,hjsql-injection,hmdbtools,hpompem,hshellnoob,hsidguesser,hunicorn-magic,hbackdoor-factory,hncat-w32,hhyperion,hshellter,hsslh,hstunnel4,hwindows-binaries,hmimikatz,hpassing-the-hash,hxspy,hlinux-exploit-suggesterhbrutespray,hcewl,hchangeme,hcmospwd,hhashid,hhydra,hjohnny,hpack,honesixtyone,hophcrack,hpdfcrack,hpipal,hrarcrack,hrcracki-mt,hrsmangler,hsamdump2,hsucrack,hthc-pptp-bruter,htwofi,hwordlists,hdevice-pharmer,hstatsprocessor,hairgeddon,hbluelog,hblueranger,hbluesnarfer,hbtscanner,hbluez-hcidump,hcrackle,hfern-wifi-cracker,hhackrf,hinspectrum,hking-phisher,hmfcuk,hmfoc,hmfterm,hlibfreefare-bin,hlibnfc-bin,hpixiewps,hredfang,hrfcat,hrtlsdr-scanner,hubertooth,hwifite,hbettercap,hchaosreader,hdarkstat,hsniffjoke,htcpflow,hdriftnet,hetherape,hfiked,hhamster-sidejack,hnetsniff-ng,hrebind,hresponder,hsslsplit,htcpreplay,hwifi-honey,hafflib-tools,hdumpzilla,hcabextract,hautopsy,hbinwalk,hsleuthkit,hewf-tools,hextundelete,hgtkhash,hhashdeep,hmagicrescue,hmissidentify,hpasco,hpdf-parser,hpdfid,hpev,hrecoverjpeg,hregripper,hrifiuti,hrifiuti2,hscrounge-ntfs,hvinetto,hxplico,hinetsim,hforensic-artifacts,hgalleta,hgpp-decrypt,hguymager,hsmartmontools,hyara,hcan-utils,hparrot-meta-sdr,hgscanbus,hclang,hdex2jar,hedb-debugger,hgdb,hjavasnoop,hrizin,hrizin-cutter,heyewitness,hfaraday-cli,hfaraday,hparrot-tools,hparrot-tools-info,hparrot-tools-vuln,hparrot-tools-web,hparrot-tools-pwn,hparrot-tools-maintain,hparrot-tools-postexploit,hparrot-tools-password,hparrot-tools-wireless,hparrot-tools-sniff,hparrot-tools-forensic,hparrot-tools-automotive,hparrot-tools-reversing,hparrot-tools-report,hparrot-crypto,hvokoscreen,hngrep,hnetsed,hosslsigncode,harpwatch,hvlan,hnginx,hdnsmap,hhashcat,hmetasploit-framework,hmiredo-server,hncrack,hnikto,hophcrack-cli,hcrackmapexec,hrainbowcrack,hset,htcpdump,htruecrack,hbeef-xss [amd64 i386],hsaidar,hhexinjecthaircrack-ng,harping,hasleap,hdoona,hbully,hchntpw,hcowpatty,hcreddump7,hcrunch,hcymothoa,hdavtest,hdc3dd,hdcfldd,hddrescue,hdhcpig,hdirb,hdirbuster,hdmitry,hdns2tcp,hdnschef,hdnsenum,hdnsrecon,hdnstracer,hdnswalk,hdos2unix,hdsniff,heapmd5pass,henumiax,hethtool,hettercap-graphical,hfcrackzip,hferret,hfierce,hforemost,hfping,hhexinject,hhping3,hhtshells,hiaxflood,himpacket-scripts,hiodine,hisr-evilgrade,hjohn,hjoomscan,hlaudanum,hlibnet1-dev,hlibpcap-dev,hlinks,hlynis,hmaskprocessor,hmdk3,hmedusa,hmiredo,hmitmproxy,hnasm,hnbtscan,hnetdiscover,hnishang,hnmap,hopenssh-server,hoscanner,houtguess,hp0f,hpayloadsallthethings,hpowercat,hpowersploit,hproxychains,hproxytunnel,hptunnel,hpwnat,hreaver,hreglookup,hrig,hsafecopy,hsbd,hscalpel,hsfuzz,hshellinabox,hsiege,hsipcrack,hsipvicious,hskipfish,hsmbmap,hsmbclient,hsmtp-user-enum,hsnmpcheck,hsocat,hspiderfoot,hsqldict,hsqlmap,hssldump,hsslscan,hsslsniff,hsteghide,ht50,htcpxtract,htcpick,htlssled,htcptrace,hthc-ipv6,hthc-ssl-dos,htheharvester,hthemole,htraceroute,hwhois,hudptunnel,hunix-privesc-check,hwce,hwebacoo,hwebshells,hwebsploit,hweevely,hwhatweb,hwireshark,hetherwake,hwpscan,hxprobe,hxsser,hyersinia,hzaproxy,hzulucrypt,hftester,hsmali,hgeany,hsoundmodem,hminimodem
Gui,Add,Tab3,x10 y10 w300 h200 ,Hash||Users|System|Forensics|Auto| ;create a tab control
Gui,Color, c9c9c9
Gui,+AlwaysOnTop
;Gui +Resize
;#######################														HASH TAB
Gui,Tab,Hash   ; enter tab 1
Gui,Add, DropDownList, x20 y40 w70 vHASH, SHA1|SHA256|SHA384|SHA512|MD2|MD4|MD5
Gui,Add, Edit, x95 y40 w205 vhInput, File Directory
Gui,Add, Button, x19 y70 w281 gexportHash, Export
Gui,Add, Edit, x20 y100 w280 h100 vhOutput, Output
;#######################														USER TAB
Gui,Tab, 2 ; enter tab 2 by using its position in the list of tabs
Gui,Add, Edit, x20 y165 w280 h40 vuOutput, Output
Gui,Add, Edit, x20 y95 w135 h65 vuAdmins, Admins
Gui,Add, Edit, x165 y95 w135 h65 vuUsers, Users
Gui,Add,Button,x20 y65 grPass,Secure Passwords
Gui,Add,Button,x123 y65 grPerms,Set Perms
Gui,Add,Edit,x186 y66 w40 vnewUser
Gui,Add,Button,x230 y65 gCreateUser, Cu
Gui,Add,Button,x255 y65 gAddUserToUsers, Au
Gui,Add,Button,x280 y65 gAddUserToAdmins, Aa
Gui,Add,Button, x20 y40 w70 guAll, Exec All
Gui,Add,Checkbox, x95 y45 vuManual, m
;#######################														SYSTEM TAB
Gui,Tab, System ; enter tab 3
Gui,Add,text,x15 y190 w200 vscurrP,
Gui,Add,Button, x20 y40 w70 gsAll, Exec All
Gui,Add,Button, x20 y65 w70 gsFiles, Scan Files
Gui,Add,Button, x20 y90 w50 gsRDP, RDP
Gui,Add,Button, x70 y90 w20 gsoRDP,
Gui,Add,Button, x20 y115 w70 gsHost, Clear Hosts
Gui,Add,Button, x20 y140 w70 gsReg, Reg
Gui,Add,Button, x20 y165 w50 gsrReg, R Reg
Gui,Add,Button, x70 y165 w20 gsorReg,
Gui,Add,Button, x95 y40 w50 gsFeatures, R Feats
Gui,Add,Button, x145 y40 w20 gsoFeatures,
Gui,Add,Button, x95 y65 w70 gaUpdates, Auto Update
Gui,Add,Button, x95 y90 w70 gsIntegrity, Integrity
Gui,Add,Button, x95 y115 w70 gsFirewall, Firewall
Gui,Add,Button, x95 y140 w50 gsAudit, Audit
Gui,Add,Button, x145 y140 w20 goffAudit,
Gui,Add,Button, x95 y165 w70 gsPower, Power
Gui,Add,Button, x170 y40 w70 gspPolicy, Pass policy
Gui,Add,Button, x170 y65 w70 gsPrograms, Scan Progs
;#######################
Gui,Tab, Forensics
Gui,Add,Button, x20 y40 w70 gaForensics, Attempt Forensics
;#######################
Gui,Tab,Auto
Gui,Font, s30
Gui,Add,Button, x20 y40 w280 h160 gLOLOLO, BRUH
Gui,Font, s8
;#######################
Gui,Tab, ;exit the tabs
Gui,Font, s9
Gui,Add,Text, x5 y225 w200 vWorkgroup,
Gui,Font, s7
Gui,Add,Text, x5 y210, Workgroup:
Gui,Add,Button,x260 y215 gFeats,Opt. Feats
Gui,Add,Button,x220 y215 gInt,Internet
Gui,Add,Button,x190 y215 gmmc,mmc
Gui,Add,Link,x160 y215,<a href="https://cryptii.com/">Cryptii</a>
runwait, %comspec% /k systeminfo | findstr /B "Domain" >> C:\tempWorkgroup.txt & exit
FileReadLine, tWorkgroup, C:\tempWorkgroup.txt, 1
tWorkgroup := LTrim(tWorkgroup, "Domain:")
tWorkgroup := LTrim(tWorkgroup)
GuiControl,,Workgroup,%tWorkgroup%
gui,show,
Gui, +LastFound ; make the GUI the Last Found Window
WinGetPos,,, GUIWidth ; find out the width of the gui window
WinGetPos,,,, GUIHeight ; find out the height of the gui window
GuiXPos := A_ScreenWidth - GUIWidth ; find out where it should be placed based on window size and current resolution of screen
GuiYPos := (A_ScreenHeight - GUIHeight)-50
WinMove,,, %GuiXPos%, %GuiYPos% ; move the window
return
;#######################														END OF WINDOW CONFIGURATION
;#######################														FUNCTIONS

mmc:
run %comspec% /k mmc & exit,,hide
return
exportHash:
	Gui, Submit, NoHide
	runwait, %comspec% /k certutil -hashfile "%hInput%" %HASH% >> C:\hashTemp.txt & exit
	FileReadLine, hFinalOutput, C:\hashTemp.txt, 2
	GuiControl,,hOutput,%hFinalOutput%
	FileDelete, C:\hashTemp.txt
return
sAll:
	Integrity()
	findFiles()
	dsblFeatures()
	scanPrograms()
	RDP()
	Host()
	pPolicy()
	Reg()
	remReg()
	autoUpdates()
	Firewall()
	sPwr()
	audit()
	GuiControl,,scurrP, All Functions Executed
return

Feats:
	run %comspec% /k optionalfeatures & exit
return
Int:
	run %comspec% /k inetcpl.cpl & exit
return
aForensics:
	forensics()
return

LOLOLO:
	MsgBox, 4, , BRUH?, 3
	IfMsgBox Timeout
		return
	else IfMsgBox No
		return
	setSecurePasswords()
	setCorrectPermissions(uAdmins, uUsers, uManual)
	findFiles()
	dsblFeatures()
	scanPrograms()
	RDP()
	Host()
	pPolicy()
	Reg()
	remReg()
	autoUpdates()
	Firewall()
	audit()
	sPwr()
	Integrity()
return

spPolicy:
	pPolicy()
return

sPrograms:
	scanPrograms()
Return

sPower:
	sPwr()
return

sorReg:
	GuiControl,,scurrP, Remote Registry On
	runwait, %comspec% /k net start RemoteRegistry & exit
	runwait, %comspec% /k sc config RemoteRegistry start=enabled & exit
	GuiControl,,scurrP, Done!
return

sAudit:
	audit()
return

offAudit:
	runwait, %comspec% /k auditpol /set /category:* /success:disable & exit
	runwait, %comspec% /k auditpol /set /category:* /failure:disable & exit
	GuiControl,,scurrP, Done!
return
soRDP:
	GuiControl,,scurrP, Enabling Remote Desktop Connection 
	RegWrite, REG_DWORD, HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server, fDenyTSConnections, 0
	RegWrite, REG_DWORD, HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server, AllowTSConnections, 1
	RegWrite, REG_DWORD, HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server, fAllowToGetHelp, 1
	RegWrite, REG_DWORD, HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp, UserAuthentication, 1
	runwait, %comspec% /k netsh advfirewall firewall set service type = remotedesktop mode = enable & exit
	runwait, %comspec% /k netsh advfirewall firewall set rule group="remote desktop" new enable=yes & exit
	run, SystemPropertiesRemote.exe
	GuiControl,,scurrP, Done!
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
	Gui, Submit, NoHide
	s := SubStr(newUser,1,1)"ABCxyz" . 0 . Chr(0x0021)
	StringLen, l, newUser
	runwait, %comspec% /k net user %newUser% %s%%l% /add & exit
return
AddUserToUsers:
	Gui, Submit, NoHide
	runwait, %comspec% /k net localgroup Users %newUser% /add & exit
return
AddUserToAdmins:
	Gui, Submit, NoHide
	runwait, %comspec% /k net localgroup Administrators %newUser% /add & exit
return
uAll: ; LITERALLY USELESS
	setSecurePasswords()
	setCorrectPermissions(uAdmins, uUsers, uManual)
	GuiControl,,uOutput, Passwords have been secured`nCorrect permissions applied`nUnauthorized users removed
return
rPass:
	setSecurePasswords()
return
rPerms:
	Gui, Submit, NoHide
	setCorrectPermissions(uAdmins, uUsers, uManual)
return

forensics() { ;untested probably doesn't work at all lol
	global tWorkgroup
	workgroup = This computer is a member of what Windows Workgroup?
	elevation = The Windows Elevation of Privilege vulnerability identified in CVE-2021-36934  
	cipher = The key used to encrypt the file is
	fcount = 1
	While fcount < 4
	{
	FileRead, forensic, %A_Desktop%\Forensics Question %fcount%.txt
	forensic := SubStr(forensic, InStr(forensic, "==============================================================================="), -1)
	
	IfInString, forensic, %workgroup% ; IS IT ASKING FOR THE WORKGROUP?
	{
		;removeLastThree(fcount)
		FileAppend, ANSWER: %tWorkgroup%, %A_Desktop%\Forensics Question %fcount%.txt
	}
	
	IfInString, forensic, %elevation% ; IS IT ASKING FOR THE CVE-2021-36934 EXPLOIT?
	{
		;removeLastThree(fcount)
		FileAppend, ANSWER: SYSTEM, %A_Desktop%\Forensics Question %fcount%.txt
	}
	
;	IfInString, forensic, %cipher% ; IS IT ASKING TO SOLVE A CIPHER
		;removeLastTwo(%forensic%)
	
	fcount++
	}
	SoundPlay *-1
}

removeLastThree(f) {
FileRead, text, %A_Desktop%\Forensics Question %f%.txt
FileDelete, %f%
FileAppend, % SubStr(text, 1, RegExMatch(text, "\R.*\R?$")-1), %A_Desktop%\Forensics Question %f%.txt
Sleep, 500
}

setSecurePasswords() {
	sLoops := usersLoop("C:\usersTemp.txt")
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

parseREADME() {
	readme = Readme,readme,README
	excludeDir = PerfLogs,Program Files, Program Files (x86),Users,Windows
	Loop Files, C:\*, FR  ; Recurse into subfolders.
	{
		if A_LoopFileLongPath contains %excludeDir%
			continue
		else if A_LoopFileLongPath contains %readme%
		{
			readmeF = %A_LoopFileLongPath%
			FileRead, readme, %readmeF%
			readme := SubStr(readme, 25, -1)
			URLDownloadToFile, %readme%, C:\readmeTemp.txt
			If ErrorLevel
			{
			GuiControl,,uOutput,README not found.
			msgbox, CANNOT FIND README!
			exit
			}
			FileRead, rawReadme, C:\readmeTemp.txt
			FileDelete, C:\readmeTemp.txt
			return %rawReadme%
		}
	}
	GuiControl,,uOutput,README not found.
	msgbox, CANNOT FIND README!
	exit
}

setCorrectPermissions(a, u, m) {
	gUsers =
	(join&
	net user "Administrator" /active:no
	net user "Guest" /active:no
	net user "WDAGUtilityAccount" /active:no
	net user "DefaultAccount" /active:no
	exit
	)
	runwait, %comspec% /k %gUsers%
	
	if m = 0
	{
	GuiControl,,uOutput,PARSING THE README
	rawReadme := parseREADME()
	rawReadme := SubStr(rawReadme, InStr(rawReadme, "Authorized Administrators:") + 32, -1)
	rawReadme := SubStr(rawReadme, 1, InStr(rawReadme, "</pre>")-1)
	pauthorizedAdmins := SubStr(rawReadme, 1, InStr(rawReadme, "<b>") - 1)
	keyword := "password"
	authorizedAdmins := ""
	for i, v in strsplit(pauthorizedAdmins, "`n")
		if (!instr(v, keyword))
			authorizedAdmins .= v "`n"
	}
	else
	{
	authorizedAdmins := a
	rawReadme := u
	}
	
	pLoops := usersLoop("C:\usersTemp.txt")
	Loop, %pLoops%
	{
	FileReadLine, pUser, C:\usersTemp.txt, 1
	pUser := RTrim(pUser)
	if (pUser = "Administrator" or pUser = "Guest" or pUser = "WDAGUtilityAccount" or pUser = "DefaultAccount")
	{
		runwait, powershell -Command "(gc C:\usersTemp.txt | select -Skip 1) | sc C:\usersTemp.txt"
		continue
	}
	IfInString, authorizedAdmins, %pUser% ; if user is an authorized admin
	{
		runwait, %comspec% /k net localgroup Administrators %pUser% /add & exit
	}
	IfNotInString, authorizedAdmins, %pUser%  ; if user is not an authorized admin
	{
		runwait, %comspec% /k net localgroup Administrators %pUser% /delete & exit
		runwait, %comspec% /k net localgroup Users %pUser% /add & exit
	}
	IfInString, rawReadme, %pUser% ; if user is an authorized user
		runwait, %comspec% /k net user %pUser% /active:yes & exit
	else ; if user is not an authorized user
		runwait, %comspec% /k net user %pUser% /active:no & exit
	
	runwait, powershell -Command "(gc C:\usersTemp.txt | select -Skip 1) | sc C:\usersTemp.txt"
	}
	return
}

usersLoop(n) {
	Runwait, PowerShell.exe get-localuser | Select-Object Name | Out-File -FilePath C:\temp.txt | powershell -NoProfile -Command "Get-Content -Path C:\temp.txt | Select-Object -Skip 3" | Out-File -FilePath C:\usersTemp.txt | powershell Remove-Item C:\temp.txt
	Loop, Read, %n% 
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
	global htools ; see top of file for list
	excludeDir = thumbnails,Appdata
	Gui, Submit, NoHide
	Loop Files, C:\Users\*, FR  ; Recurse into subfolders.
	{
		if A_LoopFileLongPath contains %excludeDir%
			continue
		else if A_LoopFileExt in %images%
			FileAppend, %A_LoopFileFullPath%`n, %A_Desktop%\ScannedFiles\images.txt
		else if A_LoopFileExt in %audio%
			FileAppend, %A_LoopFileFullPath%`n, %A_Desktop%\ScannedFiles\audio.txt
		else if A_LoopFileExt in %videos%
			FileAppend, %A_LoopFileFullPath%`n, %A_Desktop%\ScannedFiles\videos.txt
		else if A_LoopFileName contains %htools%
		{
			FileAppend, %A_LoopFileFullPath%`n, %A_Desktop%\ScannedFiles\htools.txt
			FileRecycle % A_LoopFileFullPath
		}
	}
	GuiControl,,scurrP, Done!
}

scanPrograms() {
	GuiControl,,scurrP, Finding Bad Programs
	;readmeDoc := parseREADME()
	global htools ; see top of file for list
	runwait, %comspec% /k winget list >> C:\programs.txt & exit
	runwait, powershell -Command "(gc C:\programs.txt | select -Skip 55) | sc C:\programs.txt"
	Loop, Read, C:\programs.txt
	{
	tLines = %A_Index%
	}
	tLines -= 1
	Loop, %tLines%
	{
	FileReadLine, program, C:\programs.txt, 1
	program := SubStr(program, 1, 25)
	if program contains %htools%
		runwait, %comspec% /k winget uninstall %program% & exit
	runwait, powershell -Command "(gc C:\programs.txt | select -Skip 1) | sc C:\programs.txt"
	}
	FileDelete, C:\programs.txt
	;GuiControl,,scurrP, Updating Programs
	;runwait, %comspec% /k winget upgrade --all
	GuiControl,,scurrP, Done!
}

RDP() {
	GuiControl,,scurrP, Disabling Remote Desktop Connection 
	RegWrite, REG_DWORD, HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server, fDenyTSConnections, 1
	RegWrite, REG_DWORD, HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server, AllowTSConnections, 0
	RegWrite, REG_DWORD, HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server, fAllowToGetHelp, 0
	RegWrite, REG_DWORD, HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp, UserAuthentication, 0
	runwait, %comspec% /k netsh advfirewall firewall set service type = remotedesktop mode = disable & exit
	runwait, %comspec% /k netsh advfirewall firewall set rule group="remote desktop" new enable=no & exit
	GuiControl,,scurrP, Done!
}

Host() {
	GuiControl,,scurrP, Editing Host Files
	runwait, %comspec% /k ipconfig /flushdns & exit
	fileRead, host, C:\Windows\System32\drivers\etc\hosts
	file := FileOpen("C:\Windows\System32\drivers\etc\hosts", "w")
	file.close()
	FileSetAttrib, +SR, C:\Windows\System32\drivers\etc\hosts
	GuiControl,,scurrP, Done!
}

remReg() {
	GuiControl,,scurrP, Remote Registry Off
	runwait, %comspec% /k net stop RemoteRegistry & exit
	runwait, %comspec% /k sc config RemoteRegistry start=disabled & exit
	GuiControl,,scurrP, Done!
}

autoUpdates() {
	GuiControl,,scurrP, Enabling Auto Updates
	RegWrite, REG_DWORD, HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update, AUOptions, 3
	Run ms-settings:windowsupdate-action
	WinWait, Settings
	WinMinimize
	GuiControl,,scurrP, Done!
}

Integrity() {
	GuiControl,,scurrP, Scanning System Integrity
	runwait, %comspec% /k sfc.exe /scannow
	GuiControl,,scurrP, Done!
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
	GuiControl,,scurrP, Done!
}

pPolicy() {
	GuiControl,,scurrP, Setting Password Policy
	FileAppend,
	(
	[Unicode]
	Unicode=yes
	[System Access]
	MinimumPasswordAge = 5
	MaximumPasswordAge = 30
	MinimumPasswordLength = 10
	PasswordComplexity = 1
	PasswordHistorySize = 10
	LockoutBadCount = 5
	ResetLockoutCount = 30
	LockoutDuration = 30
	RequireLogonToChangePassword = 0
	ForceLogoffWhenHourExpire = 0
	NewAdministratorName = "Administrator"
	NewGuestName = "Guest"
	ClearTextPassword = 0
	LSAAnonymousNameLookup = 0
	EnableAdminAccount = 0
	EnableGuestAccount = 0
	[Event Audit]
	AuditSystemEvents = 0
	AuditLogonEvents = 1
	AuditObjectAccess = 0
	AuditPrivilegeUse = 0
	AuditPolicyChange = 0
	AuditAccountManage = 0
	AuditProcessTracking = 0
	AuditDSAccess = 0
	AuditAccountLogon = 0
	[Registry Values]
	MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Setup\RecoveryConsole\SecurityLevel=4,0
	MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Setup\RecoveryConsole\SetCommand=4,0
	MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\CachedLogonsCount=1,"10"
	MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\ForceUnlockLogon=4,0
	MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\PasswordExpiryWarning=4,5
	MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\ScRemoveOption=1,"0"
	MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin=4,5
	MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorUser=4,3
	MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\DontDisplayLastUserName=4,0
	MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableInstallerDetection=4,1
	MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA=4,1
	MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableSecureUIAPaths=4,1
	MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableUIADesktopToggle=4,0
	MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableVirtualization=4,1
	MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\LegalNoticeCaption=1,""
	MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\LegalNoticeText=7,
	MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\PromptOnSecureDesktop=4,1
	MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ScForceOption=4,0
	MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ShutdownWithoutLogon=4,1
	MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\UndockWithoutLogon=4,1
	MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ValidateAdminCodeSignatures=4,0
	MACHINE\Software\Policies\Microsoft\Windows\Safer\CodeIdentifiers\AuthenticodeEnabled=4,0
	MACHINE\System\CurrentControlSet\Control\Lsa\AuditBaseObjects=4,0
	MACHINE\System\CurrentControlSet\Control\Lsa\CrashOnAuditFail=4,0
	MACHINE\System\CurrentControlSet\Control\Lsa\DisableDomainCreds=4,0
	MACHINE\System\CurrentControlSet\Control\Lsa\EveryoneIncludesAnonymous=4,0
	MACHINE\System\CurrentControlSet\Control\Lsa\FIPSAlgorithmPolicy\Enabled=4,0
	MACHINE\System\CurrentControlSet\Control\Lsa\ForceGuest=4,0
	MACHINE\System\CurrentControlSet\Control\Lsa\FullPrivilegeAuditing=3,0
	MACHINE\System\CurrentControlSet\Control\Lsa\LimitBlankPasswordUse=4,1
	MACHINE\System\CurrentControlSet\Control\Lsa\MSV1_0\NTLMMinClientSec=4,536870912
	MACHINE\System\CurrentControlSet\Control\Lsa\MSV1_0\NTLMMinServerSec=4,536870912
	MACHINE\System\CurrentControlSet\Control\Lsa\NoLMHash=4,1
	MACHINE\System\CurrentControlSet\Control\Lsa\RestrictAnonymous=4,0
	MACHINE\System\CurrentControlSet\Control\Lsa\RestrictAnonymousSAM=4,1
	MACHINE\System\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers\AddPrinterDrivers=4,0
	MACHINE\System\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedExactPaths\Machine=7,System\CurrentControlSet\Control\ProductOptions,System\CurrentControlSet\Control\Server Applications,Software\Microsoft\Windows NT\CurrentVersion
	MACHINE\System\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedPaths\Machine=7,System\CurrentControlSet\Control\Print\Printers,System\CurrentControlSet\Services\Eventlog,Software\Microsoft\OLAP Server,Software\Microsoft\Windows NT\CurrentVersion\Print,Software\Microsoft\Windows NT\CurrentVersion\Windows,System\CurrentControlSet\Control\ContentIndex,System\CurrentControlSet\Control\Terminal Server,System\CurrentControlSet\Control\Terminal Server\UserConfig,System\CurrentControlSet\Control\Terminal Server\DefaultUserConfiguration,Software\Microsoft\Windows NT\CurrentVersion\Perflib,System\CurrentControlSet\Services\SysmonLog
	MACHINE\System\CurrentControlSet\Control\Session Manager\Kernel\ObCaseInsensitive=4,1
	MACHINE\System\CurrentControlSet\Control\Session Manager\Memory Management\ClearPageFileAtShutdown=4,0
	MACHINE\System\CurrentControlSet\Control\Session Manager\ProtectionMode=4,1
	MACHINE\System\CurrentControlSet\Control\Session Manager\SubSystems\optional=7,
	MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\AutoDisconnect=4,15
	MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\EnableForcedLogOff=4,1
	MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\EnableSecuritySignature=4,0
	MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\NullSessionPipes=7,
	MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\RequireSecuritySignature=4,0
	MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\RestrictNullSessAccess=4,1
	MACHINE\System\CurrentControlSet\Services\LanmanWorkstation\Parameters\EnablePlainTextPassword=4,0
	MACHINE\System\CurrentControlSet\Services\LanmanWorkstation\Parameters\EnableSecuritySignature=4,1
	MACHINE\System\CurrentControlSet\Services\LanmanWorkstation\Parameters\RequireSecuritySignature=4,0
	MACHINE\System\CurrentControlSet\Services\LDAP\LDAPClientIntegrity=4,1
	MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\DisablePasswordChange=4,0
	MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\MaximumPasswordAge=4,30
	MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\RequireSignOrSeal=4,1
	MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\RequireStrongKey=4,1
	MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\SealSecureChannel=4,1
	MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\SignSecureChannel=4,1
	[Privilege Rights]
	SeNetworkLogonRight = *S-1-1-0,*S-1-5-32-544,*S-1-5-32-545,*S-1-5-32-551
	SeBackupPrivilege = *S-1-5-32-544,*S-1-5-32-551
	SeChangeNotifyPrivilege = *S-1-1-0,*S-1-5-19,*S-1-5-20,*S-1-5-32-544,*S-1-5-32-545,*S-1-5-32-551
	SeSystemtimePrivilege = *S-1-5-19,*S-1-5-32-544
	SeCreatePagefilePrivilege = *S-1-5-32-544
	SeDebugPrivilege = *S-1-5-32-544
	SeRemoteShutdownPrivilege = *S-1-5-32-544
	SeAuditPrivilege = *S-1-5-19,*S-1-5-20
	SeIncreaseQuotaPrivilege = *S-1-5-19,*S-1-5-20,*S-1-5-32-544
	SeIncreaseBasePriorityPrivilege = *S-1-5-32-544,*S-1-5-90-0
	SeLoadDriverPrivilege = *S-1-5-32-544
	SeBatchLogonRight = *S-1-5-32-544,*S-1-5-32-551,*S-1-5-32-559
	SeServiceLogonRight = *S-1-5-80-0
	SeInteractiveLogonRight = __vmware__,Guest,*S-1-5-32-544,*S-1-5-32-545,*S-1-5-32-551
	SeSecurityPrivilege = *S-1-5-32-544
	SeSystemEnvironmentPrivilege = *S-1-5-32-544
	SeProfileSingleProcessPrivilege = *S-1-5-32-544
	SeSystemProfilePrivilege = *S-1-5-32-544,*S-1-5-80-3139157870-2983391045-3678747466-658725712-1809340420
	SeAssignPrimaryTokenPrivilege = *S-1-5-19,*S-1-5-20
	SeRestorePrivilege = *S-1-5-32-544,*S-1-5-32-551
	SeShutdownPrivilege = *S-1-5-32-544,*S-1-5-32-545,*S-1-5-32-551
	SeTakeOwnershipPrivilege = *S-1-5-32-544
	SeDenyNetworkLogonRight = Guest
	SeDenyInteractiveLogonRight = Guest
	SeUndockPrivilege = *S-1-5-32-544,*S-1-5-32-545
	SeManageVolumePrivilege = *S-1-5-32-544
	SeRemoteInteractiveLogonRight = *S-1-5-32-544,*S-1-5-32-555
	SeImpersonatePrivilege = *S-1-5-19,*S-1-5-20,*S-1-5-32-544,*S-1-5-6
	SeCreateGlobalPrivilege = *S-1-5-19,*S-1-5-20,*S-1-5-32-544,*S-1-5-6
	SeIncreaseWorkingSetPrivilege = *S-1-5-32-545
	SeTimeZonePrivilege = *S-1-5-19,*S-1-5-32-544,*S-1-5-32-545
	SeCreateSymbolicLinkPrivilege = *S-1-5-32-544
	SeDelegateSessionUserImpersonatePrivilege = *S-1-5-32-544
	[Version]
	signature="$CHICAGO$"
	Revision=1
	), C:\secconfig.cfg
	Sleep, 500
	if !FileExist("C:\secconfig.cfg")
		Sleep, 3000
	runwait, %comspec% /k secedit.exe /configure /db %windir%\securitynew.sdb /cfg C:\secconfig.cfg /areas SECURITYPOLICY & exit
	Sleep, 500
	FileDelete, securitynew.jfm
	FileDelete, securitynew.sdb
	GuiControl,,scurrP, Done!
	Reg()
}

Reg() {
	GuiControl,,scurrP, Editing Registry Values
	RegWrite, REG_DWORD, HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System, EnableLUA, 1 ; Enable UAC
	RegWrite, REG_DWORD, HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU, AutoInstallMinorUpdates, 1 ; Install Minor Updates
	RegWrite, REG_DWORD, HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU, NoAutoUpdate, 0 ; Disable No Auto Updates
	RegWrite, REG_DWORD, HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU, AUOptions, 4 ; Enable Auto Updates
	RegWrite, REG_DWORD, HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update, AUOptions, 4 ; Enable Auto Updates
	RegWrite, REG_DWORD, HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate, DisableWindowsUpdateAccess, 0 ; Disable Windows Update Access
	RegWrite, REG_DWORD, HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate, ElevateNonAdmins, 0 ; ElevateNonAdmins
	RegWrite, REG_DWORD, HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer, NoWindowsUpdate, 0 ; Enable Windows Update
	RegWrite, REG_DWORD, HKLM\SYSTEM\Internet Communication Management\Internet Communication, DisableWindowsUpdateAccess, 0 ; Enable Windows Update
	RegWrite, REG_DWORD, HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\WindowsUpdate, DisableWindowsUpdateAccess, 0; Enable Windows Update
	RegWrite, REG_DWORD, HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon, AllocateCDRoms, 1 ; Allocate CD Roms
	RegWrite, REG_DWORD, HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon, AllocateFloppies, 1 ; Allocate Floppy Disks
	RegWrite, REG_DWORD, HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon, AutoAdminLogon, 0 ; Auto Admin Logon
	RegWrite, REG_DWORD, HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management, ClearPageFileAtShutdown, 1 ; Clear Page File At Shutdown
	RegWrite, REG_DWORD, HKLM\SYSTEM\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers, AddPrinterDrivers, 1 ; Add Printer Drivers
	RegWrite, REG_DWORD, HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\LSASS.exe, AuditLevel, 00000008 ; Change Audit Level
	RegWrite, REG_DWORD, HKLM\SYSTEM\CurrentControlSet\Control\Lsa, RunAsPPL, 00000001 ; Run as PPL
	RegWrite, REG_DWORD, HKLM\SYSTEM\CurrentControlSet\Control\Lsa, LimitBlankPasswordUse, 1 ; Limit Blank Passwords
	RegWrite, REG_DWORD, HKLM\SYSTEM\CurrentControlSet\Control\Lsa, auditbaseobjects, 1 ; Audit Base Objects
	RegWrite, REG_DWORD, HKLM\SYSTEM\CurrentControlSet\Control\Lsa, fullprivilegeauditing, 1 ; Enable Full Privilege Auditing
	RegWrite, REG_DWORD, HKLM\SYSTEM\CurrentControlSet\Control\Lsa, restrictanonymous, 1 ; Restrict Anonymous
	RegWrite, REG_DWORD, HKLM\SYSTEM\CurrentControlSet\Control\Lsa, restrictanonymoussam, 1 ; Restrict Anonymous SAM
	RegWrite, REG_DWORD, HKLM\SYSTEM\CurrentControlSet\Control\Lsa, disabledomaincreds, 1 ; Disable Domain Credentials
	RegWrite, REG_DWORD, HKLM\SYSTEM\CurrentControlSet\Control\Lsa, everyoneincludesanonymous, 0 ; Everyone Includes Anonymous
	RegWrite, REG_DWORD, HKLM\SYSTEM\CurrentControlSet\Control\Lsa, UseMachineId, 0 ; Use Machine ID
	RegWrite, REG_DWORD, HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System, dontdisplaylastusername, 1 ; Do Not Disable Username On Login
	RegWrite, REG_DWORD, HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System, EnableLUA, 1 ; Enable UAC
	RegWrite, REG_DWORD, HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System, PromptOnSecureDesktop, 1 ; Prompt On Secure Desktop
	RegWrite, REG_DWORD, HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System, EnableInstallerDetection, 1 ; Installer Detection
	RegWrite, REG_DWORD, HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System, undockwithoutlogon, 0 ; Undock Without Logon
	RegWrite, REG_DWORD, HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System, DisableCAD, 0 ; Disable CAD
	RegWrite, REG_DWORD, HKLM\SYSTEM\CurrentControlSet\services\Netlogon\Parameters, MaximumPasswordAge, 30 ; Maximum Password Age To 30
	RegWrite, REG_DWORD, HKLM\SYSTEM\CurrentControlSet\services\Netlogon\Parameters, DisablePasswordChange, 1 ; Disable Password Changing?
	RegWrite, REG_DWORD, HKLM\SYSTEM\CurrentControlSet\services\Netlogon\Parameters, RequireStrongKey, 1 ; Require A Strong Key
	RegWrite, REG_DWORD, HKLM\SYSTEM\CurrentControlSet\services\Netlogon\Parameters, RequireSignOrSeal, 1 ; Require A Sign Or Seal
	RegWrite, REG_DWORD, HKLM\SYSTEM\CurrentControlSet\services\Netlogon\Parameters, SignSecureChannel, 1 ; Sign Secure Channel
	RegWrite, REG_DWORD, HKLM\SYSTEM\CurrentControlSet\services\Netlogon\Parameters, SealSecureChannel, 1 ; Seal Secure Channel
	RegWrite, REG_DWORD, HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters, autodisconnect, 45 ; Auto Disconnect 45 seconds
	RegWrite, REG_DWORD, HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters, enablesecuritysignature, 0 ; Enable Security Signature
	RegWrite, REG_DWORD, HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters, requiresecuritysignature, 0 ; Require Security Signature
	RegWrite, REG_DWORD, HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced, ShowSuperHidden, 1 ; Show Super Hidden Files
	RegWrite, REG_DWORD, HKLM\SYSTEM\CurrentControlSet\Control\CrashControl, CrashDumpEnabled, 0 ; Crash Dump Enabled
	RegWrite, REG_DWORD, HKCU\SYSTEM\CurrentControlSet\Services\CDROM, AutoRun, 1 ; Auto Run?
	RegWrite, REG_DWORD, HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced, Hidden, 1
	RegWrite, REG_DWORD, HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings, WarnonZoneCrossing, 1
	RegWrite, REG_DWORD, HKCU\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_LOCALMACHINE_LOCKDOWN\Settings, LOCALMACHINE_CD_UNLOCK, 1
	RegWrite, REG_DWORD, HKCU\Software\Microsoft\Internet Explorer\Download, RunInvalidSignatures, 1
	RegWrite, REG_DWORD, HKCU\Software\Microsoft\Internet Explorer\Main, DoNotTrack, 1
	RegWrite, REG_DWORD, HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings, WarnOnPostRedirect, 1
	RegWrite, REG_DWORD, HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings, WarnonBadCertRecving, 1
	RegWrite, REG_DWORD, HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings, DisablePasswordCaching, 1
	RegWrite, REG_DWORD, HKCU\Software\Microsoft\Internet Explorer\PhishingFilter, EnabledV9, 1
	RegWrite, REG_DWORD, HKCU\Software\Microsoft\Internet Explorer\PhishingFilter, EnabledV8, 1
	RegWrite, REG_DWORD, HKLM\SYSTEM\CurrentControlSet\services\LanmanWorkstation\Parameters, EnablePlainTextPassword, 0
	RegWrite, REG_SZ, HKU\.DEFAULT\Control Panel\Accessibility\StickyKeys, Flags, 506
	RegWrite, REG_MULTI_SZ, HKLM\SYSTEM\CurrentControlSet\Control\SecurePipeServers\winreg\AllowedPaths, Machine, ""
	RegWrite, REG_MULTI_SZ, HKLM\SYSTEM\CurrentControlSet\Control\SecurePipeServers\winreg\AllowedExactPaths, Machine, ""
	RegWrite, REG_MULTI_SZ, HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters, NullSessionPipes, ""
	RegWrite, REG_MULTI_SZ, HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters, NullSessionShares, ""
	GuiControl,,scurrP, Done!
}
audit() {
	runwait, %comspec% /k auditpol /set /category:* /success:enable & exit
	runwait, %comspec% /k auditpol /set /category:* /failure:enable & exit
	GuiControl,,scurrP, Done!
}

sPwr() {
	runwait, %comspec% /k powercfg -SETDCVALUEINDEX SCHEME_BALANCED SUB_NONE CONSOLELOCK 1 & exit
	runwait, %comspec% /k powercfg -SETDCVALUEINDEX SCHEME_MIN SUB_NONE CONSOLELOCK 1 & exit
	runwait, %comspec% /k powercfg -SETDCVALUEINDEX SCHEME_MAX SUB_NONE CONSOLELOCK 1 & exit
	GuiControl,,scurrP, Done!
}
soFeatures:
	GuiControl,,scurrP, Enabling Features
	oFeatures =
	(join&
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
	GuiControl,,scurrP, Done!
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
	GuiControl,,scurrP, Done!
}

guiClose:
	FileDelete, C:\tempAdminList.txt
	FileDelete, C:\tempUserList.txt
	FileDelete, C:\usersTemp.txt
	FileDelete, C:\tempworkgroup.txt
	FileDelete, C:\secconfig.cfg
	FileDelete, C:\readmeTemp.txt
	FileDelete, C:\programs.txt
	ExitApp