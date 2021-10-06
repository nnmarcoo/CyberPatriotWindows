/*
//==================================
// AUTHOR       : Marco Todorov
// CREATE DATE  : 10/2/2021
// PURPOSE      : Automate and simplify operations to secure Windows 10
// SPECIAL NOTES: Made for Cyberpatriot 2021
// VERSION      : 0.1
// ===============================
// TODO:
// Add remove all button to user tab
// Add reg edit to sys tab
// Add system integrety scan in sys tab
// Add removal of windows features
// Scan for unwanted files
// Set password requirements
// Probably much more.
//==================================
*/

#SingleInstance Force
SetTitleMatchMode, 2
#NoEnv
SendMode Input
if not A_IsAdmin
	Run *RunAs "%A_ScriptFullPath%"

Gui,Add,Tab3,x10 y10 w300 h200 ,Hash||Users|Sys|   ;create a tab control

;#######################															HASH TAB
Gui,Tab,Hash   ; enter tab 1
Gui,Add, DropDownList, x20 y40 w70 vHASH, SHA1|SHA256|SHA384|SHA512|MD2|MD4|MD5
Gui,Add, Edit, x95 y40 w205 vhInput, File Directory
Gui,Add, Button, x19 y70 w281 gexportHash, Export
Gui,Add, Edit, x20 y100 w280 h100 vhOutput, Output
;#######################															USER TAB
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
;#######################															SYSTEM TAB
Gui,Tab, Sys ; enter tab 3
Gui,Add,Text,x20 y40 ,This is where you add the controls to tab 3
;#######################

Gui,Tab, ;exit the tabs
;Gui,Add,Text,x10 y220,bruh
Gui,Show,
return
;#######################															END OF WINDOW CONFIGURATION

;#######################															FUNCTIONS
exportHash:
	Gui, Submit
	runwait, %comspec% /k certutil -hashfile "%hInput%" %HASH% >> C:\hashTemp.txt & exit
	FileReadLine, hFinalOutput, C:\hashTemp.txt, 2
	GuiControl,,hOutput,%hFinalOutput%
	FileDelete, C:\hashTemp.txt
	Gui,Show,
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

guiClose:
	FileDelete, C:\tempAdminList.txt
	FileDelete, C:\tempUserList.txt
	FileDelete, C:\usersTemp.txt
	ExitApp