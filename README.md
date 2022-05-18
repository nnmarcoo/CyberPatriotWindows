# Windows Security Script
A tool that compiles many functions to secure a Windows machine under the guide lines of CyberPatriot into a clean gui.

**DISCLAIMER** This tool is no longer getting additions or being bug fixed as I am no longer participating in CyberPatriot.

## Features

### [File Hash]
![This is an image](https://cdn.discordapp.com/attachments/956008511861567541/975400984916398130/unknown.png)  
Gives hash SHA[1,256,384,512] or MD[2,4,5] of input file directory.


### [Users]
![This is an image](https://cdn.discordapp.com/attachments/956008511861567541/975401022665142392/unknown.png)  
***Exec All*** Will execute everything on that tab. **DO NOT** use it,some of the functions are broken.

The ***m*** checkbox will toggle manual mode. This will allow the user to input admins and users manually. **UNTESTED**

***Secure Passwords*** Will go through each user and set a unique password according to a template and their position in the user list. E.g. mABCxyz1!

***Set Perms*** Will parse the readme file and apply the correct permissions. **DOES NOT WORK**

***Cu*** Will Create a user given in the small input box to the left of the button.

***Au*** Will give the user the User group in the small input box to the left of the button.

***Aa*** Will give the user the Admin group in the small input box to the left of the button.


### [System]
![This is an image](https://cdn.discordapp.com/attachments/956008511861567541/975401060103520256/unknown.png)  

Note, the square buttons will revert the setting to what is considered less secure.

***Exec All*** Will execute all scripts on this page. (Not recommended)

***Scan Files*** Will scan the computer for notable file types and put all records in a folder.

***RDP*** Will disabble everything to do with RDP and prompt with a disable GUI.

***Clear Hosts*** Will reset the Hosts file.

<details>
	<summary><em>Reg</em> Will set a ton of registry keys.</summary>
<br>
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System, EnableLUA, 1 
	HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU, AutoInstallMinorUpdates, 1 
	HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU, NoAutoUpdate, 0
	HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU, AUOptions, 4
	HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update, AUOptions, 4 
	HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate, DisableWindowsUpdateAccess, 0 
	HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate, ElevateNonAdmins, 0 
	HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer, NoWindowsUpdate, 0
	HKLM\SYSTEM\Internet Communication Management\Internet Communication, DisableWindowsUpdateAccess, 0 
	HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\WindowsUpdate, DisableWindowsUpdateAccess, 0
	HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon, AllocateCDRoms, 1
	HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon, AllocateFloppies, 1 
	HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon, AutoAdminLogon, 0 
	HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management, ClearPageFileAtShutdown, 1 
	HKLM\SYSTEM\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers, AddPrinterDrivers, 1 
	HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\LSASS.exe, AuditLevel, 00000008
	HKLM\SYSTEM\CurrentControlSet\Control\Lsa, RunAsPPL, 00000001 
	HKLM\SYSTEM\CurrentControlSet\Control\Lsa, LimitBlankPasswordUse, 1
	HKLM\SYSTEM\CurrentControlSet\Control\Lsa, auditbaseobjects, 1
	HKLM\SYSTEM\CurrentControlSet\Control\Lsa, fullprivilegeauditing, 1
	HKLM\SYSTEM\CurrentControlSet\Control\Lsa, restrictanonymous, 1
	HKLM\SYSTEM\CurrentControlSet\Control\Lsa, restrictanonymoussam, 1 
	HKLM\SYSTEM\CurrentControlSet\Control\Lsa, disabledomaincreds, 1
	HKLM\SYSTEM\CurrentControlSet\Control\Lsa, everyoneincludesanonymous, 0 
	HKLM\SYSTEM\CurrentControlSet\Control\Lsa, UseMachineId, 0 
	HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System, dontdisplaylastusername, 1 
	HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System, EnableLUA, 1 
	HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System, PromptOnSecureDesktop, 1 
	HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System, EnableInstallerDetection, 1
	HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System, undockwithoutlogon, 0
	HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System, DisableCAD, 0 
	HKLM\SYSTEM\CurrentControlSet\services\Netlogon\Parameters, MaximumPasswordAge, 30 
	HKLM\SYSTEM\CurrentControlSet\services\Netlogon\Parameters, DisablePasswordChange, 1 
	HKLM\SYSTEM\CurrentControlSet\services\Netlogon\Parameters, RequireStrongKey, 1 
	HKLM\SYSTEM\CurrentControlSet\services\Netlogon\Parameters, RequireSignOrSeal, 1 
	HKLM\SYSTEM\CurrentControlSet\services\Netlogon\Parameters, SignSecureChannel, 1 
	HKLM\SYSTEM\CurrentControlSet\services\Netlogon\Parameters, SealSecureChannel, 1
	HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters, autodisconnect, 45 
	HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters, enablesecuritysignature, 0 
	HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters, requiresecuritysignature, 0
	HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced, ShowSuperHidden, 1
	HKLM\SYSTEM\CurrentControlSet\Control\CrashControl, CrashDumpEnabled, 0 
	HKCU\SYSTEM\CurrentControlSet\Services\CDROM, AutoRun, 1
	HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced, Hidden, 1
	HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings, WarnonZoneCrossing, 1
	HKCU\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_LOCALMACHINE_LOCKDOWN\Settings, LOCALMACHINE_CD_UNLOCK, 1
	HKCU\Software\Microsoft\Internet Explorer\Download, RunInvalidSignatures, 1
	HKCU\Software\Microsoft\Internet Explorer\Main, DoNotTrack, 1
	HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings, WarnOnPostRedirect, 1
	HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings, WarnonBadCertRecving, 1
	HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings, DisablePasswordCaching, 1
	HKCU\Software\Microsoft\Internet Explorer\PhishingFilter, EnabledV9, 1
	HKCU\Software\Microsoft\Internet Explorer\PhishingFilter, EnabledV8, 1
	HKLM\SYSTEM\CurrentControlSet\services\LanmanWorkstation\Parameters, EnablePlainTextPassword, 0
	HLU.DEFAULT\Control Panel\Accessibility\StickyKeys, Flags, 506
	HKLM\SYSTEM\CurrentControlSet\Control\SecurePipeServers\winreg\AllowedPaths, Machine, ""
	HKLM\SYSTEM\CurrentControlSet\Control\SecurePipeServers\winreg\AllowedExactPaths, Machine, ""
	HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters, NullSessionPipes, ""
	HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters, NullSessionShares, ""
</details>

### [Otools]
![This is an image](https://cdn.discordapp.com/attachments/956008511861567541/975401097189544006/unknown.png)  

***Attempt Forensics*** Will read the forensics files and answer them if it can.

***Del file*** Will delete the given directory

***File Owner*** Will give the file owner of the selected file.

