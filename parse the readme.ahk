readme = Readme,readme,README
excludeDir = PerfLogs,Program Files, Program Files (x86),Users,Windows
Loop Files, C:\*, FR  ; Recurse into subfolders.
{
	if A_LoopFileLongPath contains %excludeDir%
		continue
	else if A_LoopFileLongPath contains %readme%
	{
		readmeF = %A_LoopFileLongPath%
		Break
	}
}
FileRead, readme, %readmeF%
readme := SubStr(readme, 1, 21)
msgbox, %readme%
