#SingleInstance Force
if not A_IsAdmin
	Run *RunAs "%A_ScriptFullPath%"
FileRemoveDir, %A_Desktop%\ScannedFiles, 1
FileCreateDir, %A_Desktop%\ScannedFiles
audio := "mp3,ac3,aac,aiff,flac,m4a,m4p,midi,mp2,m3u,ogg,vqf,wav"
videos := "wma,mp4,avi,mpeg4"
images := "jpeg,jpg,bmp,png,gif,pdf"
;excludeDirs := "%A_WinDir%,%A_AppData%"
Loop Files, C:\Users\*, R  ; Recurse into subfolders.
{
	If A_LoopFileLongPath not in %excludeDirs%
		if A_LoopFileExt in %images%
			FileAppend, %A_LoopFileFullPath%`n, %A_Desktop%\ScannedFiles\images.txt
		else if A_LoopFileExt in %videos%
			FileAppend, %A_LoopFileFullPath%`n, %A_Desktop%\ScannedFiles\videos.txt
		else if A_LoopFileExt in %audio%
			FileAppend, %A_LoopFileFullPath%`n, %A_Desktop%\ScannedFiles\audio.txt
}
msgbox, done
ExitApp
