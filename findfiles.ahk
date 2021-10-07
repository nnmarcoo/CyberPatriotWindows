if not A_IsAdmin
	Run *RunAs "%A_ScriptFullPath%"
audio := "mp3,ac3,aac,aiff,flac,m4a,m4p,midi,mp2,m3u,ogg,vqf,wav"
videos := "wma,mp4,avi,mpeg4"
images := "jpeg,jpg,bmp,png,gif,pdf"
FileAppend, `n###IMAGES###`n, bruh.txt
Loop Files, C:\Users\*, R  ; Recurse into subfolders.
{
	if A_LoopFileExt in %images%
		FileAppend, %A_LoopFileFullPath%`n, bruh.txt

}
return