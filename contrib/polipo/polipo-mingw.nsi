;polipo-mingw.nsi - A basic win32 installer for Polipo
; Originally written by J Doe.
; Modified by Andrew Lewman
; This is licensed under a Modified BSD license.
;-----------------------------------------
;
!include "MUI.nsh"

!define VERSION "1.0.4.0-forbidden-1"
!define INSTALLER "polipo-${VERSION}-win32.exe"
!define WEBSITE "http://www.pps.jussieu.fr/~jch/software/polipo/"

!define LICENSE "COPYING"
;BIN is where it expects to find polipo.exe
!define BIN "."

SetCompressor lzma
OutFile ${INSTALLER}
InstallDir $PROGRAMFILES\Polipo
SetOverWrite ifnewer

Name "Polipo"
Caption "Polipo ${VERSION} Setup"
BrandingText "A Caching Web Proxy"
CRCCheck on
XPStyle on
VIProductVersion "${VERSION}"
VIAddVersionKey "ProductName" "Polipo: A caching web proxy"
VIAddVersionKey "Comments" "http://www.pps.jussieu.fr/~jch/software/polipo/"
VIAddVersionKey "LegalTrademarks" "See COPYING"
VIAddVersionKey "LegalCopyright" "©2008, Juliusz Chroboczek"
VIAddVersionKey "FileDescription" "Polipo is a caching web proxy."
VIAddVersionKey "FileVersion" "${VERSION}"

!define MUI_WELCOMEPAGE_TITLE "Welcome to the Polipo ${VERSION} Setup Wizard"
!define MUI_WELCOMEPAGE_TEXT "This wizard will guide you through the installation of Polipo ${VERSION}.\r\n\r\nIf you have previously installed Polipo and it is currently running, please exit Polipo first before continuing this installation.\r\n\r\n$_CLICK"
!define MUI_ABORTWARNING
!define MUI_ICON "${NSISDIR}\Contrib\Graphics\Icons\win-install.ico"
!define MUI_UNICON "${NSISDIR}\Contrib\Graphics\Icons\win-uninstall.ico"
!define MUI_HEADERIMAGE_BITMAP "${NSISDIR}\Contrib\Graphics\Header\win.bmp"
!define MUI_HEADERIMAGE
;!define MUI_FINISHPAGE_RUN 
!define MUI_FINISHPAGE_LINK "Visit the Polipo website for the latest updates."
!define MUI_FINISHPAGE_LINK_LOCATION ${WEBSITE}

!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_COMPONENTS
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH
!insertmacro MUI_UNPAGE_WELCOME
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES
!insertmacro MUI_UNPAGE_FINISH
!insertmacro MUI_LANGUAGE "English"

Var configfile
Var forbiddenfile

;Sections
;--------

Section "Polipo" Polipo
;Files that have to be installed for polipo to run and that the user
;cannot choose not to install
   SectionIn RO
   SetOutPath $INSTDIR
   File "${BIN}\polipo.exe"
   File "${BIN}\COPYING"
   File "${BIN}\CHANGES"
   File "${BIN}\config.sample"
   File "${BIN}\forbidden.sample"
   File "${BIN}\README.Windows"
   File "${BIN}\libgnurx-0.dll"
   WriteIniStr "$INSTDIR\Polipo Website.url" "InternetShortcut" "URL" ${WEBSITE}

   StrCpy $configfile "config"
   StrCpy $forbiddenfile "forbidden"
   SetOutPath $INSTDIR
   ;If there's already a polipo config file, ask if they want to
   ;overwrite it with the new one.
   IfFileExists "$INSTDIR\config" "" endifconfig
      MessageBox MB_ICONQUESTION|MB_YESNO "You already have a Polipo config file.$\r$\nDo you want to overwrite it with the default sample config file?" IDNO yesreplace
      Delete $INSTDIR\config
      Goto endifconfig
     yesreplace:
      StrCpy $configfile ".\config.sample"
   endifconfig:
   File /oname=$configfile ".\config.sample"
   ;If there's already a polipo forbidden file, ask if they want to
   ;overwrite it with the new one.
   IfFileExists "$INSTDIR\forbidden" "" endifforbidden
      MessageBox MB_ICONQUESTION|MB_YESNO "You already have a Polipo forbidden file.$\r$\nDo you want to overwrite it with the default sample forbidden file?" IDNO forbidyesreplace
      Delete $INSTDIR\forbidden
      Goto endifforbidden
     forbidyesreplace:
      StrCpy $forbiddenfile ".\forbidden.sample"
   endifforbidden:
   File /oname=$forbiddenfile ".\forbidden.sample"
   IfFileExists "$INSTDIR\bin\*.*" "" endifbinroot
	CreateDirectory "$INSTDIR\bin"
   endifbinroot:
   CopyFiles "${BIN}\localindex.html" $INSTDIR\index.html
   IfFileExists "$INSTDIR\cache\*.*" "" endifcache
	CreateDirectory "$INSTDIR\cache"
   endifcache:
SectionEnd

SubSection /e "Shortcuts" Shortcuts

Section "Start Menu" StartMenu
   SetOutPath $INSTDIR
   IfFileExists "$SMPROGRAMS\Polipo\*.*" "" +2
      RMDir /r "$SMPROGRAMS\Polipo"
   CreateDirectory "$SMPROGRAMS\Polipo"
   CreateShortCut "$SMPROGRAMS\Polipo\Polipo.lnk" "$INSTDIR\polipo.exe" "-c config" 
   CreateShortCut "$SMPROGRAMS\Polipo\Poliporc.lnk" "Notepad.exe" "$INSTDIR\config"
   CreateShortCut "$SMPROGRAMS\Polipo\Polipo Documentation.lnk" "$INSTDIR\www\index.html"
   CreateShortCut "$SMPROGRAMS\Polipo\Polipo Website.lnk" "$INSTDIR\Polipo Website.url"
   CreateShortCut "$SMPROGRAMS\Polipo\Uninstall.lnk" "$INSTDIR\Uninstall.exe"
SectionEnd

Section "Desktop" Desktop
   SetOutPath $INSTDIR
   CreateShortCut "$DESKTOP\Polipo.lnk" "$INSTDIR\polipo.exe" "-c config" 
SectionEnd

Section /o "Run at startup" Startup
   SetOutPath $INSTDIR
   CreateShortCut "$SMSTARTUP\Polipo.lnk" "$INSTDIR\polipo.exe" "-c config -f forbidden" "" "" "" SW_SHOWMINIMIZED
SectionEnd

SubSectionEnd

Section "Uninstall"
   Delete "$DESKTOP\Polipo.lnk"
   Delete "$INSTDIR\polipo.exe"
   Delete "$INSTDIR\Polipo Website.url"
   Delete "$INSTDIR\config"
   Delete "$INSTDIR\config.sample"
   Delete "$INSTDIR\forbidden.sample"
   Delete "$INSTDIR\libgnurx-0.dll"
   Delete "$INSTDIR\COPYING"
   Delete "$INSTDIR\CHANGES"
   Delete "$INSTDIR\README.Windows"
   StrCmp $INSTDIR $INSTDIR +2 ""
      RMDir /r $INSTDIR
   Delete "$INSTDIR\Uninstall.exe"
   RMDir /r "$INSTDIR\Documents"
   RMDir $INSTDIR
   RMDir /r "$SMPROGRAMS\Polipo"
   RMDir /r "$APPDATA\Polipo"
   Delete "$SMSTARTUP\Polipo.lnk"
   DeleteRegKey HKLM "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Polipo"
SectionEnd

Section -End
    WriteUninstaller "$INSTDIR\Uninstall.exe"
    ;The registry entries simply add the Polipo uninstaller to the Windows
    ;uninstall list.
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\Polipo" "DisplayName" "Polipo (remove only)"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\Polipo" "UninstallString" '"$INSTDIR\Uninstall.exe"'
SectionEnd

!insertmacro MUI_FUNCTION_DESCRIPTION_BEGIN
  !insertmacro MUI_DESCRIPTION_TEXT ${Polipo} "The core executable and config files needed for Polipo to run."
  !insertmacro MUI_DESCRIPTION_TEXT ${ShortCuts} "Shortcuts to easily start Polipo"
  !insertmacro MUI_DESCRIPTION_TEXT ${StartMenu} "Shortcuts to access Polipo and it's documentation from the Start Menu"
  !insertmacro MUI_DESCRIPTION_TEXT ${Desktop} "A shortcut to start Polipo from the desktop"
  !insertmacro MUI_DESCRIPTION_TEXT ${Startup} "Launches Polipo automatically at startup in a minimized window"
!insertmacro MUI_FUNCTION_DESCRIPTION_END

