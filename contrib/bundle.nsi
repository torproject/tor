!include "MUI.nsh"
!include "LogicLib.nsh"
!include "FileFunc.nsh"
  
!define VERSION "0.2.1.13"
!define INSTALLER "TorBundle.exe"
!define WEBSITE "https://www.torproject.org/"
!define LICENSE "LICENSE"
 
SetCompressor /SOLID BZIP2
RequestExecutionLevel user
OutFile ${INSTALLER}
InstallDir "$LOCALAPPDATA\TorInstPkgs"
SetOverWrite on
Name "Tor ${VERSION} Bundle"
Caption "Tor ${VERSION} Bundle Setup"
BrandingText "Tor Bundle Installer"
CRCCheck on
XPStyle on
ShowInstDetails hide
VIProductVersion "${VERSION}"
VIAddVersionKey "ProductName" "Tor"
VIAddVersionKey "Comments" "${WEBSITE}"
VIAddVersionKey "LegalTrademarks" "Three line BSD"
VIAddVersionKey "LegalCopyright" "©2004-2011, Roger Dingledine, Nick Mathewson, The Tor Project, Inc."
VIAddVersionKey "FileDescription" "Tor is an implementation of Onion Routing. You can read more at ${WEBSITE}"
VIAddVersionKey "FileVersion" "${VERSION}"

!define MUI_ICON "torinst32.ico"
!define MUI_HEADERIMAGE_BITMAP "${NSISDIR}\Contrib\Graphics\Header\win.bmp"
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_LANGUAGE "English"

Section "Tor" Tor
	SectionIn RO
	SetOutPath $INSTDIR
	Call ExtractPackages
        Call RunInstallers
	Call LaunchVidalia
SectionEnd

Function ExtractPackages
	File "license.msi"
	File "tor.msi"
	File "torbutton.msi"
	File "thandy.msi"
	File "polipo.msi"
	File "vidalia.msi"
        File "tbcheck.bat"
FunctionEnd

Function RunInstallers
	ExecWait 'msiexec /i "$INSTDIR\license.msi" /qn'
	ExecWait 'msiexec /i "$INSTDIR\tor.msi" NOSC=1 /qn'
	ExecWait 'msiexec /i "$INSTDIR\thandy.msi" NOSC=1 /qn'
	ExecWait 'msiexec /i "$INSTDIR\polipo.msi" NOSC=1 /qn'
	ExecWait 'msiexec /i "$INSTDIR\torbutton.msi" /qn'
	ExecWait 'msiexec /i "$INSTDIR\vidalia.msi" /qn'
        ExpandEnvStrings $0 %COMSPEC%
        Exec '"$0" /C "$INSTDIR\tbcheck.bat"'
FunctionEnd

Function LaunchVidalia
	SetOutPath "$LOCALAPPDATA\Programs\Vidalia"
	Exec 'vidalia.exe -loglevel info -logfile log.txt'
FunctionEnd

