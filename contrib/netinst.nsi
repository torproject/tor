!include "MUI.nsh"
!include "LogicLib.nsh"
!include "FileFunc.nsh"
  
!define VERSION "0.2.1.13"
!define INSTALLER "TorNetInstaller.exe"
!define WEBSITE "https://www.torproject.org/"
!define LICENSE "LICENSE"
 
SetCompressor /SOLID BZIP2
RequestExecutionLevel user
OutFile ${INSTALLER}
InstallDir "$TEMP\TorInstTmp"
SetOverWrite on
Name "Tor Network Installer"
Caption "Tor Network Installer"
BrandingText "Tor Network Installer"
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
	Call CleanUpTemp
SectionEnd

Function ExtractPackages
	File "license.msi"
	File "thandy.msi"
FunctionEnd

Function RunInstallers
	ExecWait 'msiexec /i "$INSTDIR\license.msi" /qn'
	ExecWait 'msiexec /i "$INSTDIR\thandy.msi" NOSC=1 /qn'
	ExecWait '"$LOCALAPPDATA\Programs\Thandy\thandy.exe" update "--repo=$LOCALAPPDATA\Thandy\Tor Updates" /bundleinfo/tor/win32/'
	ExecWait '"$LOCALAPPDATA\Programs\Thandy\thandy.exe" update "--repo=$LOCALAPPDATA\Thandy\Polipo Updates" /bundleinfo/polipo/win32/'
	ExecWait '"$LOCALAPPDATA\Programs\Thandy\thandy.exe" update "--repo=$LOCALAPPDATA\Thandy\TorButton Updates" /bundleinfo/torbutton/win32/'
	ExecWait '"$LOCALAPPDATA\Programs\Thandy\thandy.exe" update "--repo=$LOCALAPPDATA\Thandy\Vidalia Updates" /bundleinfo/vidalia/win32/'
	ExecWait '"$LOCALAPPDATA\Programs\Thandy\thandy.exe" update --install "--repo=$LOCALAPPDATA\Thandy\Tor Updates" /bundleinfo/tor/win32/'
	ExecWait '"$LOCALAPPDATA\Programs\Thandy\thandy.exe" update --install "--repo=$LOCALAPPDATA\Thandy\Polipo Updates" /bundleinfo/polipo/win32/'
	ExecWait '"$LOCALAPPDATA\Programs\Thandy\thandy.exe" update --install "--repo=$LOCALAPPDATA\Thandy\TorButton Updates" /bundleinfo/torbutton/win32/'
	ExecWait '"$LOCALAPPDATA\Programs\Thandy\thandy.exe" update --install "--repo=$LOCALAPPDATA\Thandy\Vidalia Updates" /bundleinfo/vidalia/win32/'
        ExpandEnvStrings $0 %COMSPEC%
        Exec '"$0" /C "$INSTDIR\tbcheck.bat"'
FunctionEnd

Function LaunchVidalia
	SetOutPath "$LOCALAPPDATA\Programs\Vidalia"
	Exec 'vidalia.exe -loglevel info -logfile log.txt'
FunctionEnd

Function CleanUpTemp
	ExecWait '"del" "$INSTDIR\license.msi"'
	ExecWait '"del" "$INSTDIR\thandy.msi"'
	SetOutPath $TEMP
	RMDir /r $TEMP\TorInstTmp
FunctionEnd

