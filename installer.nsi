; Mesh Network Installer Script for NSIS

!define APP_NAME "Mesh Network"
!define APP_VERSION "1.0.0"
!define APP_PUBLISHER "Your Company"
!define APP_EXE "MeshNetwork.exe"

; Modern UI
!include "MUI2.nsh"

; General settings
Name "${APP_NAME}"
OutFile "MeshNetworkInstaller.exe"
InstallDir "$PROGRAMFILES\${APP_NAME}"
InstallDirRegKey HKCU "Software\${APP_NAME}" ""
RequestExecutionLevel admin

; Interface Settings
!define MUI_ABORTWARNING
!define MUI_ICON "assets\icon.ico"
!define MUI_UNICON "assets\icon.ico"

; Pages
!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_LICENSE "LICENSE.txt"
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH

!insertmacro MUI_UNPAGE_WELCOME
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES
!insertmacro MUI_UNPAGE_FINISH

; Languages
!insertmacro MUI_LANGUAGE "English"

; Installation
Section "Main Application" SecMain
    SetOutPath "$INSTDIR"
    File "dist\${APP_EXE}"
    File /r "dist\*"
    
    ; Create shortcuts
    CreateDirectory "$SMPROGRAMS\${APP_NAME}"
    CreateShortCut "$SMPROGRAMS\${APP_NAME}\${APP_NAME}.lnk" "$INSTDIR\${APP_EXE}"
    CreateShortCut "$DESKTOP\${APP_NAME}.lnk" "$INSTDIR\${APP_EXE}"
    
    ; Registry
    WriteRegStr HKCU "Software\${APP_NAME}" "" $INSTDIR
    WriteUninstaller "$INSTDIR\Uninstall.exe"
SectionEnd

; Uninstallation
Section "Uninstall"
    Delete "$INSTDIR\${APP_EXE}"
    Delete "$INSTDIR\Uninstall.exe"
    RMDir /r "$INSTDIR"
    
    Delete "$SMPROGRAMS\${APP_NAME}\${APP_NAME}.lnk"
    Delete "$DESKTOP\${APP_NAME}.lnk"
    RMDir "$SMPROGRAMS\${APP_NAME}"
    
    DeleteRegKey HKCU "Software\${APP_NAME}"
SectionEnd