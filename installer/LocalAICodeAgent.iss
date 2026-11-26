#define MyAppName "Forge"
#define MyAppVersion "1.4.0"
#define MyAppPublisher "Forge"
#define MyAppExeName "LocalAICodeAgent.exe"

[Setup]
AppId={{D26F4B0E-28AB-48D8-A03C-AE88E47CB8D1}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
DefaultDirName={autopf}\Forge
DefaultGroupName={#MyAppName}
OutputDir=output
OutputBaseFilename=LocalAICodeAgent-Setup
SetupIconFile=..\src\assets\forge.ico
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
ArchitecturesInstallIn64BitMode=x64compatible
PrivilegesRequired=lowest
UninstallDisplayIcon={app}\{#MyAppExeName}

[Files]
; Ship the entire PyInstaller onedir output (exe + _internal runtime).
Source: "..\dist\LocalAICodeAgent\*"; DestDir: "{app}"; Flags: recursesubdirs createallsubdirs ignoreversion
Source: "..\README.md"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon

[Tasks]
Name: "desktopicon"; Description: "Create a &desktop shortcut"; GroupDescription: "Additional icons:"

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "Launch {#MyAppName}"; Flags: nowait postinstall skipifsilent
