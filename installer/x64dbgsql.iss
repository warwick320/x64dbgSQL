[Setup]
AppId=x64dbgSQL.warwick320
AppName=x64dbgSQL
AppVersion={#Version}
AppPublisher=x64dbgSQL contributors
AppPublisherURL=https://github.com/warwick320/x64dbgSQL
AppUpdatesURL=https://github.com/warwick320/x64dbgSQL/releases
DefaultDirName={localappdata}\x64dbg\release
DisableDirPage=no
DisableProgramGroupPage=yes
DisableStartupPrompt=yes
DirExistsWarning=no
PrivilegesRequired=lowest
ArchitecturesAllowed=x64compatible
LicenseFile={#Payload}\LICENSE
UninstallFilesDir={app}\.x64dbgsql
UninstallDisplayIcon={app}\x64dbgsql.exe
CloseApplications=no
RestartApplications=no
WizardStyle=modern
OutputDir={#Destination}
OutputBaseFilename=x64dbgsql-setup
Compression=lzma2
SolidCompression=yes

[Messages]
SelectDirDesc=Choose the directory that contains your x64dbg installation.
SelectDirLabel3=Select the parent folder of x64 and x32. It is usually named release. Close any running debugger sessions before installing.

[Files]
Source: "{#Payload}\x64dbgsql.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#Payload}\x64dbgsql-headless.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#Payload}\x64\plugins\x64dbgsql.dp64"; DestDir: "{app}\x64\plugins"; Flags: ignoreversion; Check: HasX64
Source: "{#Payload}\x32\plugins\x64dbgsql.dp32"; DestDir: "{app}\x32\plugins"; Flags: ignoreversion; Check: HasX32
Source: "{#Payload}\LICENSE"; DestDir: "{app}\.x64dbgsql"; Flags: ignoreversion
Source: "{#Payload}\licenses\*"; DestDir: "{app}\.x64dbgsql\licenses"; Flags: ignoreversion

[Code]
const
  UninstallKey = 'Software\Microsoft\Windows\CurrentVersion\Uninstall\x64dbgSQL.warwick320_is1';

function HasX64: Boolean;
begin
  Result := FileExists(AddBackslash(WizardDirValue) + 'x64\x64dbg.exe');
end;

function HasX32: Boolean;
begin
  Result := FileExists(AddBackslash(WizardDirValue) + 'x32\x32dbg.exe');
end;

function ValidateDirectory: String;
var
  Target, Previous: String;
begin
  Result := '';
  Target := AddBackslash(WizardDirValue);
  if not (HasX64 or HasX32) then
    Result := 'Select a folder containing x64\x64dbg.exe or x32\x32dbg.exe.'
  else if RegQueryStringValue(HKCU, UninstallKey, 'InstallLocation', Previous) then
  begin
    if CompareText(Target, AddBackslash(Previous)) <> 0 then
      Result := 'Uninstall x64dbgSQL from its previous location before installing here.';
  end
  else if FileExists(Target + 'x64dbgsql.exe') or
          FileExists(Target + 'x64dbgsql-headless.exe') or
          (HasX64 and FileExists(Target + 'x64\plugins\x64dbgsql.dp64')) or
          (HasX32 and FileExists(Target + 'x32\plugins\x64dbgsql.dp32')) or
          DirExists(Target + '.x64dbgsql') then
    Result := 'An existing x64dbgSQL file is in this folder. Move the previous manual installation before continuing.';
end;

function NextButtonClick(CurPageID: Integer): Boolean;
var
  Problem: String;
begin
  Result := True;
  if (CurPageID = wpSelectDir) and not WizardSilent then
  begin
    Problem := ValidateDirectory;
    if Problem <> '' then
    begin
      MsgBox(Problem, mbError, MB_OK);
      Result := False;
    end;
  end;
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
begin
  Result := ValidateDirectory;
end;
