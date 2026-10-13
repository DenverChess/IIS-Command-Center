; IIS Sentinel - Windows installer (Inno Setup 6).
; Built by installer\build.ps1, which stages an embedded CPython runtime + dependencies + WinSW into StageDir.
;
; Silent install / upgrade:
;   IISSentinel-Setup-2.0.0.exe /VERYSILENT /SUPPRESSMSGBOXES /NORESTART
;       /ADMINPASSWORD=<pw>   break-glass password (required on first install, optional on upgrade)
;       /ADMINUSER=<name>     break-glass account name (default sentinel-admin)
;       /PORT=<port>          console port (default 1337)
;       /REMOTEACCESS=1|0     listen on all interfaces + open the port in Windows Firewall (default 0)
; Silent uninstall keeps %ProgramData%\IIS Sentinel unless /PURGEDATA is passed to unins000.exe.

#ifndef AppVersion
  #define AppVersion "2.0.0"
#endif
#ifndef StageDir
  #define StageDir "build\stage"
#endif
#ifndef OutputDir
  #define OutputDir "..\dist"
#endif

#define AppName "IIS Sentinel"
#define ServiceId "IISSentinel"
#define FirewallRule "IIS Sentinel SOC"
#define DataDirName "IIS Sentinel"

[Setup]
AppId={{6F1C2B9E-3D4A-4E8B-9C21-5A7E0D3F8B14}
AppName={#AppName}
AppVersion={#AppVersion}
AppVerName={#AppName} {#AppVersion}
AppPublisher=IIS Sentinel
VersionInfoVersion={#AppVersion}
VersionInfoDescription={#AppName} Setup
DefaultDirName={autopf}\{#AppName}
DefaultGroupName={#AppName}
DisableProgramGroupPage=yes
PrivilegesRequired=admin
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0
OutputDir={#OutputDir}
OutputBaseFilename=IISSentinel-Setup-{#AppVersion}
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
SetupLogging=yes
CloseApplications=no
UninstallDisplayName={#AppName}
UninstallDisplayIcon={app}\python\python.exe

[Files]
Source: "{#StageDir}\python\*"; DestDir: "{app}\python"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "{#StageDir}\app\*"; DestDir: "{app}\app"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "{#StageDir}\IISSentinelService.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#StageDir}\reset-password.cmd"; DestDir: "{app}"; Flags: ignoreversion

[Dirs]
Name: "{commonappdata}\{#DataDirName}"; Flags: uninsneveruninstall

[INI]
Filename: "{app}\IIS Sentinel Console.url"; Section: "InternetShortcut"; Key: "URL"; String: "{code:ConsoleUrl}"

[Icons]
Name: "{group}\IIS Sentinel Console"; Filename: "{app}\IIS Sentinel Console.url"
Name: "{group}\Reset Break-glass Password"; Filename: "{app}\reset-password.cmd"; WorkingDir: "{app}"
Name: "{group}\Data and Logs"; Filename: "{commonappdata}\{#DataDirName}"
Name: "{group}\Uninstall IIS Sentinel"; Filename: "{uninstallexe}"
Name: "{commondesktop}\IIS Sentinel Console"; Filename: "{app}\IIS Sentinel Console.url"; Tasks: desktopicon

[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut to the console"; Flags: unchecked

[Run]
Filename: "{code:ConsoleUrl}"; Description: "Open the IIS Sentinel console"; Flags: postinstall shellexec skipifsilent nowait

[UninstallDelete]
Type: files; Name: "{app}\IISSentinelService.xml"
Type: files; Name: "{app}\IIS Sentinel Console.url"
Type: filesandordirs; Name: "{app}\app"
Type: filesandordirs; Name: "{app}\python"
Type: dirifempty; Name: "{app}"

[Code]
const
  ServiceId = '{#ServiceId}';
  FirewallRule = '{#FirewallRule}';
  SetupPasswordVar = 'SENTINEL_SETUP_PASSWORD';
  MinPasswordLength = 8;

var
  SettingsPage: TInputQueryWizardPage;
  NetworkPage: TInputOptionWizardPage;

function SetEnvironmentVariable(lpName: string; lpValue: string): BOOL;
  external 'SetEnvironmentVariableW@kernel32.dll stdcall';
function ClearEnvironmentVariable(lpName: string; lpValue: Cardinal): BOOL;
  external 'SetEnvironmentVariableW@kernel32.dll stdcall';

{ ---------------------------------------------------------------- helpers }

function GetParam(const Name, Default: string): string;
var
  I: Integer;
  Prefix: string;
begin
  Result := Default;
  Prefix := '/' + Uppercase(Name) + '=';
  for I := 1 to ParamCount do
    if Pos(Prefix, Uppercase(ParamStr(I))) = 1 then
    begin
      Result := Copy(ParamStr(I), Length(Prefix) + 1, MaxInt);
      Exit;
    end;
end;

function HasSwitch(const Name: string): Boolean;
var
  I: Integer;
begin
  Result := False;
  for I := 1 to ParamCount do
    if CompareText(ParamStr(I), '/' + Name) = 0 then
    begin
      Result := True;
      Exit;
    end;
end;

function DataDir: string;
begin
  Result := ExpandConstant('{commonappdata}\{#DataDirName}');
end;

function AdminAccountExists: Boolean;
begin
  Result := FileExists(DataDir + '\local_admin.json');
end;

function PortValue: string;
begin
  Result := Trim(SettingsPage.Values[0]);
end;

function AdminUser: string;
begin
  Result := Trim(SettingsPage.Values[1]);
end;

function AdminPassword: string;
begin
  Result := SettingsPage.Values[2];
end;

function RemoteAccess: Boolean;
begin
  Result := NetworkPage.Values[0];
end;

function ConsoleUrl(Param: string): string;
begin
  Result := 'http://127.0.0.1:' + PortValue + '/';
end;

function XmlEscape(const S: string): string;
begin
  Result := S;
  StringChangeEx(Result, '&', '&amp;', True);
  StringChangeEx(Result, '<', '&lt;', True);
  StringChangeEx(Result, '>', '&gt;', True);
  StringChangeEx(Result, '"', '&quot;', True);
end;

function RunHidden(const Exe, Params: string): Integer;
begin
  Log('Exec: ' + Exe + ' ' + Params);
  if not Exec(Exe, Params, '', SW_HIDE, ewWaitUntilTerminated, Result) then
  begin
    Log('  failed to launch: ' + SysErrorMessage(Result));
    Result := -1;
  end
  else
    Log('  exit code ' + IntToStr(Result));
end;

function PowerShell(const Script: string): Integer;
begin
  Result := RunHidden(ExpandConstant('{sys}\WindowsPowerShell\v1.0\powershell.exe'),
    '-NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "' + Script + '"');
end;

function ServiceExists: Boolean;
begin
  Result := RunHidden(ExpandConstant('{sys}\sc.exe'), 'query ' + ServiceId) = 0;
end;

{ Stops the service and waits until it (and its python child) has fully exited. }
function StopService: Boolean;
begin
  Result := True;
  if not ServiceExists then
    Exit;
  Result := PowerShell(
    '$s = Get-Service -Name ' + ServiceId + ' -ErrorAction SilentlyContinue; ' +
    'if (-not $s) { exit 0 }; ' +
    'if ($s.Status -ne ''Stopped'') { Stop-Service -Name ' + ServiceId + ' -Force -ErrorAction SilentlyContinue }; ' +
    'try { $s.WaitForStatus(''Stopped'', ''00:00:45''); exit 0 } catch { exit 1 }') = 0;
end;

{ ------------------------------------------------------------ validation }

function ValidateSettings: string;
var
  Port, I: Integer;
  User: string;
begin
  Result := '';
  Port := StrToIntDef(PortValue, -1);
  if (Port < 1) or (Port > 65535) then
  begin
    Result := 'The console port must be a number between 1 and 65535.';
    Exit;
  end;
  User := AdminUser;
  if (Length(User) < 1) or (Length(User) > 64) then
  begin
    Result := 'Enter a break-glass account name (1-64 characters).';
    Exit;
  end;
  for I := 1 to Length(User) do
    if Pos(User[I], 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-@') = 0 then
    begin
      Result := 'The account name may only contain letters, digits, ''.'', ''_'', ''-'' and ''@''.';
      Exit;
    end;
  if AdminPassword = '' then
  begin
    if not AdminAccountExists then
      Result := 'Set a break-glass password. It is the only way to sign in until Active Directory is configured.';
    Exit;
  end;
  if Length(AdminPassword) < MinPasswordLength then
    Result := 'The break-glass password must be at least ' + IntToStr(MinPasswordLength) + ' characters.'
  else if AdminPassword <> SettingsPage.Values[3] then
    Result := 'The two passwords do not match.';
end;

{ ----------------------------------------------------------------- wizard }

procedure InitializeWizard;
var
  Password: string;
begin
  SettingsPage := CreateInputQueryPage(wpSelectDir, 'Console settings',
    'Web console port and break-glass administrator',
    'Analysts normally sign in with Active Directory. The break-glass account is a local administrator that always ' +
    'works, even when AD is unreachable. Its password is stored only as a salted PBKDF2 hash.' + #13#10 + #13#10 +
    'Leave the password empty on an upgrade to keep the existing account.');
  SettingsPage.Add('Console port:', False);
  SettingsPage.Add('Break-glass account name:', False);
  SettingsPage.Add('Break-glass password:', True);
  SettingsPage.Add('Confirm password:', True);

  SettingsPage.Values[0] := GetParam('PORT', GetPreviousData('Port', '1337'));
  SettingsPage.Values[1] := GetParam('ADMINUSER', GetPreviousData('AdminUser', 'sentinel-admin'));
  Password := GetParam('ADMINPASSWORD', '');
  SettingsPage.Values[2] := Password;
  SettingsPage.Values[3] := Password;

  NetworkPage := CreateInputOptionPage(SettingsPage.ID, 'Network access',
    'Who can reach the SOC console?',
    'By default the console only listens on this workstation (127.0.0.1). Enable remote access to let other ' +
    'analysts open it from their machines; setup then listens on all interfaces and opens the port in Windows ' +
    'Firewall for the Domain and Private profiles.',
    False, False);
  NetworkPage.Add('Allow other computers on the network to open the console');
  NetworkPage.Values[0] := GetParam('REMOTEACCESS', GetPreviousData('RemoteAccess', '0')) = '1';
end;

procedure RegisterPreviousData(PreviousDataKey: Integer);
begin
  SetPreviousData(PreviousDataKey, 'Port', PortValue);
  SetPreviousData(PreviousDataKey, 'AdminUser', AdminUser);
  if RemoteAccess then
    SetPreviousData(PreviousDataKey, 'RemoteAccess', '1')
  else
    SetPreviousData(PreviousDataKey, 'RemoteAccess', '0');
end;

function NextButtonClick(CurPageID: Integer): Boolean;
var
  Error: string;
begin
  Result := True;
  if CurPageID = SettingsPage.ID then
  begin
    Error := ValidateSettings;
    if Error <> '' then
    begin
      MsgBox(Error, mbError, MB_OK);
      Result := False;
    end;
  end;
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
begin
  Result := ValidateSettings;
  if Result <> '' then
    Exit;
  WizardForm.StatusLabel.Caption := 'Stopping the IIS Sentinel service...';
  if not StopService then
  begin
    Result := 'The IIS Sentinel service did not stop within 45 seconds. Stop it manually (services.msc) and run setup again.';
    Exit;
  end;
  { Start from a clean application tree so files removed in this version do not linger. }
  DelTree(ExpandConstant('{app}\app'), True, True, True);
end;

{ ----------------------------------------------------------- post-install }

procedure SecureDataDir;
begin
  { DPAPI secrets are machine-scoped, so the database must be unreadable to non-admin local users. }
  RunHidden(ExpandConstant('{sys}\icacls.exe'),
    '"' + DataDir + '" /inheritance:r /grant:r *S-1-5-18:(OI)(CI)F *S-1-5-32-544:(OI)(CI)F');
end;

procedure WriteServiceConfig;
var
  Lines: TArrayOfString;
  App, Host: string;
begin
  App := ExpandConstant('{app}');
  if RemoteAccess then Host := '0.0.0.0' else Host := '127.0.0.1';
  SetArrayLength(Lines, 24);
  Lines[0] := '<?xml version="1.0" encoding="utf-8"?>';
  Lines[1] := '<service>';
  Lines[2] := '  <id>' + ServiceId + '</id>';
  Lines[3] := '  <name>IIS Sentinel SOC</name>';
  Lines[4] := '  <description>Centralized IIS 10 security monitoring console (IIS Sentinel {#AppVersion}).</description>';
  Lines[5] := '  <executable>' + XmlEscape(App + '\python\python.exe') + '</executable>';
  Lines[6] := '  <arguments>"' + XmlEscape(App + '\app\main.py') + '"</arguments>';
  Lines[7] := '  <workingdirectory>' + XmlEscape(App + '\app') + '</workingdirectory>';
  Lines[8] := '  <env name="SENTINEL_DATA_DIR" value="' + XmlEscape(DataDir) + '"/>';
  Lines[9] := '  <env name="SENTINEL_HOST" value="' + Host + '"/>';
  Lines[10] := '  <env name="SENTINEL_PORT" value="' + PortValue + '"/>';
  Lines[11] := '  <env name="PYTHONUNBUFFERED" value="1"/>';
  Lines[12] := '  <logpath>' + XmlEscape(DataDir + '\service-logs') + '</logpath>';
  Lines[13] := '  <log mode="roll-by-size">';
  Lines[14] := '    <sizeThreshold>10240</sizeThreshold>';
  Lines[15] := '    <keepFiles>8</keepFiles>';
  Lines[16] := '  </log>';
  Lines[17] := '  <onfailure action="restart" delay="10 sec"/>';
  Lines[18] := '  <onfailure action="restart" delay="30 sec"/>';
  Lines[19] := '  <resetfailure>1 hour</resetfailure>';
  Lines[20] := '  <startmode>Automatic</startmode>';
  Lines[21] := '  <delayedAutoStart>true</delayedAutoStart>';
  Lines[22] := '  <stoptimeout>20 sec</stoptimeout>';
  Lines[23] := '</service>';
  if not SaveStringsToUTF8File(App + '\IISSentinelService.xml', Lines, False) then
    RaiseException('Could not write ' + App + '\IISSentinelService.xml');
end;

function SaveAdminAccount: Boolean;
var
  Code: Integer;
begin
  Result := True;
  if AdminPassword = '' then
    Exit;
  WizardForm.StatusLabel.Caption := 'Saving the break-glass account...';
  { The password travels via an inherited environment variable, never on a command line. }
  SetEnvironmentVariable(SetupPasswordVar, AdminPassword);
  SetEnvironmentVariable('SENTINEL_DATA_DIR', DataDir);
  try
    Code := RunHidden(ExpandConstant('{app}\python\python.exe'),
      '"' + ExpandConstant('{app}\app\sentinelctl.py') + '" set-admin-password --user "' + AdminUser +
      '" --from-env ' + SetupPasswordVar);
  finally
    ClearEnvironmentVariable(SetupPasswordVar, 0);
    ClearEnvironmentVariable('SENTINEL_DATA_DIR', 0);
  end;
  Result := Code = 0;
end;

procedure ConfigureFirewall;
begin
  RunHidden(ExpandConstant('{sys}\netsh.exe'), 'advfirewall firewall delete rule name="' + FirewallRule + '"');
  if RemoteAccess then
    RunHidden(ExpandConstant('{sys}\netsh.exe'),
      'advfirewall firewall add rule name="' + FirewallRule + '" dir=in action=allow protocol=TCP localport=' +
      PortValue + ' profile=domain,private');
end;

function StartService: Boolean;
var
  Winsw: string;
begin
  Winsw := ExpandConstant('{app}\IISSentinelService.exe');
  if not ServiceExists then
    if RunHidden(Winsw, 'install') <> 0 then
    begin
      Result := False;
      Exit;
    end;
  Result := RunHidden(Winsw, 'start') = 0;
end;

function WaitForConsole: Boolean;
begin
  Result := PowerShell(
    'for ($i = 0; $i -lt 45; $i++) { ' +
    'try { $r = Invoke-WebRequest -UseBasicParsing -TimeoutSec 3 -Uri http://127.0.0.1:' + PortValue + '/healthz; ' +
    'if ($r.StatusCode -eq 200) { exit 0 } } catch { }; Start-Sleep -Seconds 1 }; exit 1') = 0;
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep <> ssPostInstall then
    Exit;
  WizardForm.StatusLabel.Caption := 'Securing the data directory...';
  ForceDirectories(DataDir);
  SecureDataDir;
  if not SaveAdminAccount then
    SuppressibleMsgBox('The break-glass account could not be saved. Run "Reset Break-glass Password" from the ' +
      'Start menu after setup finishes.', mbError, MB_OK, IDOK);
  WizardForm.StatusLabel.Caption := 'Configuring the IIS Sentinel service...';
  WriteServiceConfig;
  ConfigureFirewall;
  WizardForm.StatusLabel.Caption := 'Starting the IIS Sentinel service...';
  if not StartService then
    SuppressibleMsgBox('The IIS Sentinel service could not be started. Check the logs in ' + DataDir +
      '\service-logs and start it from services.msc.', mbError, MB_OK, IDOK)
  else
  begin
    WizardForm.StatusLabel.Caption := 'Waiting for the console to come online...';
    if not WaitForConsole then
      SuppressibleMsgBox('The service started but the console did not answer on port ' + PortValue +
        ' within 45 seconds. Check ' + DataDir + '\sentinel.log and ' + DataDir + '\service-logs.',
        mbInformation, MB_OK, IDOK);
  end;
end;

{ -------------------------------------------------------------- uninstall }

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  Purge: Boolean;
begin
  if CurUninstallStep = usUninstall then
  begin
    StopService;
    if FileExists(ExpandConstant('{app}\IISSentinelService.exe')) then
      RunHidden(ExpandConstant('{app}\IISSentinelService.exe'), 'uninstall')
    else
      RunHidden(ExpandConstant('{sys}\sc.exe'), 'delete ' + ServiceId);
    RunHidden(ExpandConstant('{sys}\netsh.exe'), 'advfirewall firewall delete rule name="' + FirewallRule + '"');
  end
  else if CurUninstallStep = usPostUninstall then
  begin
    if not DirExists(DataDir) then
      Exit;
    if UninstallSilent then
      Purge := HasSwitch('PURGEDATA')
    else
      Purge := MsgBox('Delete the IIS Sentinel database, settings, reports and logs in ' + DataDir + '?' + #13#10 + #13#10 +
        'Choose No to keep them for a future reinstall. Firewall bans already pushed to IIS servers are not removed.',
        mbConfirmation, MB_YESNO or MB_DEFBUTTON2) = IDYES;
    if Purge then
      DelTree(DataDir, True, True, True);
  end;
end;
