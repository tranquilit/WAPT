library waptguihelper;

{$mode delphi}{$H+}

{$R *.res}

uses
  Classes,SysUtils,Windows,
  PythonEngine, Forms,uWaptBuildParams, Controls, Interfaces,
  LazFileUtils,LazUTF8,registry
  { you can add units after this };

var
  PyE:TPythonEngine;
  Methods : packed array [0..2] of PyMethodDef;
  RegWaptBaseDir: String;

function BuildParamsDialog(Self : PPyObject;
                          Args : PPyObject):PPyObject;  cdecl;
var
  pTitle, pConfig,pServerURL,pUser,pPassword,pKeyPath,pKeyPassword:PAnsiChar;
begin
  //config,server_url,user,passwd,keypath,keypassword
  PyE.PyArg_ParseTuple(Args, 'sssssss', @pTitle,@pConfig,@pServerURL,@pUser,@pPassword,@pKeyPath,@pKeyPassword);
  with TVisWaptBuildParams.Create(Nil) do
  try
    labServer.Visible:= True;
    edWaptServerName.Visible:=True;
    labUser.Visible := True;
    EdUser.Visible:= True;
    LabPassword.Visible:= True;
    EdPassword.Visible:= True;

    LabKeyPath.Visible:=True;
    EdKeyPath.Visible:=True;
    LabKeyPassword.Visible:=True;
    EdKeyPassword.Visible:=True;

    Caption := pTitle;
    CBConfiguration.Text:=pConfig;
    edWaptServerName.Text:=pServerURL;
    EdUser.Text := pUser;
    EdPassword.Text := pPassword;

    EdKeyPath.Caption := pKeyPath;
    edKeyPassword.Text := pKeyPassword;

    if ShowModal = mrOk then
    begin
      Result := PyE.PyDict_New();
      PyE.PyDict_SetItemString(Result,'config',Pye.PyString_FromString(PChar(CBConfiguration.Text)));
      PyE.PyDict_SetItemString(Result,'user',Pye.PyString_FromString(PChar(EdUser.Text)));
      PyE.PyDict_SetItemString(Result,'password',Pye.PyString_FromString(PChar(edPassword.Text)));
      PyE.PyDict_SetItemString(Result,'keypassword',Pye.PyString_FromString(PChar(edKeyPassword.Text)));
    end
    else
      Result := PyE.Py_None;
  finally
    Free;
  end;
end;

function LoginPasswordDialog(Self : PPyObject;
                             Args : PPyObject):PPyObject;  cdecl;
var
  pTitle, pServerURL,pUser,pPassword:PAnsiChar;
begin
  //config,server_url,user,passwd,keypath,keypassword
  PyE.PyArg_ParseTuple(Args, 'ssss', @pTitle,@pServerURL,@pUser,@pPassword);
  with TVisWaptBuildParams.Create(Nil) do
  try
    labServer.Visible:= True;
    edWaptServerName.Visible:=True;

    labUser.Visible := True;
    EdUser.Visible:= True;

    labPassword.Visible:= True;
    edPassword.Visible:= True;

    Caption:=pTitle;
    edWaptServerName.Text:=pServerURL;
    EdUser.Text := pUser;
    edPassword.Text := pPassword;

    if ShowModal = mrOk then
    begin
      Result := PyE.PyDict_New();
      PyE.PyDict_SetItemString(Result,'user',Pye.PyString_FromString(PChar(EdUser.Text)));
      PyE.PyDict_SetItemString(Result,'password',Pye.PyString_FromString(PChar(edPassword.Text)));
    end
    else
      Result := PyE.Py_None;
  finally
    Free;
  end;
end;

function KeyPasswordDialog(Self : PPyObject;
                             Args : PPyObject):PPyObject;  cdecl;
var
  pTitle, pKeypath,pKeyPassword:PAnsiChar;
begin
  //title, key path, key passwd 3 strings thus 'sss'
  PyE.PyArg_ParseTuple(Args, 'sss', @pTitle,@pKeyPath,@pKeyPassword);
  with TVisWaptBuildParams.Create(Nil) do
  try
    LabKeyPath.Visible:=True;
    EdKeyPath.Visible:=True;
    LabKeyPassword.Visible:=True;
    EdKeyPassword.Visible:=True;

    Caption:=pTitle;
    edKeyPath.Caption := pKeyPath;
    edKeyPassword.Text := pKeyPassword;

    if ShowModal = mrOk then
    begin
      Result := PyE.PyDict_New();
      PyE.PyDict_SetItemString(Result,'keypassword',Pye.PyString_FromString(PChar(edKeyPassword.Text)));
    end
    else
      Result := PyE.Py_None;
  finally
    Free;
  end;
end;

procedure initwaptguihelper; cdecl;
begin
  Methods[0].ml_name := 'build_params_dialog';
  Methods[0].ml_meth := @BuildParamsDialog;
  Methods[0].ml_flags := METH_VARARGS;
  Methods[0].ml_doc := 'Dialog which asks for user, password and key password for package build / upload. title,configpath,server_url,user,password,keypath,keypassword';

  Methods[1].ml_name := 'login_password_dialog';
  Methods[1].ml_meth := @LoginPasswordDialog;
  Methods[1].ml_flags := METH_VARARGS;
  Methods[1].ml_doc := 'Dialog which asks for user, password; title, server_url,user,password';

  Methods[2].ml_name := 'key_password_dialog';
  Methods[2].ml_meth := @KeyPasswordDialog;
  Methods[2].ml_flags := METH_VARARGS;
  Methods[2].ml_doc := 'Dialog which asks for private key password; title, keypath, keypassword';


  Pye.Py_InitModule('waptguihelper', @Methods[0]);
end;

function WaptBaseDir: String;
begin
  result := ExtractFileDir(ParamStrUTF8(0));
  if lowercase(ExtractFileName(result)) = 'scripts' then
    Result := ExtractFileDir(result);
  Result := AppendPathDelim(Result);
end;


{$ifdef windows}
// Get the registered install location for an application from registry given its executable name
function RegisteredAppInstallLocation(UninstallKey:String): String;
var
  Reg: TRegistry;
  KeyPath: String;
begin
  result := '';
  Reg := TRegistry.Create(KEY_READ or KEY_WOW64_64KEY);
  With Reg do
  try
    RootKey:=HKEY_LOCAL_MACHINE;
    KeyPath := 'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\'+UninstallKey;
    if KeyExists(KeyPath) and OpenKey(KeyPath,False) then
    begin
      Result := ReadString('InstallLocation');
      CloseKey;
    end
    else
    begin
      KeyPath := 'SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\'+UninstallKey;
      if KeyExists(KeyPath) and OpenKey(KeyPath,False) then
      begin
        Result := ReadString('InstallLocation');
        CloseKey;
      end;
    end;
  finally
    Reg.Free;
  end;
end;

// Get the registered application location from registry given its executable name
function RegisteredExePath(ExeName:String): String;
var
  Reg: TRegistry;
  KeyPath: String;
begin
  result := '';
  Reg := TRegistry.Create(KEY_READ or KEY_WOW64_64KEY);
  With Reg do
  try
    RootKey:=HKEY_LOCAL_MACHINE;
    KeyPath := 'SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\'+ExeName;
    if KeyExists(KeyPath) and OpenKey(KeyPath,False) then
    begin
      Result := ReadString('');
      CloseKey;
    end
    else
    begin
      KeyPath := 'SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\App Paths\'+ExeName;
      if KeyExists(KeyPath) and OpenKey(KeyPath,False) then
      begin
        Result := ReadString('');
        CloseKey;
      end;
    end;
  finally
    Reg.Free;
  end;
end;

{$endif}

exports
  initwaptguihelper;

initialization
  PyE := TPythonEngine.Create(Nil);

  RegWaptBaseDir:=WaptBaseDir();
  {$ifdef windows}
  if not FileExistsUTF8(AppendPathDelim(RegWaptBaseDir)+'python27.dll') then
    RegWaptBaseDir:=RegisteredAppInstallLocation('wapt_is1');
  if not FileExistsUTF8(AppendPathDelim(RegWaptBaseDir)+'python27.dll') then
    RegWaptBaseDir:=RegisteredAppInstallLocation('WAPT Server_is1');
  if RegWaptBaseDir='' then
    RegWaptBaseDir:=ExtractFilePath(RegisteredExePath('wapt-get.exe'));
  {$endif}

  With PyE do
  begin
    AutoLoad := False;
    // We should not specify dll path to avoid being in conflict with already python DLL
    // in PyScripter / RPyc.
    // If we force path here, we have an "SystemError: dynamic module not initialized properly"
    // when importing module in wapt-get.py...
    // removed : DllPath := RegWaptBaseDir;
    DllName := 'python27.dll';
    SetPythonHome(RegWaptBaseDir);

    UseLastKnownVersion := False;
    FatalAbort:=True;
    FatalMsgDlg:=False;

    LoadDLL;
  end;
  Application.Scaled := True;
  RequireDerivedFormResource := True;
  Application.Initialize;

finalization
  if Assigned(Pye) then
    FreeAndNil(PyE);
end.

