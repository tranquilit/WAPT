library waptguihelper;

{$mode delphi}{$H+}

{$R *.res}

uses
  Classes,SysUtils,
  PythonEngine, Forms,uWaptBuildParams, uscaledpi,Controls, Interfaces
  { you can add units after this };

var
  PyE:TPythonEngine;
  Methods : packed array [0..2] of PyMethodDef;

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
  //title, key path, key passwd
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


exports
  initwaptguihelper;

initialization
  PyE := TPythonEngine.Create(Nil);
  PyE.Initialize;
  Application.Initialize;

finalization
  if Assigned(Pye) then
    FreeAndNil(PyE);
end.

