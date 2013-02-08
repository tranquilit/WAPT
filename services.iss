//
// Services functions for InnoSetup 5.x
// Version 1.1
//
// The contents of this file are subject to the Mozilla Public License
// Version 1.1 (the "License"); you may not use this file except in
// compliance with the License. You may obtain a copy of the License at
// http://www.mozilla.org/MPL/
//
// Software distributed under the License is distributed on an "AS IS"
// basis, WITHOUT WARRANTY OF ANY KIND, either express or implied. See the
// License for the specific language governing rights and limitations
// under the License.
//
// The Original Code is services.iss.
//
// The Initial Developer of the Original Code is Luigi D. Sandon
// Copyright © 2006-2008 Luigi D. Sandon. All Rights Reserved.
//
//
// Note on passing PChars using RemObjects Pascal Script
// '' pass a nil PChar
// #0 pass an empty PChar
//

type
  _SERVICE_STATUS = record
    dwServiceType: Longword;
    dwCurrentState: Longword;
    dwControlsAccepted: Longword;
    dwWin32ExitCode: Longword;
    dwServiceSpecificExitCode: Longword;
    dwCheckPoint: Longword;
    dwWaitHint: Longword;
  end;

const
  NO_ERROR = 0;
  STANDARD_RIGHTS_REQUIRED = $F0000;

  //
  // Service Control Manager object specific access types
  //
  SC_MANAGER_CONNECT = $0001;
  SC_MANAGER_CREATE_SERVICE = $0002;
  SC_MANAGER_ENUMERATE_SERVICE = $0004;
  SC_MANAGER_LOCK = $0008;
  SC_MANAGER_QUERY_LOCK_STATUS = $0010;
  SC_MANAGER_MODIFY_BOOT_CONFIG = $0020;

  SC_MANAGER_ALL_ACCESS  =
    (STANDARD_RIGHTS_REQUIRED +
    SC_MANAGER_CONNECT +
    SC_MANAGER_CREATE_SERVICE +
    SC_MANAGER_ENUMERATE_SERVICE +
    SC_MANAGER_LOCK +
    SC_MANAGER_QUERY_LOCK_STATUS +
    SC_MANAGER_MODIFY_BOOT_CONFIG);

  //
  // No change constant
  //
  SERVICE_NO_CHANGE = $FFFFFFFF;

  //
  // Service Types (Bit Mask)
  //
  SERVICE_KERNEL_DRIVER = $00000001;
  SERVICE_FILE_SYSTEM_DRIVER = $00000002;
  SERVICE_ADAPTER = $00000004;
  SERVICE_RECOGNIZER_DRIVER = $00000008;

  SERVICE_DRIVER =
    (SERVICE_KERNEL_DRIVER +
     SERVICE_FILE_SYSTEM_DRIVER +
     SERVICE_RECOGNIZER_DRIVER);

  SERVICE_WIN32_OWN_PROCESS = $00000010;
  SERVICE_WIN32_SHARE_PROCESS = $00000020;
  SERVICE_WIN32 =
    (SERVICE_WIN32_OWN_PROCESS +
    SERVICE_WIN32_SHARE_PROCESS);

  SERVICE_INTERACTIVE_PROCESS = $00000100;

  SERVICE_TYPE_ALL =
    (SERVICE_WIN32 +
    SERVICE_ADAPTER +
    SERVICE_DRIVER +
    SERVICE_INTERACTIVE_PROCESS);

  //
  // Start Type
  //
  SERVICE_BOOT_START = $00000000;
  SERVICE_SYSTEM_START = $00000001;
  SERVICE_AUTO_START = $00000002;
  SERVICE_DEMAND_START = $00000003;
  SERVICE_DISABLED = $00000004;

  //
  // Error control type
  //
  SERVICE_ERROR_IGNORE = $00000000;
  SERVICE_ERROR_NORMAL = $00000001;
  SERVICE_ERROR_SEVERE = $00000002;
  SERVICE_ERROR_CRITICAL = $00000003;

  //
  // Service object specific access type
  //
  SERVICE_QUERY_CONFIG = $0001;
  SERVICE_CHANGE_CONFIG = $0002;
  SERVICE_QUERY_STATUS = $0004;
  SERVICE_ENUMERATE_DEPENDENTS = $0008;
  SERVICE_START= $0010;
  SERVICE_STOP= $0020;
  SERVICE_PAUSE_CONTINUE = $0040;
  SERVICE_INTERROGATE = $0080;
  SERVICE_USER_DEFINED_CONTROL = $0100;

  SERVICE_ALL_ACCESS =
    (STANDARD_RIGHTS_REQUIRED +
    SERVICE_QUERY_CONFIG +
    SERVICE_CHANGE_CONFIG +
    SERVICE_QUERY_STATUS +
    SERVICE_ENUMERATE_DEPENDENTS +
    SERVICE_START +
    SERVICE_STOP +
    SERVICE_PAUSE_CONTINUE +
    SERVICE_INTERROGATE +
    SERVICE_USER_DEFINED_CONTROL);

  //
  // Controls
  //
  SERVICE_CONTROL_STOP = $00000001;
  SERVICE_CONTROL_PAUSE = $00000002;
  SERVICE_CONTROL_CONTINUE = $00000003;
  SERVICE_CONTROL_INTERROGATE = $00000004;

  //
  // Status
  //
  SERVICE_CONTINUE_PENDING = $00000005;
  SERVICE_PAUSE_PENDING = $00000006;
  SERVICE_PAUSED = $00000007;
  SERVICE_RUNNING = $00000004;
  SERVICE_START_PENDING = $00000002;
  SERVICE_STOP_PENDING = $00000003;
  SERVICE_STOPPED = $00000001;


  //
  //  Error codes
  //
  ERROR_DEPENDENT_SERVICES_RUNNING = 1051;
  ERROR_INVALID_SERVICE_CONTROL = 1052;
  ERROR_SERVICE_REQUEST_TIMEOUT = 1053;
  ERROR_SERVICE_NO_THREAD = 1054;
  ERROR_SERVICE_DATABASE_LOCKED = 1055;
  ERROR_SERVICE_ALREADY_RUNNING = 1056;
  ERROR_INVALID_SERVICE_ACCOUNT = 1057;
  ERROR_SERVICE_DISABLED = 1058;
  ERROR_CIRCULAR_DEPENDENCY = 1059;
  ERROR_SERVICE_DOES_NOT_EXIST = 1060;
  ERROR_SERVICE_CANNOT_ACCEPT_CTRL = 1061;
  ERROR_SERVICE_NOT_ACTIVE = 1062;
  ERROR_FAILED_SERVICE_CONTROLLER_CONNECT = 1063;
  ERROR_EXCEPTION_IN_SERVICE = 1064;
  ERROR_DATABASE_DOES_NOT_EXIST = 1065;
  ERROR_SERVICE_SPECIFIC_ERROR = 1066;
  ERROR_PROCESS_ABORTED = 1067;
  ERROR_SERVICE_DEPENDENCY_FAIL = 1068;
  ERROR_SERVICE_LOGON_FAILED = 1069;
  ERROR_SERVICE_START_HANG = 1070;
  ERROR_INVALID_SERVICE_LOCK = 1071;
  ERROR_SERVICE_MARKED_FOR_DELETE = 1072;
  ERROR_SERVICE_EXISTS = 1073;



function OpenSCManager(
  lpMachineName: string; 
  lpDatabaseName: string; 
  dwDesiredAccess: Longword): Longword;
  external 'OpenSCManagerA@advapi32.dll stdcall';

//
// lpServiceName is the service name, not the service display name
//

function OpenService(
  hSCManager: Longword; 
  lpServiceName: string; 
  dwDesiredAccess: Longword): Longword;
  external 'OpenServiceA@advapi32.dll stdcall';

function StartService(
  hService: Longword;
  dwNumServiceArgs: Longword; 
  lpServiceArgVectors: PChar): Longword;
  external 'StartServiceA@advapi32.dll stdcall';

function CloseServiceHandle(hSCObject: Longword): Longword;
  external 'CloseServiceHandle@advapi32.dll stdcall';

function ControlService(
  hService: Longword;
  dwControl: Longword; 
  var lpServiceStatus: _SERVICE_STATUS): Longword;
  external 'ControlService@advapi32.dll stdcall';

function CreateService(hSCManager: Longword;
  lpServiceName: string;
  lpDisplayName: string;
  dwDesiredAccess: Longword;
  dwServiceType: Longword;
  dwStartType: Longword;
  dwErrorControl: Longword;
  lpBinaryPathName: string;
  lpLoadOrderGroup: string;
  lpdwTagId: Longword;
  lpDependencies: string;
  lpServiceStartName: string;
  lpPassword: string): Longword;
  external 'CreateServiceA@advapi32.dll stdcall';

function DeleteService(hService: Longword): Longword;
  external 'DeleteService@advapi32.dll stdcall';

function ChangeServiceConfig(
  hService: Longword;
  dwServiceType: Longword;
  dwStartType: Longword;
  dwErrorControl: Longword;
  lpBinaryPathName: PChar;
  lpLoadOrderGroup: PChar;
  lpdwTagId: Longword;
  lpDependencies: PChar;
  lpServiceStartName: PChar;
  lpPassword: PChar;
  lpDisplayName: PChar): Longword;
  external 'ChangeServiceConfigA@advapi32.dll stdcall';

function LockServiceDatabase(hSCManager: Longword): Longword;
  external 'LockServiceDatabase@advapi32.dll stdcall';

function UnlockServiceDatabase(ScLock: Longword): Longword;
  external 'UnlockServiceDatabase@advapi32.dll stdcall';


function SimpleCreateService(
  AServiceName,
  ADisplayName, 
  AFileName: string;
  AStartType: Longword;
  AUser, APassword: string; 
  Interactive: Boolean; 
  IgnoreExisting: Boolean): Boolean;
var
  SCMHandle: Longword;
  ServiceHandle: Longword;
  ServiceType: Longword;
  Error: Integer;
begin
  Result := False;
  ServiceType := SERVICE_WIN32_OWN_PROCESS;
  try
    SCMHandle := OpenSCManager('', '', SC_MANAGER_ALL_ACCESS);
    if SCMHandle = 0 then
      RaiseException('OpenSCManager@SimpleCreateService: ' + AServiceName + ' ' + 
        SysErrorMessage(DLLGetLastError));
    try
      if AUser = '' then
      begin
        if Interactive then
          ServiceType := ServiceType + SERVICE_INTERACTIVE_PROCESS;
        APassword := '';
      end;
      ServiceHandle := CreateService(SCMHandle, AServiceName, ADisplayName, 
        SERVICE_ALL_ACCESS, ServiceType, AStartType, SERVICE_ERROR_NORMAL, 
        AFileName, '', 0, '', AUser, APassword);
      if ServiceHandle = 0 then
      begin
        Error := DLLGetLastError;
        if IgnoreExisting and (Error = ERROR_SERVICE_EXISTS) then
          Exit
        else
          RaiseException('CreateService@SimpleCreateService: ' + AServiceName + 
            ' ' + SysErrorMessage(Error));
      end;
      Result := True;
    finally
      if ServiceHandle <> 0 then
        CloseServiceHandle(ServiceHandle);
    end;
  finally
    if SCMHandle <> 0 then
      CloseServiceHandle(SCMHandle);
  end;
end;

function WaitForService(ServiceHandle: Longword; AStatus: Longword): Boolean;
var
  PendingStatus: Longword;
  ServiceStatus: _SERVICE_STATUS;
  Error: Integer;
begin
  Result := False;

  case AStatus of
    SERVICE_RUNNING: PendingStatus := SERVICE_START_PENDING;
    SERVICE_STOPPED: PendingStatus := SERVICE_STOP_PENDING;
  end;

  repeat
    if ControlService(ServiceHandle, SERVICE_CONTROL_INTERROGATE, ServiceStatus) = 0 then
    begin
      Error := DLLGetLastError;
      RaiseException('ControlService@WaitForService: ' + SysErrorMessage(Error));
    end;
    if ServiceStatus.dwWin32ExitCode <> 0 then
      Break;
    Result := ServiceStatus.dwCurrentState = AStatus;
    if not Result and (ServiceStatus.dwCurrentState = PendingStatus) then
      Sleep(ServiceStatus.dwWaitHint)
    else
      Break;
  until Result;
end;

procedure SimpleStopService(AService: string; Wait, IgnoreStopped: Boolean);
var
  ServiceStatus: _SERVICE_STATUS;
  SCMHandle: Longword;
  ServiceHandle: Longword;
  Error: Integer;
begin
  try
    SCMHandle := OpenSCManager('', '', SC_MANAGER_ALL_ACCESS);
    if SCMHandle = 0 then
      RaiseException('OpenSCManager@SimpleStopService: ' + AService + ' ' + 
        SysErrorMessage(DLLGetLastError));
    try
      ServiceHandle := OpenService(SCMHandle, AService, SERVICE_ALL_ACCESS);
      if ServiceHandle = 0 then
        RaiseException('OpenService@SimpleStopService: ' + AService + ' ' + 
          SysErrorMessage(DLLGetLastError));
      try
        if ControlService(ServiceHandle, SERVICE_CONTROL_STOP, ServiceStatus) = 0 then
        begin
          Error := DLLGetLastError;
          if IgnoreStopped and (Error = ERROR_SERVICE_NOT_ACTIVE) then
            Exit
          else
            RaiseException('ControlService@SimpleStopService: ' + AService + ' ' + 
              SysErrorMessage(Error));
          if Wait then
            WaitForService(ServiceHandle, SERVICE_STOPPED);
        end;
      finally
        if ServiceHandle <> 0 then
          CloseServiceHandle(ServiceHandle);
      end;
    finally
      if SCMHandle <> 0 then
        CloseServiceHandle(SCMHandle);
    end;
  except
    ShowExceptionMessage;
  end;
end;

procedure SimpleStartService(AService: string; Wait, IgnoreStarted: Boolean);
var
  SCMHandle: Longword;
  ServiceHandle: Longword;
  Error: Integer;
begin
  try
    SCMHandle := OpenSCManager('', '', SC_MANAGER_ALL_ACCESS);
    if SCMHandle = 0 then
      RaiseException('OpenSCManager@SimpleStartService: ' + AService + ' ' +
        SysErrorMessage(DLLGetLastError));
    try
      ServiceHandle := OpenService(SCMHandle, AService, SERVICE_ALL_ACCESS);
      if ServiceHandle = 0 then
        RaiseException('OpenService@SimpleStartService: ' + AService + ' ' + 
          SysErrorMessage(DLLGetLastError));
      try
        if StartService(ServiceHandle, 0, '') = 0 then
        begin
          Error := DLLGetLastError;
          if IgnoreStarted and (Error = ERROR_SERVICE_ALREADY_RUNNING) then
            Exit
          else
            RaiseException('StartService@SimpleStartService: ' + AService + ' ' + 
              SysErrorMessage(Error));
          if Wait then
          begin
            WaitForService(ServiceHandle, SERVICE_RUNNING);
          end;
        end;
      finally
        if ServiceHandle <> 0 then
          CloseServiceHandle(ServiceHandle);
      end;
    finally
      if SCMHandle <> 0 then
        CloseServiceHandle(SCMHandle);
    end;
  except
    ShowExceptionMessage;
  end;
end;

procedure SimpleDeleteService(AService: string);
var
  SCMHandle: Longword;
  ServiceHandle: Longword;
begin
  try
    SCMHandle := OpenSCManager('', '', SC_MANAGER_ALL_ACCESS);
    if SCMHandle = 0 then
      RaiseException('OpenSCManager@SimpleDeleteService: ' + AService + ' ' + 
        SysErrorMessage(DLLGetLastError));
    try
      ServiceHandle := OpenService(SCMHandle, AService, SERVICE_ALL_ACCESS);
      if ServiceHandle = 0 then
        RaiseException('OpenService@SimpleDeleteService: ' + AService + ' ' + 
          SysErrorMessage(DLLGetLastError));
      try
        if DeleteService(ServiceHandle) = 0 then
          RaiseException('StartService@SimpleDeleteService: ' + AService + ' ' + 
            SysErrorMessage(DLLGetLastError));
      finally
        if ServiceHandle <> 0 then
          CloseServiceHandle(ServiceHandle);
      end;
    finally
      if SCMHandle <> 0 then
        CloseServiceHandle(SCMHandle);
    end;
  except
    ShowExceptionMessage;
  end;
end;

procedure SimpleSetServiceStartup(AService: string; AStartupType: Longword);
var
  SCMHandle: Longword;
  ServiceHandle: Longword;
begin
  try
    SCMHandle := OpenSCManager('', '', SC_MANAGER_ALL_ACCESS);
    if SCMHandle = 0 then
      RaiseException('SimpleSetServiceStartup@OpenSCManager: ' + AService + ' ' + 
        SysErrorMessage(DLLGetLastError));
    try
      ServiceHandle := OpenService(SCMHandle, AService, SERVICE_ALL_ACCESS);
      if ServiceHandle = 0 then
        RaiseException('SimpleSetServiceStartup@OpenService: ' + AService + ' ' + 
          SysErrorMessage(DLLGetLastError));
      try
        if ChangeServiceConfig(ServiceHandle, SERVICE_NO_CHANGE, AStartupType, SERVICE_NO_CHANGE,
          '', '', 0, '', '', '', '') = 0 then
          RaiseException('SimpleSetServiceStartup@SetServiceStartup: ' + AService + ' ' +
            SysErrorMessage(DLLGetLastError));
      finally
        if ServiceHandle <> 0 then
          CloseServiceHandle(ServiceHandle);
      end;
    finally
      if SCMHandle <> 0 then
        CloseServiceHandle(SCMHandle);
    end;
  except
    ShowExceptionMessage;
  end;
end;

function ServiceExists(AService: string): Boolean;
var
  SCMHandle: Longword;
  ServiceHandle: Longword;
  Error: Integer;
begin
  try
    SCMHandle := OpenSCManager('', '', SC_MANAGER_ALL_ACCESS);
    if SCMHandle = 0 then
      RaiseException('OpenSCManager@ServiceExists: ' + AService + ' ' + 
        SysErrorMessage(DLLGetLastError));
    try
      ServiceHandle := OpenService(SCMHandle, AService, SERVICE_ALL_ACCESS);
      try
        if ServiceHandle = 0 then
        begin
          Error := DLLGetLastError;
          if Error = ERROR_SERVICE_DOES_NOT_EXIST then
            Result := False
          else
            RaiseException('OpenService@ServiceExists: ' + AService + ' ' + 
              SysErrorMessage(Error));
        end
        else
          Result := True;
      finally
        if ServiceHandle <> 0 then
          CloseServiceHandle(ServiceHandle);
      end;
    finally
      if SCMHandle <> 0 then
        CloseServiceHandle(SCMHandle);
    end;
  except
    ShowExceptionMessage;
  end;
end;

function SimpleQueryService(AService: string): Longword;
var
  ServiceStatus: _SERVICE_STATUS;
  SCMHandle: Longword;
  ServiceHandle: Longword;
  Error: Integer;
begin
  Result := 0;
  try
    SCMHandle := OpenSCManager('', '', SC_MANAGER_ALL_ACCESS);
    if SCMHandle = 0 then
      RaiseException('OpenSCManager@SimpleQueryService: ' + AService + ' ' + 
        SysErrorMessage(DLLGetLastError));
    try
      ServiceHandle := OpenService(SCMHandle, AService, SERVICE_ALL_ACCESS);
      if ServiceHandle = 0 then
        RaiseException('OpenService@SimpleQueryService: ' + AService + ' ' + 
          SysErrorMessage(DLLGetLastError));
      try
        if ControlService(ServiceHandle, SERVICE_CONTROL_INTERROGATE, ServiceStatus) = 0 then
        begin
          Error := DLLGetLastError;
          RaiseException('ControlService@SimpleQueryService: ' + AService + ' ' + 
            SysErrorMessage(Error));
        end;
        Result := ServiceStatus.dwCurrentState;
      finally
        if ServiceHandle <> 0 then
          CloseServiceHandle(ServiceHandle);
      end;
    finally
      if SCMHandle <> 0 then
        CloseServiceHandle(SCMHandle);
    end;
  except
    ShowExceptionMessage;
  end;
end;
