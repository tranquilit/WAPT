unit UnitRedirect;
// This is an example application to demonstrate the use of pipes
// to redirect the input/output of a console application.
// The function "Sto_RedirectedExecute" was written by Martin Stoeckli
// and is part of the site:
//   http://www.martinstoeckli.ch/delphi/
//
{$mode delphiunicode}

interface
uses Windows, Classes,JWAWinBase;

  /// <summary>
  ///   Runs a console application and captures the stdoutput and
  ///   stderror.</summary>
  /// <param name="CmdLine">The commandline contains the full path to
  ///   the executable and the necessary parameters. Don't forget to
  ///   quote filenames with "" if the path contains spaces.</param>
  /// <param name="Output">Receives the console stdoutput.</param>
  /// <param name="Error">Receives the console stderror.</param>
  /// <param name="Input">Send to stdinput of the process.</param>
  /// <param name="Wait">[milliseconds] Maximum of time to wait,
  ///   until application has finished. After reaching this timeout,
  ///   the application will be terminated and False is returned as
  ///   result.</param>
  /// <returns>True if process could be started and did not reach the
  ///   timeout.</returns>
  function Sto_RedirectedExecute(CmdLine: WideString;
    const Input: RawByteString = '';
    const Wait: DWORD = 3600000;user:WideString='';domain:WideString='';password:WideString='';onpoll:TNotifyEvent=Nil): RawByteString;


  const
    LOGON_WITH_PROFILE = $00000001;

  function CreateProcessWithLogonW(lpUsername, lpDomain, lpPassword: PWideChar;
    dwLogonFlags: dword; lpApplicationName, lpCommandLine: PWideChar;
    dwCreationFlags: dword; lpEnvironment: pointer;
    lpCurrentDirectory: PWideChar; lpStartupInfo: PStartUpInfoW;
    lpProcessInfo: PProcessInformation): boolean; stdcall;
    external 'advapi32.dll';



implementation

uses sysutils;

type
  TStoReadPipeThread = class(TThread)
  protected
    FPipe: THandle;
    FContent: TStringStream;
    function Get_Content: RawByteString;
    procedure Execute; override;
  public
    constructor Create(const Pipe: THandle);
    destructor Destroy; override;
    property Content: RawByteString read Get_Content;
  end;

  TStoWritePipeThread = class(TThread)
  protected
    FPipe: THandle;
    FContent: TStringStream;
    procedure Execute; override;
  public
    constructor Create(const Pipe: THandle; const Content: RawByteString);
    destructor Destroy; override;
  end;

{ TStoReadPipeThread }

constructor TStoReadPipeThread.Create(const Pipe: THandle);
begin
  FPipe := Pipe;
  FContent := TStringStream.Create('');
  inherited Create(False); // start running
end;

destructor TStoReadPipeThread.Destroy;
begin
  FContent.Free;
  inherited Destroy;
end;

procedure TStoReadPipeThread.Execute;
const
  BLOCK_SIZE = 4096;
var
  iBytesRead: DWORD;
  myBuffer: array[0..BLOCK_SIZE-1] of Byte;
begin
  repeat
    // try to read from pipe
    if Windows.ReadFile(FPipe, myBuffer, BLOCK_SIZE, iBytesRead, nil) then
      FContent.Write(myBuffer, iBytesRead);
  // a process may write less than BLOCK_SIZE, even if not at the end
  // of the output, so checking for < BLOCK_SIZE would block the pipe.
  until (iBytesRead = 0);
end;

function TStoReadPipeThread.Get_Content: RawByteString;
begin
  Result := FContent.DataString;
end;

{ TStoWritePipeThread }

constructor TStoWritePipeThread.Create(const Pipe: THandle;
  const Content: RawByteString);
begin
  FPipe := Pipe;
  FContent := TStringStream.Create(Content);
  inherited Create(False); // start running
end;

destructor TStoWritePipeThread.Destroy;
begin
  FContent.Free;
  if (FPipe <> 0) then
    CloseHandle(FPipe);
  inherited Destroy;
end;

procedure TStoWritePipeThread.Execute;
const
  BLOCK_SIZE = 4096;
var
  myBuffer: array[0..BLOCK_SIZE-1] of Byte;
  iBytesToWrite: DWORD;
  iBytesWritten: DWORD;
begin
  iBytesToWrite := FContent.Read(myBuffer, BLOCK_SIZE);
  while (iBytesToWrite > 0) do
  begin
    Windows.WriteFile(FPipe, myBuffer, iBytesToWrite, iBytesWritten, nil);
    iBytesToWrite := FContent.Read(myBuffer, BLOCK_SIZE);
  end;
  // close our handle to let the other process know, that
  // there won't be any more data.
  CloseHandle(FPipe);
  FPipe := 0;
end;

function Sto_RedirectedExecute(CmdLine: WideString;
  const Input: RawByteString = '';
  const Wait: DWORD = 3600000;user:WideString='';domain:WideString='';password:WideString='';onpoll:TNotifyEvent=Nil): RawByteString;
var
  mySecurityAttributes: SECURITY_ATTRIBUTES;
  myStartupInfo: STARTUPINFOW;
  myProcessInfo: PROCESS_INFORMATION;
  hPipeInputRead, hPipeInputWrite: THandle;
  hPipeOutputRead, hPipeOutputWrite: THandle;
  hPipeErrorRead, hPipeErrorWrite: THandle;
  myWriteInputThread: TStoWritePipeThread;
  myReadOutputThread: TStoReadPipeThread;
  myReadErrorThread: TStoReadPipeThread;
  iWaitRes: Integer;

  wparams:WideString;
  output,error:RawByteString;

  exitCode:LongWord;
  ose : EOSError;

  start_ms:DWORD;

const
  pollwait:DWORD = 500;

begin
  try
    ZeroMemory(@mySecurityAttributes, SizeOf(SECURITY_ATTRIBUTES));
    mySecurityAttributes.nLength := SizeOf(SECURITY_ATTRIBUTES);
    mySecurityAttributes.bInheritHandle := TRUE;
    // create pipe to set stdinput
    hPipeInputRead := 0;
    hPipeInputWrite := 0;
    CreatePipe(hPipeInputRead, hPipeInputWrite, @mySecurityAttributes, 0);
    CreatePipe(hPipeOutputRead, hPipeOutputWrite, @mySecurityAttributes, 0);
    CreatePipe(hPipeErrorRead, hPipeErrorWrite, @mySecurityAttributes, 0);

    try
      // prepare startupinfo structure
      ZeroMemory(@myStartupInfo, SizeOf(STARTUPINFO));
      myStartupInfo.cb := Sizeof(STARTUPINFO);

      // hide application
      myStartupInfo.dwFlags := STARTF_USESHOWWINDOW;
      myStartupInfo.wShowWindow := SW_HIDE;
      // assign pipes
      myStartupInfo.dwFlags := myStartupInfo.dwFlags or STARTF_USESTDHANDLES;
      myStartupInfo.hStdInput := hPipeInputRead;
      myStartupInfo.hStdOutput := hPipeOutputWrite;
      myStartupInfo.hStdError := hPipeErrorWrite;


      // since Delphi calls CreateProcessW, literal strings cannot be used anymore
      UniqueString(CmdLine);

      // start the process
      wparams := CmdLine;
      if user<>'' then
      begin
        UniqueString(user);
        UniqueString(password);
        UniqueString(domain);
        // prepare startupinfo structure
        //Result := CreateProcessWith (token, nil, PChar(CmdLine), nil, nil, false, NORMAL_PRIORITY_CLASS or CREATE_NEW_CONSOLE, nil, nil, @myStartupInfo, @myProcessInfo)
        if not CreateProcessWithLogonW(PWidechar(user),pwidechar(domain),pwidechar(password),0, Nil,PWideChar(wparams), CREATE_NEW_CONSOLE,nil,nil,@myStartupInfo, @myProcessInfo) then
          RaiseLastOSError;
      end
      else
      begin
        if not CreateProcessW(Nil,PWideChar(wparams),  Nil,Nil, True, CREATE_NEW_CONSOLE,nil,nil,myStartupInfo,myProcessInfo) then
        {if  not CreateProcess(nil, PChar(CmdLine), nil, nil, True,
              CREATE_NEW_CONSOLE, nil, nil, myStartupInfo, myProcessInfo) then}
          RaiseLastOSError();
      end;


    finally
      // close the ends of the pipes, now used by the process
      CloseHandle(hPipeInputRead);
      CloseHandle(hPipeOutputWrite);
      CloseHandle(hPipeErrorWrite);
    end;

    myWriteInputThread := Nil;
    myReadOutputThread := Nil;
    myReadErrorThread := Nil;

    myWriteInputThread := TStoWritePipeThread.Create(hPipeInputWrite, Input);
    myReadOutputThread := TStoReadPipeThread.Create(hPipeOutputRead);
    myReadErrorThread := TStoReadPipeThread.Create(hPipeErrorRead);
    try
      start_ms := GetTickCount;
      repeat
        // wait unitl there is no more data to receive, or the timeout is reached
        iWaitRes := WaitForSingleObject(myProcessInfo.hProcess, pollwait);
        if Assigned(onpoll) then
          onpoll(Nil);
        // timeout reached ?
      until ((GetTickCount-start_ms > Wait) and  (iWaitRes = WAIT_TIMEOUT)) or (iWaitRes <> WAIT_TIMEOUT);
      if (GetTickCount-start_ms > Wait) then
      begin
        TerminateProcess(myProcessInfo.hProcess, UINT(ERROR_CANCELLED));
        raise Exception.Create('Timeout running '+CmdLine);
      end;
      // return output
      myReadOutputThread.WaitFor;
      Output := myReadOutputThread.Content;
      Result := output;
      myReadErrorThread.WaitFor;
      Error := myReadErrorThread.Content;
      if not GetExitCodeProcess(myProcessInfo.hProcess, exitCode) or (exitCode>0) then
        RaiseLastOSError(exitCode);


    finally
      if myWriteInputThread<>Nil then  myWriteInputThread.Free;
      if myReadOutputThread<>Nil then myReadOutputThread.Free;
      if myReadErrorThread<>Nil then myReadErrorThread.Free;
      CloseHandle(myProcessInfo.hThread);
      CloseHandle(myProcessInfo.hProcess);
    end;

  finally
    // close our ends of the pipes
    CloseHandle(hPipeOutputRead);
    CloseHandle(hPipeErrorRead);

  end;
end;

end.
