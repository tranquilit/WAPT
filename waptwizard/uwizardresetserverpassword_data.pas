unit uwizardresetserverpassword_data;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils;

type
  TWizardResetServerPasswordData = record
    wapt_server_home : String;
    wapt_user        : String;
    wapt_password    : String;
  end;
  PWizardResetServerPasswordData = ^TWizardResetServerPasswordData;

implementation


end.

