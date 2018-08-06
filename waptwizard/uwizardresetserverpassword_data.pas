unit uwizardresetserverpassword_data;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils;

const
  PAGE_WELCOME        : String = 'welcome';
  PAGE_RESET_PASSWORD : String = 'reset_password';
  PAGE_RESTART_SERVER : String = 'restart_server';
  PAGE_FINISHED       : String = 'finished';

type
  TWizardResetServerPasswordData = record
    wapt_server_home : String;
    wapt_user        : String;
    wapt_password    : String;
  end;
  PWizardResetServerPasswordData = ^TWizardResetServerPasswordData;

implementation


end.

