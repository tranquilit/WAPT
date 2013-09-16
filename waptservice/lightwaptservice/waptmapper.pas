unit WaptMapper; 
{ -----------------------------------------------------------------------
#    This file is part of WAPT
#    Copyright (C) 2013  Tranquil IT Systems http://www.tranquil.it
#    WAPT aims to help Windows systems administrators to deploy
#    setup and update applications on users PC.
#
#    WAPT is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    WAPT is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with WAPT.  If not, see <http://www.gnu.org/licenses/>.
#
# -----------------------------------------------------------------------
}

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, FileUtil, DaemonApp; 

type

  { TDaemonMapper1 }

  TDaemonMapper1 = class(TDaemonMapper)
    procedure DaemonMapper1Create(Sender: TObject);
  private
    { private declarations }
  public
    { public declarations }
  end; 

var
  DaemonMapper1: TDaemonMapper1; 

implementation

procedure RegisterMapper; 
begin
  RegisterDaemonMapper(TDaemonMapper1)
end;

{ TDaemonMapper1 }

procedure TDaemonMapper1.DaemonMapper1Create(Sender: TObject);
begin

end;

{$R *.lfm}


initialization
  RegisterMapper; 
end.

