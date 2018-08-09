unit resources;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils;

const
  RES_IMG_WAPT : String = 'img_wapt';

implementation

uses
  LResources;


initialization

{$ifdef ENTERPRISE}
{$I resources.enterprise.lrs}
{$else}
{$I resources.community.lrs}
{$endif}

end.

