unit uviswaptconfig;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, FileUtil, Forms,
  Controls, Graphics, Dialogs, ButtonPanel, StdCtrls, ExtCtrls,EditBtn;

type

  { TVisWAPTConfig }

  TVisWAPTConfig = class(TForm)
    ButtonPanel1: TButtonPanel;
    cbProxyLocalConnection: TCheckBox;
    eddefault_sources_root: TDirectoryEdit;
    edwapt_server: TLabeledEdit;
    edtemplates_repo_url: TLabeledEdit;
    edprivate_key: TFileNameEdit;
    edhttp_proxy: TLabeledEdit;
    Label1: TLabel;
    Label2: TLabel;
    eddefault_package_prefix: TLabeledEdit;
    edrepo_url: TLabeledEdit;
    Label3: TLabel;
    Label4: TLabel;
  private
    { private declarations }
  public
    { public declarations }
  end;

var
  VisWAPTConfig: TVisWAPTConfig;

implementation

{$R *.lfm}

end.

