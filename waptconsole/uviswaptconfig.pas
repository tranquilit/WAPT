unit uviswaptconfig;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, FileUtil, Forms,
  Controls, Graphics, Dialogs, ButtonPanel,
  StdCtrls, ExtCtrls,EditBtn, DefaultTranslator;

type

  { TVisWAPTConfig }

  TVisWAPTConfig = class(TForm)
    ButtonPanel1: TButtonPanel;
    cbUseProxyForRepo: TCheckBox;
    cbUseProxyForServer: TCheckBox;
    cbUseProxyForTemplate: TCheckBox;
    eddefault_sources_root: TDirectoryEdit;
    edhttp_proxy_templates: TLabeledEdit;
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
    Label5: TLabel;
    Label6: TLabel;
    Label7: TLabel;
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

