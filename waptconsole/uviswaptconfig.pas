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
    Button1: TButton;
    ButtonPanel1: TButtonPanel;
    cbUseProxyForRepo: TCheckBox;
    cbUseProxyForServer: TCheckBox;
    cbUseProxyForTemplate: TCheckBox;
    cbSendStats: TCheckBox;
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
    Label8: TLabel;
    procedure Button1Click(Sender: TObject);
  private
    { private declarations }
  public
    { public declarations }
  end;

var
  VisWAPTConfig: TVisWAPTConfig;

implementation
uses waptcommon;
{$R *.lfm}

{ TVisWAPTConfig }

procedure TVisWAPTConfig.Button1Click(Sender: TObject);
begin
  try
    ShowMessage(WAPTServerJsonGet('api/v1/usage_statistics',[])['result'].AsJSon(True));
  except
    on E:Exception do
      ShowMessage('Unable to retrieve statistics : '+E.Message);
  end;
end;

end.

