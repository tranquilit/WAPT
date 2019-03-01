#define edition "waptsetup"
#define default_repo_url ""
#define default_wapt_server ""
#define repo_url ""
#define wapt_server ""
#define AppId "WAPT"
#define AppName "WAPTSetup"
#define output_dir "."
#define Company "Tranquil IT Systems"
#define send_usage_report 0

; if not empty, set value 0 or 1 will be defined in wapt-get.ini
#define set_use_kerberos "0"

; if empty, a task is added
; copy authorized package certificates (CA or signers) in <wapt>\ssl
#ifndef set_install_certs
#define set_install_certs ""
#endif

; if 1, expiry and CRL of package certificates will be checked
#define check_certificates_validity 1

; if not empty, the 0, 1 or path to a CA bundle will be defined in wapt-get.ini for checking of https certificates
#define set_verify_cert "0"

; default value for detection server and repo URL using dns 
#define default_dnsdomain ""

; if not empty, a task will propose to install this package or list of packages (comma separated)
#ifndef set_start_packages
#define set_start_packages ""
#endif

#define use_fqdn_as_uuid ""

;#define waptenterprise

#ifndef set_disable_hiberboot
#define set_disable_hiberboot ""
#endif

; if not empty, the host will inherit these (comma separated) list of profile packages.
; if *, append the profiles from command line
#define append_host_profiles "*"

;#define signtool "kSign /d $qWAPT Client$q /du $qhttp://www.tranquil-it-systems.fr$q $f"

#ifdef waptenterprise
  #define set_waptwua_enabled ""
  #define set_waptwua_default_allow ""
  #define set_waptwua_offline ""
  #define set_waptwua_allow_direct_download ""
  #define set_waptwua_install_delay ""
  #define set_waptwua_download_scheduling ""
  #define set_waptwua_install_at_shutdown ""   
#endif

; for fast compile in developent mode
;#define FastDebug

#include "common.iss"

[RUN]
;Filename: "{app}\waptconsolepostconf.exe"; Parameters: "--lang {language}"; Flags: postinstall runascurrentuser skipifsilent shellexec; StatusMsg: {cm:LaunchingPostConf}; Description: "{cm:LaunchingPostConf}"; Check: RunWizardCheck
Filename: {cm:InstallDocURL}; Flags: postinstall runascurrentuser skipifsilent shellexec; StatusMsg: {cm:OpenWaptDocumentation}; Description: "{cm:OpenWaptDocumentation}"

[CustomMessages]
fr.LaunchingPostConf=Lancement de la post-configuration de la console
en.LaunchingPostConf=Launch console post-configuration
de.LaunchingPostconf=Konsole Post-Konfiguration starten
fr.OpenWaptDocumentation=Afficher la documentation d'installation
fr.InstallDocURL=https://doc.wapt.fr
en.OpenWaptDocumentation=Show installation documentation
en.InstallDocURL=https://doc.wapt.fr


[Code]

function RunWizardCheck:Boolean;
begin
  Result := cbUseWizard.checked;
end;

