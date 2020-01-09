#define edition "waptstarter"
#define default_repo_url "https://store.wapt.fr/wapt"
#define default_wapt_server ""
#define repo_url ""
#define wapt_server ""
#define AppName "WAPTSetup"
#define wapt_base_dir "..\"
#define output_dir "."
#define Company "Tranquil IT Systems"
#define send_usage_report 0

; if not empty, set value 0 or 1 will be defined in wapt-get.ini
#define set_use_kerberos "0"

; if empty, a task is added
; copy authorized package certificates (CA or signers) in <wapt>\ssl
#define set_install_certs "1"

; if 1, expiry and CRL of package certificates will be checked
#define check_certificates_validity "1"

; if not empty, the 0, 1 or path to a CA bundle will be defined in wapt-get.ini for checking of https certificates
#define set_verify_cert "1"

; default value for detection server and repo URL using dns 
#define default_dnsdomain ""

; if not empty, a task will propose to install this package or list of packages (comma separated)
#define set_start_packages "waptstarter"

; if not empty, the host will inherit these (comma separated) list of profile packages.
#define append_host_profiles ""

; period of audit scheduling
#ifndef set_waptaudit_task_period
#define set_waptaudit_task_period  ""
#endif

;#define signtool "kSign /d $qWAPT Client$q /du $qhttp://www.tranquil-it-systems.fr$q $f"

; for fast compile in developent mode
;#define FastDebug

#ifndef set_disable_hiberboot
  #define set_disable_hiberboot ""
#endif

#define use_fqdn_as_uuid ""

#define use_ad_groups ""

#define use_random_uuid ""

#ifdef waptenterprise
  #define set_waptwua_enabled ""
  #define set_waptwua_default_allow ""
  #define set_waptwua_offline ""
  #define set_waptwua_allow_direct_download ""
  #define set_waptwua_install_delay ""
  #define set_waptwua_download_scheduling ""
#endif


#include "common.iss"


[RUN]
Filename: "{app}\waptself.exe"; Flags: postinstall runascurrentuser skipifsilent shellexec; StatusMsg: {cm:RunWaptSelfService}; Description: "{cm:RunWaptSelfService}"

[CustomMessages]
fr.RunWaptSelfService=Lancer le Self service applicatif WAPT
en.RunWaptSelfService=Start WAPT Self service
de.RunWaptSelfService=WAPT Self Service Konsole starten


[INI]
Filename: {app}\wapt-get.ini; Section: global; Key: waptservice_password; String: "NOPASSWORD"; Tasks: EnableWaptServiceNoPassword;

