unit tisinstall;
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

// From http://crteknologies.fr/programmation/conseils/installation.php
interface
{$mode objfpc}{$H+}
  Procedure Installer;
  Procedure desinstaller;

implementation
uses windows,registry,forms,sysutils,dialogs,controls;

Procedure Installer();
  Var
    reg: TRegistry;
  Begin
    reg := TRegistry.Create;
    Try
      reg.RootKey := HKEY_LOCAL_MACHINE;
      If (Not(reg.OpenKey('\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\'+Application.Name, false))
          Or (ParamStr(0) <> reg.ReadString(''))) Then
      Begin //-- si pas installé du tout ou changé chemin
        // chemin
        reg.CloseKey();
        reg.OpenKey('\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\'+Application.Name, true);
        reg.WriteString('', ParamStr(0));
        reg.WriteString('Path', ExtractFilePath(ParamStr(0)) );
        reg.CloseKey();
        // uninstall
        reg.OpenKey('\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall', false);
        reg.CreateKey('\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\'+Application.Name);
        reg.OpenKey('\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\'+Application.Name, false);
        reg.WriteString('DisplayName', Application.Name);
        reg.WriteString('UninstallString', ParamStr(0) + ' uninstall');
        reg.CloseKey();
        // registrer .kpx et option crypter pour tous les autres fichiers
        {reg.RootKey := HKEY_CLASSES_ROOT;
        reg.OpenKey('\*\Shell\'+Application.Name, true);
        reg.WriteString('', 'Crypter avec CR-KryptX');
        reg.CloseKey(); reg.OpenKey('\*\Shell\CR-KryptX\command', true);
        reg.WriteString('', '"' + ParamStr(0) + '"'  + ' crypter "%1"');
        reg.CloseKey(); reg.OpenKey('\.kpx', true);
        reg.WriteString('', 'fKryptX');
        reg.CloseKey(); reg.OpenKey('\fKryptX', true);
        reg.WriteString('', 'Fichier crypté CR-KryptX');
        reg.CloseKey(); reg.OpenKey('\fKryptX\DefaultIcon', true);
        reg.WriteString('', ParamStr(0) + ',1');
        reg.CloseKey(); reg.OpenKey('\fKryptX\Shell', true);
        reg.WriteString('', 'Decrypter');
        reg.OpenKey('\fKryptX\Shell\Decrypter', true);
        reg.WriteString('', 'Décrypter avec CR-KryptX');
        reg.CloseKey(); reg.OpenKey('\fKryptX\Shell\Decrypter\command', true);
        reg.WriteString('', '"' + ParamStr(0) + '"'  + ' decrypter "%1"');
        reg.CloseKey();
        // clé options
        If Not(reg.KeyExists('\SOFTWARE\CR-TEKnologies')) Then reg.CreateKey('SOFTWARE\CR-TEKnologies');
        If Not(reg.KeyExists('\SOFTWARE\CR-TEKnologies\KryptX')) Then reg.CreateKey('SOFTWARE\CR-TEKnologies\XFonte');
        reg.OpenKey('\SOFTWARE\CR-TEKnologies\KryptX', true);
        If Not(reg.ValueExists('Langue')) Then reg.WriteString('Langue', 'Français');}
        reg.CloseKey();
      End;
      //reg.OpenKey('\SOFTWARE\CR-TEKnologies\KryptX', true);
      //Langue := reg.ReadString('Langue');
    Finally reg.Free End;
  End;



  Procedure desinstaller;
  Var
      res: Integer;
    reg: TRegistry;
    infos: TRegKeyInfo;
  Begin
    try
      res := MessageDlg('Voulez-vous effacer les entrées du registre ?', mtConfirmation, mbYesNoCancel, 0);
      If (res = mrCancel) Then Exit;
      If (res = mrYes) Then
      Begin
        reg := TRegistry.Create;
        Try
          reg.RootKey := HKEY_LOCAL_MACHINE;
          reg.DeleteKey('\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\'+Application.Name);
          reg.DeleteKey('\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\'+Application.Name);
          {reg.DeleteKey('\SOFTWARE\CR-TEKnologies\'+Application.Name);
          reg.OpenKey('\SOFTWARE\CR-TEKnologies', true);
          reg.GetKeyInfo(infos);
          If (infos.NumSubKeys = 0) Then reg.DeleteKey('\SOFTWARE\CR-TEKnologies');}
        Finally reg.Free End;
      End;

      res := MessageDlg('Vous devez supprimer les fichiers manuellement. Voulez-vous accéder au dossier ?', mtConfirmation, mbYesNoCancel, 0);
      If (res = mrYes) Then
        ShellExecute(0, nil, PChar(ExtractFilePath(ParamStr(0))), nil, nil, SW_NORMAL);
    finally
      Application.Terminate;
    end;
  End;

end.

