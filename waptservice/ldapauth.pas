unit ldapauth;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils,superobject,ldapsend;

// try to login to specified LDAP server, returns the user object
// {'result':'','value':''}
function LDAPSSLLogin(Fserver,Fusername,FDomain,Fpassword:String;Fport:String='636'):TLDAPSend;
function LdapSearch(ldap:TLDAPSend;base:String='dc=domain,dc=local';search:String='(objectClass=*)';attribs:String='*';SearchScope:TLDAPSearchScope=SS_WholeSubtree):ISuperObject;

// return {'dn':'cn=gg,...','user':{},'groups':{'cn=public,ou=,dc=...':''}}
function GetUserAndGroups(ldap:TLDAPSend;basedn,username:String;groupsdetails:Boolean=False):ISuperObject;

// check if username is member of group. group can be either the full DN, or the first part (CN=Domain Admins)
// Active Directory shema.... TODO : OpenLDAP with members group attribute
function UserIngroup(ldap:TLDAPSend;basedn,username,group:String):Boolean;

Implementation
uses blcksock, ssl_openssl,asn1util;

function LDAPSSLLogin(Fserver,Fusername,FDomain,Fpassword:String;Fport:String='636'):TLDAPSend;
var
  ldap: TLDAPSend;
  FVersion : integer;

begin
  result:=Nil;
  ldap := Nil;
  FVersion := 3;
  ldap := TLDAPSend.Create;
  ldap.TargetHost := Fserver;
  ldap.TargetPort := FPort;
  ldap.UserName := FUserName+'@'+FDomain;
  ldap.Password := FPassword;
  ldap.Version := FVersion;
  ldap.FullSSL := True;
  try
    //The following code borrowed from Lou Feliz
    if ldap.Login then
    try
      if not ldap.Bind then
        raise Exception.CreateFmt('Unable to bind to LDAP directory server %s:%s with user %s',[FServer,Fport,Fusername+'@'+Fdomain]);
      result := ldap;
    finally
    end
    else
      raise Exception.CreateFmt('Unable to login to LDAP directory server %s:%s with user %s',[FServer,Fport,Fusername+'@'+Fdomain]);

  except
    FreeAndNil(ldap);
    raise;
  end;
end;

function LdapSearch(ldap:TLDAPSend;base:String='dc=domain,dc=local';search:String='(objectClass=*)';attribs:String='*';SearchScope:TLDAPSearchScope=SS_WholeSubtree):ISuperObject;
var
  FVersion : integer;
  attribs_list:TStringList;
  recno,i,j:integer;
  r : TLDAPResult;
  rec :ISuperObject;

begin
  result:=TSuperObject.Create;
  FVersion := 3;
  Attribs_list := TStringList.Create;
  attribs_list.CommaText:=attribs;
  try
      ldap.SearchScope := SearchScope;
      if ldap.Search(base,false,search,attribs_list) then
      begin
        for recno := 0 to ldap.SearchResult.count-1 do
        begin
          r := ldap.SearchResult[recno];
          rec := TSuperObject.Create;
          // use keys with quotes asobject to avoid path parsing (ldap names have dot and colons which are parsed as path...)
          Result.AsObject.O[r.ObjectName] := rec;
          for i:=0 to r.Attributes.Count-1 do
            if r.Attributes[i].Count>1 then
            begin
              rec[r.Attributes[i].AttributeName] := TSuperObject.Create(stArray);
              for j:=0 to r.Attributes[i].Count-1 do
                rec.A[r.Attributes[i].AttributeName].Add(r.Attributes[i][j])
            end
            else
              rec.S[r.Attributes[i].AttributeName] := r.Attributes[i][0];
        end;
      end
      else
        raise Exception.CreateFmt('LDAP search error for query %s on basedn %s and attributes %s : %s',[search,base,attribs,ldap.ResultString]);
  finally
     attribs_list.Free;
  end;
end;

function GetUserAndGroups(ldap:TLDAPSend;basedn,username:String;groupsdetails:Boolean=False):ISuperObject;
var
  user,groups,g:ISuperObject;
  gn:String;
begin
  result := TSuperObject.Create;
  user := LdapSearch(ldap,basedn,'(&(objectClass=user)(cn='+username+'))','cn,name,mail,displayName,memberOf,profilePath,distinguishedName,description');
  result['user'] := user.AsObject.GetValues['0'];
  result['dn'] := user.AsObject.GetNames['0'];
  if groupsdetails then
  begin
    groups := TSuperObject.Create;
    result['groups'] := groups;
    if result['user.memberOf']<>Nil then
      for g in result['user.memberOf'] do
      begin
        gn := g.AsString;
        // use keys with quotes asobject to avoid path parsing (ldap names have dot and colons which are parsed as path...)
        groups.AsObject.O[gn] := LdapSearch(ldap,gn,'(objectClass=*)','cn,name,displayName,distinguishedName,description',SS_BaseObject);
      end;
  end;
end;

// check if user is member of group. group can be either the full DN, or the first part (CN=Domain Admins)
function UserIngroup(ldap:TLDAPSend;basedn,username,group:String):Boolean;
var
  user,g,groups : ISuperObject;
begin
  Result := False;
  user := GetUserAndGroups(ldap,basedn,username);
  groups := user['user.memberOf'];
  for g in groups do
    if (LowerCase(group) = LowerCase(g.AsString)) or (pos(LowerCase(group)+',',LowerCase(g.AsString))=1) then
    begin
      Result := True;
      Break;
    end;
end;

End.
