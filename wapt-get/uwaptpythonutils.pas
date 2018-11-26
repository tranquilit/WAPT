unit uWaptPythonUtils;

{$mode objfpc}{$H+}

interface
uses
  Classes, SysUtils, variants, PythonEngine, PythonGUIInputOutput, WrapDelphi,
  VarPyth, superobject;

function pyObjectToSuperObject(pvalue:PPyObject):ISuperObject;
function PyVarToSuperObject(PyVar:Variant):ISuperObject;


function SuperObjectToPyObject(aso:ISuperObject):PPyObject;
function SuperObjectToPyVar(aso:ISuperObject):Variant;

function PyUTF8Decode(s:RawByteString):UnicodeString;

implementation


function pyObjectToSuperObject(pvalue:PPyObject):ISuperObject;
var
  j,k: Integer;
  pyKey,pyDict,pyValue: PPyObject;
begin
  if GetPythonEngine.PyUnicode_Check(pvalue) or GetPythonEngine.PyString_Check(pvalue) then
    Result := TSuperObject.Create(GetPythonEngine.PyString_AsDelphiString(pvalue))
  else if GetPythonEngine.PyInt_Check(pvalue) then
    Result := TSuperObject.Create(GetPythonEngine.PyInt_AsLong(pvalue))
  else if GetPythonEngine.PyFloat_Check(pvalue) then
    Result := TSuperObject.Create(GetPythonEngine.PyFloat_AsDouble(pvalue))
  else if GetPythonEngine.PyList_Check(pvalue) then
  begin
    Result := TSuperObject.Create(stArray);
    for k := 0 to GetPythonEngine.PyList_Size(pvalue) - 1 do
        Result.AsArray.Add(pyObjectToSuperObject(GetPythonEngine.PyList_GetItem(pvalue,k)));
  end
  else if GetPythonEngine.PyTuple_Check(pvalue) then
  begin
    Result := TSuperObject.Create(stArray);
    for k := 0 to GetPythonEngine.PyTuple_Size(pvalue) - 1 do
        Result.AsArray.Add(pyObjectToSuperObject(GetPythonEngine.PyTuple_GetItem(pvalue,k)));
  end
  else if GetPythonEngine.PyDict_Check(pvalue) then
  begin
    Result := TSuperObject.Create(stObject);
    j := 0;
    pyKey := Nil;
    pyValue := Nil;
    while GetPythonEngine.PyDict_Next(pvalue,@j,@pyKey,@pyValue) <> 0 do
      Result[GetPythonEngine.PyObjectAsString(pyKey)] := pyObjectToSuperObject(pyvalue);
  end
  else if GetPythonEngine.PyObject_HasAttrString(pvalue,'as_dict') <> 0  then
  begin
    Result := TSuperObject.Create(stObject);
    pyDict := GetPythonEngine.PyObject_CallMethodStr(pvalue,'as_dict',Nil,Nil);
    j := 0;
    pyKey := Nil;
    pyValue := Nil;
    while GetPythonEngine.PyDict_Next(pyDict,@j,@pyKey,@pyValue) <> 0 do
      Result[GetPythonEngine.PyObjectAsString(pyKey)] := pyObjectToSuperObject(pyvalue);
  end
  else if pvalue = GetPythonEngine.Py_None then
    Result := TSuperObject.Create(stNull)
  else
    Result := TSuperObject.Create(GetPythonEngine.PyObjectAsString(pvalue));
end;

function PyVarToSuperObject(PyVar:Variant):ISuperObject;
begin
  Result := pyObjectToSuperObject(ExtractPythonObjectFrom(PyVar));
end;

function SuperObjectToPyObject(aso: ISuperObject): PPyObject;
var
  i:integer;
  item: ISuperObject;
  key: ISuperObject;

begin
  if aso<>Nil then
  begin
    case aso.DataType of
      stBoolean: begin
          if aso.AsBoolean then
            Result := PPyObject(GetPythonEngine.Py_True)
          else
            Result := PPyObject(GetPythonEngine.Py_False);
          GetPythonEngine.Py_INCREF(result);
      end;
      stNull: begin
          Result := GetPythonEngine.ReturnNone;
        end;
      stInt: begin
          Result := GetPythonEngine.PyInt_FromLong(aso.AsInteger);
        end;
      stDouble,stCurrency: begin
        Result := GetPythonEngine.PyFloat_FromDouble(aso.AsDouble);
        end;
      stString: begin
        Result := GetPythonEngine.PyUnicode_FromWideString(aso.AsString);
        end;
      stArray: begin
        Result := GetPythonEngine.PyTuple_New(aso.AsArray.Length);
        i:=0;
        for item in aso do
        begin
          GetPythonEngine.PyTuple_SetItem(Result,i,SuperObjectToPyObject(item));
          inc(i);
        end;
      end;
      stObject: begin
        Result := GetPythonEngine.PyDict_New();
        for key in Aso.AsObject.GetNames do
          GetPythonEngine.PyDict_SetItem(Result, SuperObjectToPyObject(key),SuperObjectToPyObject(Aso[key.AsString]));
      end
      else
        Result := GetPythonEngine.VariantAsPyObject(aso);
    end
  end
  else
    Result := GetPythonEngine.ReturnNone;
end;

function SuperObjectToPyVar(aso: ISuperObject): Variant;
begin
  result := VarPyth.VarPythonCreate(SuperObjectToPyObject(aso));
end;


function PyUTF8Decode(s:RawByteString):UnicodeString;
begin
  result := UTF8Decode(s);
end;

end.

