unit Golang.Errors;

interface

type
  IError = interface
    function Error(): UTF8String;
  end;

type
// errorString is a trivial implementation of error.
  TErrorString = class(TInterfacedObject, IError)
  protected
    s: UTF8String;
  public
    constructor Create(const text: UTF8String);
    function Error(): UTF8String; virtual;
  end;



function New(const text: UTF8String): IError;

implementation

// New returns an error that formats as the given text.
function New(const text: UTF8String): IError;
begin
  Result := TErrorString.Create(text);
end;


{ TErrorString }

constructor TErrorString.Create(const text: UTF8String);
begin
  s := text
end;

function TErrorString.Error: UTF8String;
begin
  Result := s
end;

end.
