unit Golang.Slice;

interface

uses System.SysUtils;

type
  TByteSlice = record
  private
  	FBytes: TBytes;
    FLow: Integer;
    FHigh: Integer;
    function GetByteAt(I: Integer): Byte;
    procedure SetByteAt(I: Integer; const Value: Byte);
  public
    constructor Create(const ABytes: TBytes; const ALow, AHigh: Integer); overload;
    constructor Create(ALen: Integer; ACap: Integer = 0); overload;
    constructor Create(const A: TByteSlice; const ALow, AHigh: Integer); overload;
    constructor Create(const A: UTF8String;
      const ALow: Integer = 0; const AHigh: Integer = MaxInt); overload;

    function Slice(const ALow, AHigh: Integer): TByteSlice;
    function ToString: UTF8String;
    function Len: Integer;
    property Bytes[I: Integer]: Byte read GetByteAt write SetByteAt; default;
  end;

  TCharSlice = record
  private
  	FStr: UTF8String;
    FLow: Integer;
    FHigh: Integer;
  public
    constructor Create(const A: TCharSlice;
      ALow: Integer = 0; AHigh: Integer = 0); overload;
    constructor Create(const A: UTF8String;
      ALow: Integer = 0; AHigh: Integer = MaxInt); overload;
    function Slice(ALow: Integer; AHigh: Integer): TCharSlice;
    function ToString: UTF8String;
    function Len: Integer;
  end;


implementation

uses
  AcedConsts;


{ TCharSlice }

constructor TCharSlice.Create(const A: UTF8String; ALow, AHigh: Integer);
begin
  FStr := A;
  FLow := ALow;
  FHigh := AHigh;
  if (FLow > 0) and (FHigh = 0) then
    FHigh := Length(FStr)
  else if FHigh >= Length(FStr) then
    FHigh := Length(FStr)
end;

function TCharSlice.Len: Integer;
begin
  Result := FHigh - FLow
end;

constructor TCharSlice.Create(const A: TCharSlice; ALow, AHigh: Integer);
begin
  Create(A.FStr, ALow, AHigh)
end;

function TCharSlice.Slice(ALow, AHigh: Integer): TCharSlice;
begin
  Result := TCharSlice.Create(Self, FLow + ALow, FLow + AHigh);
end;

function TCharSlice.ToString: UTF8String;
begin
  Result := Copy(FStr, FLow + 1, FHigh - FLow);
end;


{ TByteSlice }

constructor TByteSlice.Create(const A: TByteSlice; const ALow, AHigh: Integer);
begin
  Create(A.FBytes, ALow, AHigh)
end;

constructor TByteSlice.Create(const A: UTF8String; const ALow, AHigh: Integer);
begin
  Create(BytesOf(A), ALow, AHigh)
end;

constructor TByteSlice.Create(ALen, ACap: Integer);
begin
  if ACap = 0 then
    ACap := ALen;
  SetLength(FBytes, ACap);
  Create(FBytes, 0, ALen);
end;

constructor TByteSlice.Create(const ABytes: System.SysUtils.TBytes; const ALow, AHigh: Integer);
begin
  FBytes := ABytes;
  FLow := ALow;
  FHigh := AHigh;
  if (FLow > 0) and (FHigh = 0) then
    FHigh := Length(FBytes)
  else if FHigh >= Length(FBytes) then
    FHigh := Length(FBytes)
end;

function TByteSlice.Len: Integer;
begin
  Result := FHigh - FLow
end;

procedure TByteSlice.SetByteAt(I: Integer; const Value: Byte);
begin
  FBytes[FLow + I] := Value
end;

function TByteSlice.GetByteAt(I: Integer): Byte;
begin
  Result := FBytes[FLow + I]
end;

function TByteSlice.Slice(const ALow, AHigh: Integer): TByteSlice;
begin
  Result := TByteSlice.Create(Self, FLow + ALow, FLow + AHigh);
end;

function TByteSlice.ToString: UTF8String;
begin
  SetLength(Result, Len);
  Move(FBytes[FLow], Pointer(Result)^, Len);
end;


end.
