unit Golang.Net.Url;

// https://golang.org/src/net/url/url.go

// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package url parses URLs and implements query escaping.

// See RFC 3986. This package generally follows RFC 3986, except where
// it deviates for compatibility reasons. When sending changes, first
// search old issues for history on decisions. Unit tests should also
// contain references to issue numbers with details.

interface

uses
  SysUtils,
  //
  Golang.Errors;

// Error reports an error and the operation and URL that caused it.
type
  TError =  class(TInterfacedObject, IError)
  private
  	Op:  UTF8String;
  	URL: UTF8String;
	  Err: IError;
  public
    constructor Create(const AOp, AUrl: UTF8String; const AErr: IError);
    function Error: UTF8String;
  end;

  TEscapeError = class(TErrorString)
  public
    function Error(): UTF8String; override;
  end;

  TInvalidHostError = class(TErrorString)
  public
    function Error(): UTF8String; override;
  end;


// The Userinfo type is an immutable encapsulation of username and
// password details for a URL. An existing Userinfo value is guaranteed
// to have a username set (potentially empty, as allowed by RFC 2396),
// and optionally a password.
  TUserinfo = record
    username:    UTF8String;
    password:    UTF8String;
    passwordSet: Boolean;
    function IsEmpty: Boolean;
    procedure Empty;
  end;


// A URL represents a parsed URL (technically, a URI reference).
//
// The general form represented is:
//
//	[scheme:][//[userinfo@]host][/]path[?query][#fragment]
//
// URLs that do not start with a slash after the scheme are interpreted as:
//
//	scheme:opaque[?query][#fragment]
//
// Note that the Path field is stored in decoded form: /%47%6f%2f becomes /Go/.
// A consequence is that it is impossible to tell which slashes in the Path were
// slashes in the raw URL and which were %2f. This distinction is rarely important,
// but when it is, code must not use Path directly.
// The Parse function sets both Path and RawPath in the URL it returns,
// and URL's String method uses RawPath if it is a valid encoding of Path,
// by calling the EscapedPath method.
  TUrl = record
    Scheme:     UTF8String;
    Opaque:     UTF8String;    // encoded opaque data
    User:       TUserinfo;     // username and password information
    Host:       UTF8String;    // host or host:port
    Path:       UTF8String;    // path (relative paths may omit leading slash)
    RawPath:    UTF8String;    // encoded path hint (see EscapedPath method)
    ForceQuery: Boolean;       // append a query ('?') even if RawQuery is empty
    RawQuery:   UTF8String;    // encoded query values, without '?'
    Fragment:   UTF8String;    // fragment for references, without '#'
    //---
    class function Empty: TUrl; static;
    function ParseStr(const ref: UTF8String; out R: TUrl): IError;
    function ResolveReference(const ref: TUrl): TUrl;
  end;

implementation

uses
  AcedStrings,
  //
  Golang.Strconv.Quote;

constructor TError.Create(const AOp, AUrl: UTF8String; const AErr: IError);
begin
  Op  := AOp;
  URL := AUrl;
  Err := AErr;
end;

function TError.Error: UTF8String;
begin
  Result := Op + ' ' + URL + '": ' + Err.Error()
end;

function ishex(const c: AnsiChar): Boolean;
begin
  Result := (('0' <= c) and (c <= '9')) or
            (('a' <= c) and (c <= 'f')) or
            (('A' <= c) and (c <= 'F'))
end;

function unhex(const c: AnsiChar): Byte;
begin
	if ('0' <= c) and (c <= '9') then
  begin
		Result := Ord(c) - Ord('0');
    Exit;
  end;
	if ('a' <= c) and (c <= 'f') then
  begin
		Result := Ord(c) - Ord('a') + 10;
    Exit;
  end;
	if ('A' <= c) and (c <= 'F') then
  begin
		Result := Ord(c) - Ord('A') + 10;
    Exit;
  end;
  Result := 0
end;


type
  encoding = (encodePath, encodePathSegment, encodeHost, encodeZone,
    encodeUserPassword, encodeQueryComponent, encodeFragment);


function TEscapeError.Error(): UTF8String;
begin
  Result := 'invalid URL escape ' + Quote(s);
end;

function TInvalidHostError.Error(): UTF8String;
begin
  Result := 'invalid character ' + Quote(s) + ' in host name'
end;

// Return true if the specified character should be escaped when
// appearing in a URL string, according to RFC 3986.
//
// Please be informed that for now shouldEscape does not check all
// reserved characters correctly. See golang.org/issue/5684.
function shouldEscape(const c: AnsiChar; const mode: encoding): Boolean;
begin
	// §2.3 Unreserved characters (alphanum)
	if (('A' <= c) and (c <= 'Z')) or (('a' <= c) and (c <= 'z')) or (('0' <= c) and (c <= '9')) then
  begin
		Result := False;
    Exit;
  end;


	if (mode = encodeHost) or (mode = encodeZone) then
  begin
		// §3.2.2 Host allows
		//	sub-delims = "!" / "$" / "&" / "'" / "(" / ")" / "*" / "+" / "," / ";" / "="
		// as part of reg-name.
		// We add : because we include :port as part of host.
		// We add [ ] because we include [ipv6]:port as part of host.
		// We add < > because they're the only characters left that
		// we could possibly allow, and Parse will reject them if we
		// escape them (because hosts can't use %-encoding for
		// ASCII bytes).
		case c of
		  '!', '$', '&', '''', '(', ')', '*', '+', ',', ';', '=', ':', '[', ']', '<', '>', '"':
      begin
			  Result := False;
        Exit;
      end;
    end;
  end;

	case c of
    '-', '_', '.', '~': // §2.3 Unreserved characters (mark)
      begin
			  Result := False;
        Exit;
      end;

    '$', '&', '+', ',', '/', ':', ';', '=', '?', '@': // §2.2 Reserved characters (reserved)
      begin
        // Different sections of the URL allow a few of
        // the reserved characters to appear unescaped.
        case mode of
          encodePath:
            begin
              // §3.3
              // The RFC allows : @ & = + $ but saves / ; , for assigning
              // meaning to individual path segments. This package
              // only manipulates the path as a whole, so we allow those
              // last three as well. That leaves only ? to escape.
              Result := c = '?';
              Exit;
            end;

          encodePathSegment:
            begin
              // §3.3

              // The RFC allows : @ & = + $ but saves / ; , for assigning
              // meaning to individual path segments.
              Result := (c = '/') or (c = ';') or (c = ',') or (c = '?');
              Exit;
            end;

          encodeUserPassword:
            begin
              // §3.2.1
              // The RFC allows ';', ':', '&', '=', '+', '$', and ',' in
              // userinfo, so we must escape only '@', '/', and '?'.
              // The parsing of userinfo treats ':' as special so we must escape
              // that too.
              Result := (c = '@') or (c = '/') or (c = '?') or (c = ':');
              Exit;
            end;

          encodeQueryComponent:
            begin
              // §3.4
              // The RFC reserves (so we must escape) everything.
              Result := True;
              Exit;
            end;

          encodeFragment:
            begin
              // §4.1
              // The RFC text is silent but the grammar allows
              // everything, so escape nothing.
              Result := False;
              Exit;
            end
        end;
      end;
	end;

	if (mode = encodeFragment) then
  begin
		// RFC 3986 §2.2 allows not escaping sub-delims. A subset of sub-delims are
		// included in reserved from RFC 2396 §2.2. The remaining sub-delims do not
		// need to be escaped. To minimize potential breakage, we apply two restrictions:
		// (1) we always escape sub-delims outside of the fragment, and (2) we always
		// escape single quote to avoid breaking callers that had previously assumed that
		// single quotes would be escaped. See issue #19917.
		case c of
		   '!', '(', ')', '*':
       begin
         Result := False;
         Exit;
       end;
    end;
	end;

	// Everything else must be escaped.
	Result := True
end;


// unescape unescapes a string; the mode specifies
// which section of the URL string is being unescaped.
function unescape(const s: UTF8String; const mode: encoding; out R: UTF8String): IError;
var
  len: Integer;
  i,j: Integer;
  n: Integer;
  hasPlus: Boolean;
  z: UTF8String;
  v: Byte;
  t: TAnsiStringBuilder;
begin
	// Count %, check that they're well-formed.
	n := 0;
  len := Length(s);
	hasPlus := False;
  i := 1;
	while i <= Length(s) do
  begin
		case s[i] of
		  '%': begin
        Inc(n);
        if ((i+2) > len) or (not ishex(s[i+1]) or not ishex(s[i+2])) then
        begin
          z := Copy(s, i, 3);
          R := '';
          Result := TEscapeError.Create(z);
          Exit;
        end;
        // Per https://tools.ietf.org/html/rfc3986#page-21
        // in the host component %-encoding can only be used
        // for non-ASCII bytes.
        // But https://tools.ietf.org/html/rfc6874#section-2
        // introduces %25 being allowed to escape a percent sign
        // in IPv6 scoped-address literals. Yay.
        if mode = encodeHost then
        begin
          if ((i+1) > len) or (unhex(s[i+1]) < 8) then
          begin
            z := Copy(s, i, 3);
            if (z <> '%25') then
            begin
              R := '';
              Result := TEscapeError.Create(z);
              Exit;
            end;
          end;
        end;
        if (mode = encodeZone) then
        begin
          // RFC 6874 says basically "anything goes" for zone identifiers
          // and that even non-ASCII can be redundantly escaped,
          // but it seems prudent to restrict %-escaped bytes here to those
          // that are valid host name bytes in their unescaped form.
          // That is, you can use escaping in the zone identifier but not
          // to introduce bytes you couldn't just write directly.
          // But Windows puts spaces here! Yay.
          v := (unhex(s[i+1]) shl 4) or unhex(s[i+2]);
          z := Copy(s, i, 3);
          if (z <> '%25') and (v <> 32) and shouldEscape(AnsiChar(v), encodeHost) then
          begin
            R := '';
            Result := TEscapeError.Create(z);
            Exit;
          end;
        end;
        Inc(i, 3)
      end;
      '+': begin
        hasPlus := mode = encodeQueryComponent;
        Inc(i);
      end;
      else begin
        if ((mode = encodeHost) or (mode = encodeZone)) then
          if (s[i] < #$80) and shouldEscape(s[i], mode) then
          begin
            R := '';
            Result := TInvalidHostError(Copy(s, i, 1));
            Exit;
          end;
        Inc(i);
      end;
    end;
	end;

	if (n = 0) and not hasPlus then
  begin
    R := s;
		Result := nil;
    Exit;
	end;

	t := TAnsiStringBuilder.Create(len - 2 * n);
	j := 0;
  i := 1;
	while i <= len do
  begin
		case s[i] of
      '%': begin
        t.Chars[j] := AnsiChar((unhex(s[i+1]) shl 4) or unhex(s[i+2]));
        Inc(j);
        Inc(i, 3);
      end;
      '+': begin
        if mode = encodeQueryComponent then
          t.Chars[j] := #32
        else
          t.Chars[j] := '+';

        Inc(j);
        Inc(i);
      end;
      else begin
        t.Chars[j] := s[i];
        Inc(j);
        Inc(i);
      end
		end
	end;
  R := t.ToString;
	Result := nil;
end;

// QueryUnescape does the inverse transformation of QueryEscape,
// converting each 3-byte encoded substring of the form "%AB" into the
// hex-decoded byte 0xAB.
// It returns an error if any % is not followed by two hexadecimal
// digits.
function QueryUnescape(const s: UTF8String; out R: UTF8String): IError;
begin
	Result := unescape(s, encodeQueryComponent, R)
end;

(*

// PathUnescape does the inverse transformation of PathEscape,
// converting each 3-byte encoded substring of the form "%AB" into the
// hex-decoded byte 0xAB. It returns an error if any % is not followed
// by two hexadecimal digits.
//
// PathUnescape is identical to QueryUnescape except that it does not
// unescape '+' to ' ' (space).
func PathUnescape(s string) (string, error) {
	return unescape(s, encodePathSegment)
}


// QueryEscape escapes the string so it can be safely placed
// inside a URL query.
func QueryEscape(s string) string {
	return escape(s, encodeQueryComponent)
}

// PathEscape escapes the string so it can be safely placed
// inside a URL path segment.
func PathEscape(s string) string {
	return escape(s, encodePathSegment)
}

func escape(s string, mode encoding) string {
	spaceCount, hexCount := 0, 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		if shouldEscape(c, mode) {
			if c == ' ' && mode == encodeQueryComponent {
				spaceCount++
			} else {
				hexCount++
			}
		}
	}

	if spaceCount == 0 && hexCount == 0 {
		return s
	}

	var buf [64]byte
	var t []byte

	required := len(s) + 2*hexCount
	if required <= len(buf) {
		t = buf[:required]
	} else {
		t = make([]byte, required)
	}

	if hexCount == 0 {
		copy(t, s)
		for i := 0; i < len(s); i++ {
			if s[i] == ' ' {
				t[i] = '+'
			}
		}
		return string(t)
	}

	j := 0
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c == ' ' && mode == encodeQueryComponent:
			t[j] = '+'
			j++
		case shouldEscape(c, mode):
			t[j] = '%'
			t[j+1] = "0123456789ABCDEF"[c>>4]
			t[j+2] = "0123456789ABCDEF"[c&15]
			j += 3
		default:
			t[j] = s[i]
			j++
		}
	}
	return string(t)
}


// User returns a Userinfo containing the provided username
// and no password set.
func User(username string) *Userinfo {
	return &Userinfo{username, "", false}
}

// UserPassword returns a Userinfo containing the provided username
// and password.
//
// This functionality should only be used with legacy web sites.
// RFC 2396 warns that interpreting Userinfo this way
// ``is NOT RECOMMENDED, because the passing of authentication
// information in clear text (such as URI) has proven to be a
// security risk in almost every case where it has been used.''
func UserPassword(username, password string) *Userinfo {
	return &Userinfo{username, password, true}
}


*)

function TUserinfo.IsEmpty: Boolean;
begin
  Result := username = ''
end;

procedure TUserinfo.Empty;
begin
  username := '';
  password := '';
  passwordSet := False;
end;

(*

// Username returns the username.
func (u *Userinfo) Username() string {
	if u == nil {
		return ""
	}
	return u.username
}

// Password returns the password in case it is set, and whether it is set.
func (u *Userinfo) Password() (string, bool) {
	if u == nil {
		return "", false
	}
	return u.password, u.passwordSet
}

// String returns the encoded userinfo information in the standard form
// of "username[:password]".
func (u *Userinfo) String() string {
	if u == nil {
		return ""
	}
	s := escape(u.username, encodeUserPassword)
	if u.passwordSet {
		s += ":" + escape(u.password, encodeUserPassword)
	}
	return s
}

// Maybe rawurl is of the form scheme:path.
// (Scheme must be [a-zA-Z][a-zA-Z0-9+-.]* )
// If so, return scheme, path; else return "", rawurl.
func getscheme(rawurl string) (scheme, path string, err error) {
	for i := 0; i < len(rawurl); i++ {
		c := rawurl[i]
		switch {
		case 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z':
		// do nothing
		case '0' <= c && c <= '9' || c == '+' || c == '-' || c == '.':
			if i == 0 {
				return "", rawurl, nil
			}
		case c == ':':
			if i == 0 {
				return "", "", errors.New("missing protocol scheme")
			}
			return rawurl[:i], rawurl[i+1:], nil
		default:
			// we have encountered an invalid character,
			// so there is no valid scheme
			return "", rawurl, nil
		}
	}
	return "", rawurl, nil
}

*)

// Maybe s is of the form t c u.
// If so, return t, c u (or t, u if cutc == true).
// If not, return s, "".
procedure split(const s, c: UTF8String; cutc: Boolean; out R1, R2: UTF8String);
var i: Integer;
begin
	i := Pos(c, s);
	if i < 0 then
  begin
    R1 := s;
    R2 := '';
		Exit;
	end;
	if cutc then
  begin
    R1 := Copy(s, 1, i - 1);
    R2 := Copy(s, i + Length(c), MaxInt);
	end;
  R1 := Copy(s, 1, i - 1);
  R2 := Copy(s, i, MaxInt);
end;

// Parse parses rawurl into a URL structure.
//
// The rawurl may be relative (a path, without a host) or absolute
// (starting with a scheme). Trying to parse a hostname and path
// without a scheme is invalid but may not necessarily return an
// error, due to parsing ambiguities.
function Parse(const rawurl: PUTF8String; out R: TUrl): IError;
var
  u, frag: PUTF8String;
  err: IError;
  url: TUrl;
begin
  R := TUrl.Empty;
	// Cut off #frag
  split(rawurl, '#', true, u, frag);
	err := parse(u, false, url);
	if err <> nil then
  begin
    Result := TError.Create('parse', u, err);
    Exit;
	end;
	if frag = '' then
  begin
    R := url;
    Result := nil;
    Exit;
	end;
  err := unescape(frag, encodeFragment, url.Fragment);
	if  err <> nil then
  begin
    Result := TError.Create('parse', rawurl, err);
    Exit;
	end;
  R := url;
  Result := nil;
end;

(*
// ParseRequestURI parses rawurl into a URL structure. It assumes that
// rawurl was received in an HTTP request, so the rawurl is interpreted
// only as an absolute URI or an absolute path.
// The string rawurl is assumed not to have a #fragment suffix.
// (Web browsers strip #fragment before sending the URL to a web server.)
func ParseRequestURI(rawurl string) (*URL, error) {
	url, err := parse(rawurl, true)
	if err != nil {
		return nil, &Error{"parse", rawurl, err}
	}
	return url, nil
}

// parse parses a URL from a string in one of two contexts. If
// viaRequest is true, the URL is assumed to have arrived via an HTTP request,
// in which case only absolute URLs or path-absolute relative URLs are allowed.
// If viaRequest is false, all forms of relative URLs are allowed.
func parse(rawurl string, viaRequest bool) (*URL, error) {
	var rest string
	var err error

	if stringContainsCTLByte(rawurl) {
		return nil, errors.New("net/url: invalid control character in URL")
	}

	if rawurl == "" && viaRequest {
		return nil, errors.New("empty url")
	}
	url := new(URL)

	if rawurl == "*" {
		url.Path = "*"
		return url, nil
	}

	// Split off possible leading "http:", "mailto:", etc.
	// Cannot contain escaped characters.
	if url.Scheme, rest, err = getscheme(rawurl); err != nil {
		return nil, err
	}
	url.Scheme = strings.ToLower(url.Scheme)

	if strings.HasSuffix(rest, "?") && strings.Count(rest, "?") == 1 {
		url.ForceQuery = true
		rest = rest[:len(rest)-1]
	} else {
		rest, url.RawQuery = split(rest, "?", true)
	}

	if !strings.HasPrefix(rest, "/") {
		if url.Scheme != "" {
			// We consider rootless paths per RFC 3986 as opaque.
			url.Opaque = rest
			return url, nil
		}
		if viaRequest {
			return nil, errors.New("invalid URI for request")
		}

		// Avoid confusion with malformed schemes, like cache_object:foo/bar.
		// See golang.org/issue/16822.
		//
		// RFC 3986, §3.3:
		// In addition, a URI reference (Section 4.1) may be a relative-path reference,
		// in which case the first path segment cannot contain a colon (":") character.
		colon := strings.Index(rest, ":")
		slash := strings.Index(rest, "/")
		if colon >= 0 && (slash < 0 || colon < slash) {
			// First path segment has colon. Not allowed in relative URL.
			return nil, errors.New("first path segment in URL cannot contain colon")
		}
	}

	if (url.Scheme != "" || !viaRequest && !strings.HasPrefix(rest, "///")) && strings.HasPrefix(rest, "//") {
		var authority string
		authority, rest = split(rest[2:], "/", false)
		url.User, url.Host, err = parseAuthority(authority)
		if err != nil {
			return nil, err
		}
	}
	// Set Path and, optionally, RawPath.
	// RawPath is a hint of the encoding of Path. We don't want to set it if
	// the default escaping of Path is equivalent, to help make sure that people
	// don't rely on it in general.
	if err := url.setPath(rest); err != nil {
		return nil, err
	}
	return url, nil
}

func parseAuthority(authority string) (user *Userinfo, host string, err error) {
	i := strings.LastIndex(authority, "@")
	if i < 0 {
		host, err = parseHost(authority)
	} else {
		host, err = parseHost(authority[i+1:])
	}
	if err != nil {
		return nil, "", err
	}
	if i < 0 {
		return nil, host, nil
	}
	userinfo := authority[:i]
	if !validUserinfo(userinfo) {
		return nil, "", errors.New("net/url: invalid userinfo")
	}
	if !strings.Contains(userinfo, ":") {
		if userinfo, err = unescape(userinfo, encodeUserPassword); err != nil {
			return nil, "", err
		}
		user = User(userinfo)
	} else {
		username, password := split(userinfo, ":", true)
		if username, err = unescape(username, encodeUserPassword); err != nil {
			return nil, "", err
		}
		if password, err = unescape(password, encodeUserPassword); err != nil {
			return nil, "", err
		}
		user = UserPassword(username, password)
	}
	return user, host, nil
}

// parseHost parses host as an authority without user
// information. That is, as host[:port].
func parseHost(host string) (string, error) {
	if strings.HasPrefix(host, "[") {
		// Parse an IP-Literal in RFC 3986 and RFC 6874.
		// E.g., "[fe80::1]", "[fe80::1%25en0]", "[fe80::1]:80".
		i := strings.LastIndex(host, "]")
		if i < 0 {
			return "", errors.New("missing ']' in host")
		}
		colonPort := host[i+1:]
		if !validOptionalPort(colonPort) {
			return "", fmt.Errorf("invalid port %q after host", colonPort)
		}

		// RFC 6874 defines that %25 (%-encoded percent) introduces
		// the zone identifier, and the zone identifier can use basically
		// any %-encoding it likes. That's different from the host, which
		// can only %-encode non-ASCII bytes.
		// We do impose some restrictions on the zone, to avoid stupidity
		// like newlines.
		zone := strings.Index(host[:i], "%25")
		if zone >= 0 {
			host1, err := unescape(host[:zone], encodeHost)
			if err != nil {
				return "", err
			}
			host2, err := unescape(host[zone:i], encodeZone)
			if err != nil {
				return "", err
			}
			host3, err := unescape(host[i:], encodeHost)
			if err != nil {
				return "", err
			}
			return host1 + host2 + host3, nil
		}
	}

	var err error
	if host, err = unescape(host, encodeHost); err != nil {
		return "", err
	}
	return host, nil
}

// setPath sets the Path and RawPath fields of the URL based on the provided
// escaped path p. It maintains the invariant that RawPath is only specified
// when it differs from the default encoding of the path.
// For example:
// - setPath("/foo/bar")   will set Path="/foo/bar" and RawPath=""
// - setPath("/foo%2fbar") will set Path="/foo/bar" and RawPath="/foo%2fbar"
// setPath will return an error only if the provided path contains an invalid
// escaping.
func (u *URL) setPath(p string) error {
	path, err := unescape(p, encodePath)
	if err != nil {
		return err
	}
	u.Path = path
	if escp := escape(path, encodePath); p == escp {
		// Default encoding is fine.
		u.RawPath = ""
	} else {
		u.RawPath = p
	}
	return nil
}

// EscapedPath returns the escaped form of u.Path.
// In general there are multiple possible escaped forms of any path.
// EscapedPath returns u.RawPath when it is a valid escaping of u.Path.
// Otherwise EscapedPath ignores u.RawPath and computes an escaped
// form on its own.
// The String and RequestURI methods use EscapedPath to construct
// their results.
// In general, code should call EscapedPath instead of
// reading u.RawPath directly.
func (u *URL) EscapedPath() string {
	if u.RawPath != "" && validEncodedPath(u.RawPath) {
		p, err := unescape(u.RawPath, encodePath)
		if err == nil && p == u.Path {
			return u.RawPath
		}
	}
	if u.Path == "*" {
		return "*" // don't escape (Issue 11202)
	}
	return escape(u.Path, encodePath)
}

// validEncodedPath reports whether s is a valid encoded path.
// It must not contain any bytes that require escaping during path encoding.
func validEncodedPath(s string) bool {
	for i := 0; i < len(s); i++ {
		// RFC 3986, Appendix A.
		// pchar = unreserved / pct-encoded / sub-delims / ":" / "@".
		// shouldEscape is not quite compliant with the RFC,
		// so we check the sub-delims ourselves and let
		// shouldEscape handle the others.
		switch s[i] {
		case '!', '$', '&', '\'', '(', ')', '*', '+', ',', ';', '=', ':', '@':
			// ok
		case '[', ']':
			// ok - not specified in RFC 3986 but left alone by modern browsers
		case '%':
			// ok - percent encoded, will decode
		default:
			if shouldEscape(s[i], encodePath) {
				return false
			}
		}
	}
	return true
}

// validOptionalPort reports whether port is either an empty string
// or matches /^:\d*$/
func validOptionalPort(port string) bool {
	if port == "" {
		return true
	}
	if port[0] != ':' {
		return false
	}
	for _, b := range port[1:] {
		if b < '0' || b > '9' {
			return false
		}
	}
	return true
}

// String reassembles the URL into a valid URL string.
// The general form of the result is one of:
//
//	scheme:opaque?query#fragment
//	scheme://userinfo@host/path?query#fragment
//
// If u.Opaque is non-empty, String uses the first form;
// otherwise it uses the second form.
// Any non-ASCII characters in host are escaped.
// To obtain the path, String uses u.EscapedPath().
//
// In the second form, the following rules apply:
//	- if u.Scheme is empty, scheme: is omitted.
//	- if u.User is nil, userinfo@ is omitted.
//	- if u.Host is empty, host/ is omitted.
//	- if u.Scheme and u.Host are empty and u.User is nil,
//	   the entire scheme://userinfo@host/ is omitted.
//	- if u.Host is non-empty and u.Path begins with a /,
//	   the form host/path does not add its own /.
//	- if u.RawQuery is empty, ?query is omitted.
//	- if u.Fragment is empty, #fragment is omitted.
func (u *URL) String() string {
	var buf strings.Builder
	if u.Scheme != "" {
		buf.WriteString(u.Scheme)
		buf.WriteByte(':')
	}
	if u.Opaque != "" {
		buf.WriteString(u.Opaque)
	} else {
		if u.Scheme != "" || u.Host != "" || u.User != nil {
			if u.Host != "" || u.Path != "" || u.User != nil {
				buf.WriteString("//")
			}
			if ui := u.User; ui != nil {
				buf.WriteString(ui.String())
				buf.WriteByte('@')
			}
			if h := u.Host; h != "" {
				buf.WriteString(escape(h, encodeHost))
			}
		}
		path := u.EscapedPath()
		if path != "" && path[0] != '/' && u.Host != "" {
			buf.WriteByte('/')
		}
		if buf.Len() == 0 {
			// RFC 3986 §4.2
			// A path segment that contains a colon character (e.g., "this:that")
			// cannot be used as the first segment of a relative-path reference, as
			// it would be mistaken for a scheme name. Such a segment must be
			// preceded by a dot-segment (e.g., "./this:that") to make a relative-
			// path reference.
			if i := strings.IndexByte(path, ':'); i > -1 && strings.IndexByte(path[:i], '/') == -1 {
				buf.WriteString("./")
			}
		}
		buf.WriteString(path)
	}
	if u.ForceQuery || u.RawQuery != "" {
		buf.WriteByte('?')
		buf.WriteString(u.RawQuery)
	}
	if u.Fragment != "" {
		buf.WriteByte('#')
		buf.WriteString(escape(u.Fragment, encodeFragment))
	}
	return buf.String()
}

// Values maps a string key to a list of values.
// It is typically used for query parameters and form values.
// Unlike in the http.Header map, the keys in a Values map
// are case-sensitive.
type Values map[string][]string

// Get gets the first value associated with the given key.
// If there are no values associated with the key, Get returns
// the empty string. To access multiple values, use the map
// directly.
func (v Values) Get(key string) string {
	if v == nil {
		return ""
	}
	vs := v[key]
	if len(vs) == 0 {
		return ""
	}
	return vs[0]
}

// Set sets the key to value. It replaces any existing
// values.
func (v Values) Set(key, value string) {
	v[key] = []string{value}
}

// Add adds the value to key. It appends to any existing
// values associated with key.
func (v Values) Add(key, value string) {
	v[key] = append(v[key], value)
}

// Del deletes the values associated with key.
func (v Values) Del(key string) {
	delete(v, key)
}

// ParseQuery parses the URL-encoded query string and returns
// a map listing the values specified for each key.
// ParseQuery always returns a non-nil map containing all the
// valid query parameters found; err describes the first decoding error
// encountered, if any.
//
// Query is expected to be a list of key=value settings separated by
// ampersands or semicolons. A setting without an equals sign is
// interpreted as a key set to an empty value.
func ParseQuery(query string) (Values, error) {
	m := make(Values)
	err := parseQuery(m, query)
	return m, err
}

func parseQuery(m Values, query string) (err error) {
	for query != "" {
		key := query
		if i := strings.IndexAny(key, "&;"); i >= 0 {
			key, query = key[:i], key[i+1:]
		} else {
			query = ""
		}
		if key == "" {
			continue
		}
		value := ""
		if i := strings.Index(key, "="); i >= 0 {
			key, value = key[:i], key[i+1:]
		}
		key, err1 := QueryUnescape(key)
		if err1 != nil {
			if err == nil {
				err = err1
			}
			continue
		}
		value, err1 = QueryUnescape(value)
		if err1 != nil {
			if err == nil {
				err = err1
			}
			continue
		}
		m[key] = append(m[key], value)
	}
	return err
}

// Encode encodes the values into ``URL encoded'' form
// ("bar=baz&foo=quux") sorted by key.
func (v Values) Encode() string {
	if v == nil {
		return ""
	}
	var buf strings.Builder
	keys := make([]string, 0, len(v))
	for k := range v {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		vs := v[k]
		keyEscaped := QueryEscape(k)
		for _, v := range vs {
			if buf.Len() > 0 {
				buf.WriteByte('&')
			}
			buf.WriteString(keyEscaped)
			buf.WriteByte('=')
			buf.WriteString(QueryEscape(v))
		}
	}
	return buf.String()
}

// resolvePath applies special path segments from refs and applies
// them to base, per RFC 3986.
func resolvePath(base, ref string) string {
	var full string
	if ref == "" {
		full = base
	} else if ref[0] != '/' {
		i := strings.LastIndex(base, "/")
		full = base[:i+1] + ref
	} else {
		full = ref
	}
	if full == "" {
		return ""
	}
	var dst []string
	src := strings.Split(full, "/")
	for _, elem := range src {
		switch elem {
		case ".":
			// drop
		case "..":
			if len(dst) > 0 {
				dst = dst[:len(dst)-1]
			}
		default:
			dst = append(dst, elem)
		}
	}
	if last := src[len(src)-1]; last == "." || last == ".." {
		// Add final slash to the joined path.
		dst = append(dst, "")
	}
	return "/" + strings.TrimPrefix(strings.Join(dst, "/"), "/")
}

// IsAbs reports whether the URL is absolute.
// Absolute means that it has a non-empty scheme.
func (u *URL) IsAbs() bool {
	return u.Scheme != ""
}

*)

// Parse parses a URL in the context of the receiver. The provided URL
// may be relative or absolute. Parse returns nil, err on parse
// failure, otherwise its return value is the same as ResolveReference.
class function TUrl.Empty: TUrl;
begin
  Result := Default(TUrl);
end;

function TUrl.ParseStr(const ref: UTF8String; out R: TUrl): IError;
var refurl: TUrl;
begin
	Result := Parse(ref, refurl);
	if Result <> nil then
  begin
    R := '';
		Exit;
  end;
	R := ResolveReference(refurl);
  Result := nil
end;

// ResolveReference resolves a URI reference to an absolute URI from
// an absolute base URI u, per RFC 3986 Section 5.2. The URI reference
// may be relative or absolute. ResolveReference always returns a new
// URL instance, even if the returned URL is identical to either the
// base or reference. If ref is an absolute URL, then ResolveReference
// ignores base and returns a copy of ref.
function TUrl.ResolveReference(const ref: TUrl): TUrl;
begin
	Result := ref;
	if ref.Scheme = '' then
  begin
		Result.Scheme = Scheme;
	end;
	if (ref.Scheme <> '') or (ref.Host <> '') or (not ref.User.IsEmpty) then
  begin
		// The "absoluteURI" or "net_path" cases.
		// We can ignore the error from setPath since we know we provided a
		// validly-escaped path.
		Result.setPath(resolvePath(ref.EscapedPath(), ''));
		Exit;
	end;
	if ref.Opaque <> '' then
  begin
		Result.User.Empty();
		Result.Host := '';
		Result.Path := '';
		Exit;
	end;
	if (ref.Path = '') and (ref.RawQuery = '') then
  begin
		Result.RawQuery = RawQuery;
		if ref.Fragment = '' then
			Result.Fragment = Fragment;
	end;
	// The "abs_path" or "rel_path" cases.
	Result.Host = Host;
	Result.User = User;
	Result.setPath(resolvePath(EscapedPath(), ref.EscapedPath()));
end;

(*
// Query parses RawQuery and returns the corresponding values.
// It silently discards malformed value pairs.
// To check errors use ParseQuery.
func (u *URL) Query() Values {
	v, _ := ParseQuery(u.RawQuery)
	return v
}

// RequestURI returns the encoded path?query or opaque?query
// string that would be used in an HTTP request for u.
func (u *URL) RequestURI() string {
	result := u.Opaque
	if result == "" {
		result = u.EscapedPath()
		if result == "" {
			result = "/"
		}
	} else {
		if strings.HasPrefix(result, "//") {
			result = u.Scheme + ":" + result
		}
	}
	if u.ForceQuery || u.RawQuery != "" {
		result += "?" + u.RawQuery
	}
	return result
}

// Hostname returns u.Host, without any port number.
//
// If Host is an IPv6 literal with a port number, Hostname returns the
// IPv6 literal without the square brackets. IPv6 literals may include
// a zone identifier.
func (u *URL) Hostname() string {
	return stripPort(u.Host)
}

// Port returns the port part of u.Host, without the leading colon.
// If u.Host doesn't contain a port, Port returns an empty string.
func (u *URL) Port() string {
	return portOnly(u.Host)
}

func stripPort(hostport string) string {
	colon := strings.IndexByte(hostport, ':')
	if colon == -1 {
		return hostport
	}
	if i := strings.IndexByte(hostport, ']'); i != -1 {
		return strings.TrimPrefix(hostport[:i], "[")
	}
	return hostport[:colon]
}

func portOnly(hostport string) string {
	colon := strings.IndexByte(hostport, ':')
	if colon == -1 {
		return ""
	}
	if i := strings.Index(hostport, "]:"); i != -1 {
		return hostport[i+len("]:"):]
	}
	if strings.Contains(hostport, "]") {
		return ""
	}
	return hostport[colon+len(":"):]
}

// Marshaling interface implementations.
// Would like to implement MarshalText/UnmarshalText but that will change the JSON representation of URLs.

func (u *URL) MarshalBinary() (text []byte, err error) {
	return []byte(u.String()), nil
}

func (u *URL) UnmarshalBinary(text []byte) error {
	u1, err := Parse(string(text))
	if err != nil {
		return err
	}
	*u = *u1
	return nil
}

// validUserinfo reports whether s is a valid userinfo string per RFC 3986
// Section 3.2.1:
//     userinfo    = *( unreserved / pct-encoded / sub-delims / ":" )
//     unreserved  = ALPHA / DIGIT / "-" / "." / "_" / "~"
//     sub-delims  = "!" / "$" / "&" / "'" / "(" / ")"
//                   / "*" / "+" / "," / ";" / "="
//
// It doesn't validate pct-encoded. The caller does that via func unescape.
func validUserinfo(s string) bool {
	for _, r := range s {
		if 'A' <= r && r <= 'Z' {
			continue
		}
		if 'a' <= r && r <= 'z' {
			continue
		}
		if '0' <= r && r <= '9' {
			continue
		}
		switch r {
		case '-', '.', '_', ':', '~', '!', '$', '&', '\'',
			'(', ')', '*', '+', ',', ';', '=', '%', '@':
			continue
		default:
			return false
		}
	}
	return true
}

// stringContainsCTLByte reports whether s contains any ASCII control character.
func stringContainsCTLByte(s string) bool {
	for i := 0; i < len(s); i++ {
		b := s[i]
		if b < ' ' || b == 0x7f {
			return true
		}
	}
	return false
}
}
*)

end.
