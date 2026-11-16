package melon

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

const testLoginID = "test@example.invalid"
const testLoginPassword = "Synthetic-password-123!"
const testPassphrase = "test-passphrase"
const testCSRF = "test-csrf"
const testOAuthState = "CRYT_test+opaque/state=="

// English: Fail closed if any package test accidentally uses a live endpoint. Korean: 패키지 테스트가 실수로 외부 엔드포인트를 사용하면 통신 전에 실패합니다.
func TestMain(m *testing.M) {
	base := http.DefaultTransport.(*http.Transport).Clone()
	base.Proxy = nil
	http.DefaultTransport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		ip := net.ParseIP(r.URL.Hostname())
		if ip == nil || !ip.IsLoopback() {
			return nil, fmt.Errorf("external network is disabled in tests: %s", r.URL.Hostname())
		}
		return base.RoundTrip(r)
	})
	os.Exit(m.Run())
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// English: Use an independent OpenSSL vector with synthetic credentials, never captured account secrets. Korean: 실제 계정 정보 대신 합성 자격 증명으로 만든 독립 OpenSSL 벡터를 사용합니다.
func TestEncryptKakaoPassword(t *testing.T) {
	const vector = "U2FsdGVkX18BAgMEBQYHCBZxmhtsXZR7lSUdXxIp1m9KT9hDZ/I9JhIcWUVDeRqF"
	for _, encoded := range []string{vector, mustEncrypt(t)} {
		if got := decryptPassword(t, encoded); got != testLoginPassword {
			t.Fatal("password does not match the independent OpenSSL vector")
		}
	}
	if _, err := encryptKakaoPassword(testLoginPassword, ""); err == nil {
		t.Fatal("expected missing passphrase error")
	}
}

func mustEncrypt(t *testing.T) string {
	t.Helper()
	encoded, err := encryptKakaoPassword(testLoginPassword, testPassphrase)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func decryptPassword(t *testing.T, encoded string) string {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil || len(raw) <= 16 || string(raw[:8]) != "Salted__" || (len(raw)-16)%aes.BlockSize != 0 {
		t.Error("password is not OpenSSL Salted AES ciphertext")
		return ""
	}
	key, iv := evpBytesToKey([]byte(testPassphrase), raw[8:16], 32, 16)
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Error(err)
		return ""
	}
	plain := make([]byte, len(raw)-16)
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(plain, raw[16:])
	pad := int(plain[len(plain)-1])
	if pad < 1 || pad > aes.BlockSize || pad > len(plain) {
		t.Error("invalid PKCS7 padding")
		return ""
	}
	for _, b := range plain[len(plain)-pad:] {
		if int(b) != pad {
			t.Error("invalid PKCS7 padding bytes")
			return ""
		}
	}
	return string(plain[:len(plain)-pad])
}

func TestParseNextData(t *testing.T) {
	page, err := parseNextData(testNextData("/login?continue=x", "https://kauth.kakao.com/oauth/authorize?state=test", "en"))
	if err != nil {
		t.Fatal(err)
	}
	if page.csrf != testCSRF || page.p != testPassphrase || page.loginURL != "/login?continue=x" || page.locale != "en" {
		t.Fatal("NEXT_DATA fields were not preserved")
	}
	for _, malformed := range []string{"<html></html>", `<script id="__NEXT_DATA__" type="application/json">{}</script>`} {
		if _, err := parseNextData(malformed); err == nil {
			t.Fatal("expected missing NEXT_DATA fields error")
		}
	}
}

func TestParseMelonAuthorizeURL(t *testing.T) {
	want := testAuthorizeURL()
	for _, content := range []string{`document.location.href = "` + want + `";`, `<a href="` + html.EscapeString(want) + `">Login</a>`} {
		got, err := parseMelonAuthorizeURL(content)
		if err != nil || got != want {
			t.Fatalf("server-issued authorize URL was not preserved: %v", err)
		}
	}
	for _, content := range []string{"<html>Login</html>", kakaoAuthorizeURL + "?client_id=test", strings.Replace(want, "accounts.melon.com", "example.invalid", 1)} {
		if _, err := parseMelonAuthorizeURL(content); err == nil {
			t.Fatal("expected invalid authorize URL error")
		}
	}
}

func TestParseOAuthForm(t *testing.T) {
	at, rt, poc, redirect, err := parseOAuthForm(`<form><input value="at&amp;test" name="accessToken"><input name="refreshToken" value="rt"><input name="pocId" value="MP15"><input name="redirectURL" value="https://ticket.melon.com/main/readingGate.htm?a=1&amp;b=2"></form>`)
	if err != nil || at != "at&test" || rt != "rt" || poc != "MP15" || !strings.HasSuffix(redirect, "?a=1&b=2") {
		t.Fatalf("OAuth form fields or entities were not preserved: %v", err)
	}
}

// English: Session is now in-memory only; Login must not write .env. Korean: 세션은 메모리 전용이며 Login은 .env를 쓰지 않습니다.

type mockReply struct {
	status int
	body   string
}

type loginFixture struct {
	requests []string
	pcid     string
	loadedAt time.Time
}

func testAuthorizeURL() string {
	return kakaoAuthorizeURL + "?" + url.Values{
		"client_id": {"test-client"}, "redirect_uri": {melonOAuthURL}, "response_type": {"code"},
		"state": {testOAuthState}, "encode_state": {"true"}, "prompt": {""},
	}.Encode()
}

func testNextData(loginURL, continueURL, locale string) string {
	data := map[string]any{"props": map[string]any{"pageProps": map[string]any{"pageContext": map[string]any{
		"commonContext": map[string]string{"_csrf": testCSRF, "p": testPassphrase, "locale": locale},
		"context":       map[string]any{"loginUrl": loginURL, "continueUrl": continueURL, "showPasskeyLogin": true, "useDkaptcha": true},
	}}}}
	body, _ := json.Marshal(data)
	return `<script id="__NEXT_DATA__" type="application/json">` + string(body) + `</script>`
}

// English: Preserve real hostnames for cookie scope while every transport call goes to one local TLS server. Korean: 쿠키 범위를 검증하도록 실제 호스트명을 유지하되 모든 통신은 로컬 TLS 서버로 보냅니다.
func newLoginFixture(t *testing.T, overrides map[string]mockReply, redirectProcs bool) *loginFixture {
	t.Helper()
	fixture := &loginFixture{}
	continueURL := testAuthorizeURL() + "&through_account=true&auth_tran_id=test-transaction&ka=test-agent"
	loginPath := "/login?continue=" + url.QueryEscape(continueURL) + "&lang=ko"
	loginURL := "https://accounts.kakao.com" + loginPath
	assertCookie := func(r *http.Request, name, value string) {
		t.Helper()
		c, err := r.Cookie(name)
		if err != nil || c.Value != value {
			t.Errorf("cookie %s was not preserved for %s", name, r.Host+r.URL.Path)
		}
	}
	noCookie := func(r *http.Request, name string) {
		t.Helper()
		if _, err := r.Cookie(name); err == nil {
			t.Errorf("cookie %s leaked to %s", name, r.Host+r.URL.Path)
		}
	}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		step := r.Host + r.URL.Path
		if r.Host == "kauth.kakao.com" && r.URL.Query().Get("through_account") == "true" {
			step = "continue"
		}
		fixture.requests = append(fixture.requests, step)
		setCookie := func(name, value, domain string, secure bool) {
			http.SetCookie(w, &http.Cookie{Name: name, Value: value, Domain: domain, Path: "/", Secure: secure, HttpOnly: true})
		}
		if strings.HasPrefix(r.URL.Path, "/api/v2/") {
			if r.Method != http.MethodPost || r.Header.Get("Content-Type") != "application/json" || r.Header.Get("Accept") != "*/*" || r.Header.Get("Accept-Language") != loginAcceptLanguage {
				t.Error("Kakao API method or JSON/language headers differ from the HAR")
			}
			if r.Header.Get("User-Agent") != loginUserAgent || r.Referer() != loginURL || r.Header.Get("Origin") != "https://accounts.kakao.com" || r.Header.Get("Sec-Fetch-Site") != "same-origin" || r.Header.Get("Sec-CH-UA-Platform-Version") != `"27.2.1"` {
				t.Error("Kakao API browser headers differ from the HAR")
			}
			assertCookie(r, "__T_", "1")
			assertCookie(r, "__T_SECURE", "1")
			assertCookie(r, "_maldive_oauth_webapp_session_key", "session-test")
			assertCookie(r, "_T_ANO", "tiara-issued")
			noCookie(r, "__T__")
			noCookie(r, "PCID")
			noCookie(r, "TUID")
		}
		if reply, ok := overrides[step]; ok {
			w.WriteHeader(reply.status)
			_, _ = io.WriteString(w, reply.body)
			return
		}
		readJSON := func() map[string]any {
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Error(err)
			}
			if body["_csrf"] != testCSRF {
				t.Error("CSRF token was not preserved")
			}
			return body
		}
		switch step {
		case "ticket.melon.com/main/index.htm":
			_, _ = io.WriteString(w, "ticket")
		case "accounts.melon.com/login/login.htm":
			c, err := r.Cookie("PCID")
			if err != nil || !regexp.MustCompile(`^\d{23}$`).MatchString(c.Value) {
				t.Error("23-digit PCID must exist before login.htm")
			} else {
				fixture.pcid = c.Value
			}
			setCookie("_MLBRU", "melon-login", "melon.com", false)
			setCookie("MRU", "melon-return", "melon.com", false)
			_, _ = io.WriteString(w, `<script>document.location.href="`+testAuthorizeURL()+`";</script>`)
		case "kauth.kakao.com/oauth/authorize":
			if r.URL.Query().Get("state") != testOAuthState || r.URL.Query().Get("encode_state") != "true" {
				t.Error("Melon server-issued state was replaced")
			}
			http.Redirect(w, r, loginURL, http.StatusFound)
		case "accounts.kakao.com/login":
			fixture.loadedAt = time.Now()
			setCookie("_maldive_oauth_webapp_session_key", "session-test", "", true)
			setCookie("_kau", "page-kau", "kakao.com", true)
			_, _ = io.WriteString(w, testNextData(loginPath, continueURL, "ko"))
		case "stat.tiara.kakao.com/track":
			var body struct {
				SDK    map[string]string `json:"sdk"`
				Common map[string]string `json:"common"`
				Etc    struct {
					Client map[string]any `json:"client_info"`
				} `json:"etc"`
			}
			if r.Method != http.MethodGet || json.Unmarshal([]byte(r.URL.Query().Get("d")), &body) != nil {
				t.Error("invalid Tiara GET pageview")
			}
			if body.SDK["version"] != "1.2.7" || body.Common["url"] != "https://accounts.kakao.com/login/" || body.Common["page"] != "page-login" || body.Common["referrer"] != "https://accounts.melon.com/" {
				t.Error("Tiara pageview differs from the HAR")
			}
			for _, key := range []string{"tuid", "tsid", "uuid", "suid", "isuid"} {
				id, _ := body.Etc.Client[key].(string)
				if !regexp.MustCompile(`^w-[a-zA-Z0-9]{12}_\d{15}$`).MatchString(id) {
					t.Errorf("invalid Tiara %s format", key)
				}
			}
			noCookie(r, "__T_")
			noCookie(r, "_maldive_oauth_webapp_session_key")
			setCookie("_T_ANO", "tiara-issued", ".kakao.com", true)
			setCookie("TUID", "tiara-only", ".tiara.kakao.com", true)
			_, _ = io.WriteString(w, "pixel")
		case "accounts.kakao.com/api/v2/banner/get.json":
			assertCookie(r, "_kau", "page-kau")
			if body := readJSON(); body["continue"] != continueURL || len(body) != 2 {
				t.Error("banner payload differs from the HAR")
			}
			setCookie("_kau", "banner-kau", "kakao.com", true)
			_, _ = io.WriteString(w, `{"status":0}`)
		case "accounts.kakao.com/api/v2/passkey/auth/options":
			assertCookie(r, "_kau", "banner-kau")
			if body := readJSON(); body["username"] != "" || body["userVerification"] != "required" || len(body) != 3 {
				t.Error("passkey payload differs from the HAR")
			}
			setCookie("_kau", "passkey-kau", "kakao.com", true)
			setCookie("_kawask", "passkey-session", "kakao.com", true)
			_, _ = io.WriteString(w, `{"res":{"challenge":"test-challenge"},"status":0}`)
		case "accounts.kakao.com/api/v2/login/authenticate.json":
			assertCookie(r, "_kau", "passkey-kau")
			assertCookie(r, "_kawask", "passkey-session")
			body := readJSON()
			for key, value := range map[string]any{"loginId": testLoginID, "loginKey": testLoginID, "loginUrl": loginPath, "lang": "ko", "staySignedIn": false, "saveSignedIn": false, "k": true} {
				if body[key] != value {
					t.Errorf("authenticate field %s differs from the HAR", key)
				}
			}
			if _, ok := body["captchaToken"]; ok {
				t.Error("unsolved CAPTCHA must not have a token")
			}
			if len(body) != 10 {
				t.Error("unexpected authenticate payload fields")
			}
			password, _ := body["password"].(string)
			if decryptPassword(t, password) != testLoginPassword {
				t.Error("incorrect encrypted password")
			}
			context, _ := body["security_context"].(map[string]any)
			points, _ := context["a"].([]any)
			for _, point := range points {
				stamp := int64(point.(map[string]any)["t"].(float64))
				if stamp < fixture.loadedAt.UnixMilli() || stamp > time.Now().UnixMilli() {
					t.Error("event timestamp is outside the current page visit")
				}
			}
			setCookie("_kau", "auth-kau", "kakao.com", true)
			_, _ = io.WriteString(w, `{"method":"sms","token":"initial-token","status":-451}`)
		case "accounts.kakao.com/api/v2/two_step_verification/send_passcode_for_login.json":
			assertCookie(r, "_kau", "auth-kau")
			if body := readJSON(); body["verifyMethod"] != "sms" || body["reissue"] != true || len(body) != 3 {
				t.Error("send SMS payload differs from the HAR")
			}
			setCookie("_kau", "sms-kau", "kakao.com", true)
			_, _ = io.WriteString(w, `{"token":"reissued-token","expireSeconds":180,"status":0}`)
		case "accounts.kakao.com/api/v2/two_step_verification/verify_passcode_for_login.json":
			assertCookie(r, "_kau", "sms-kau")
			if body := readJSON(); body["verifyMethod"] != "sms" || body["token"] != "reissued-token" || body["passcode"] != "123456" || body["isRememberBrowser"] != true || len(body) != 5 {
				t.Error("verify SMS payload differs from the HAR")
			}
			setCookie("_kau", "verified-kau", "kakao.com", true)
			setCookie("_kawlt", "login-token", "kakao.com", true)
			setCookie("_karb", "remembered-browser", "kakao.com", false)
			w.WriteHeader(http.StatusOK)
		case "continue":
			if r.URL.String() != strings.TrimPrefix(continueURL, "https://kauth.kakao.com") {
				t.Error("continueUrl parameters were not preserved")
			}
			if _, skipped2FA := overrides["accounts.kakao.com/api/v2/login/authenticate.json"]; !skipped2FA {
				assertCookie(r, "_kawlt", "login-token")
				assertCookie(r, "_kau", "verified-kau")
			}
			assertCookie(r, "_T_ANO", "tiara-issued")
			noCookie(r, "__T_")
			noCookie(r, "__T_SECURE")
			noCookie(r, "_maldive_oauth_webapp_session_key")
			http.Redirect(w, r, melonOAuthURL+"?code=test-code&encode_state=true&state="+url.QueryEscape(testOAuthState), http.StatusFound)
		case "accounts.melon.com/oauth.htm":
			assertCookie(r, "PCID", fixture.pcid)
			assertCookie(r, "_MLBRU", "melon-login")
			noCookie(r, "_kau")
			noCookie(r, "__T_")
			_, _ = io.WriteString(w, `<form><input name="pocId" value="MP15"><input name="memberKey" value=""><input name="redirectURL" value="https://ticket.melon.com/main/readingGate.htm"><input name="accessToken" value="at&amp;test"><input name="refreshToken" value="rt-test"><input name="qrCode" value=""><input name="autoLoginYN" value=""><input name="userAgent" value=""></form>`)
		case "accounts.melon.com/login/loginProcs":
			assertCookie(r, "PCID", fixture.pcid)
			assertCookie(r, "__T_", "1")
			assertCookie(r, "__T_SECURE", "1")
			if r.Method != http.MethodPost || r.ParseForm() != nil || r.Header.Get("Origin") != "https://accounts.melon.com" {
				t.Error("invalid loginProcs request")
			}
			want := url.Values{"pocId": {"MP15"}, "memberKey": {""}, "redirectURL": {"https://ticket.melon.com/main/readingGate.htm"}, "accessToken": {"at&test"}, "refreshToken": {"rt-test"}, "qrCode": {""}, "autoLoginYN": {""}, "userAgent": {""}}
			if !reflect.DeepEqual(r.PostForm, want) {
				t.Error("loginProcs fields differ from the HAR")
			}
			setCookie("keyCookie", "test-key", "melon.com", false)
			setCookie("MAC", "test-mac", "melon.com", false)
			setCookie("MLCP", "test-mlcp", "melon.com", false)
			setCookie("MUS", "test-mus", "melon.com", false)
			if redirectProcs {
				http.Redirect(w, r, "https://ticket.melon.com/done", http.StatusFound)
				return
			}
			_, _ = io.WriteString(w, "ok")
		case "ticket.melon.com/done":
			assertCookie(r, "keyCookie", "test-key")
			_, _ = io.WriteString(w, "done")
		default:
			t.Errorf("unexpected request: %s", step)
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	localURL, _ := url.Parse(srv.URL)
	base := srv.Client().Transport
	oldTransport := loginTransport
	loginTransport = roundTripFunc(func(req *http.Request) (*http.Response, error) {
		switch req.URL.Hostname() {
		case "ticket.melon.com", "accounts.melon.com", "accounts.kakao.com", "kauth.kakao.com", "stat.tiara.kakao.com":
		default:
			return nil, fmt.Errorf("unexpected login host: %s", req.URL.Hostname())
		}
		local := req.Clone(req.Context())
		local.URL.Scheme, local.URL.Host = localURL.Scheme, localURL.Host
		local.Host = req.URL.Host
		resp, err := base.RoundTrip(local)
		if resp != nil {
			resp.Request = req
		}
		return resp, err
	})
	t.Cleanup(func() { loginTransport = oldTransport })
	return fixture
}

func TestLoginFullFlow(t *testing.T) {
	for _, redirect := range []bool{false, true} {
		t.Run(fmt.Sprintf("loginProcsRedirect=%t", redirect), func(t *testing.T) {
			fixture := newLoginFixture(t, nil, redirect)
			prompts := 0
			session, err := Login("  "+testLoginID+"  ", testLoginPassword, func() (string, error) { prompts++; return " 123456 ", nil })
			if err != nil {
				t.Fatal(err)
			}
			if session.PCID != fixture.pcid || session.KeyCookie != "test-key" || session.MAC != "test-mac" || session.MLCP != "test-mlcp" || prompts != 1 {
				t.Fatal("login session or SMS prompt count is incorrect")
			}
			want := []string{"ticket.melon.com/main/index.htm", "accounts.melon.com/login/login.htm", "kauth.kakao.com/oauth/authorize", "accounts.kakao.com/login", "stat.tiara.kakao.com/track", "accounts.kakao.com/api/v2/banner/get.json", "accounts.kakao.com/api/v2/passkey/auth/options", "accounts.kakao.com/api/v2/login/authenticate.json", "accounts.kakao.com/api/v2/two_step_verification/send_passcode_for_login.json", "accounts.kakao.com/api/v2/two_step_verification/verify_passcode_for_login.json", "continue", "accounts.melon.com/oauth.htm", "accounts.melon.com/login/loginProcs"}
			if redirect {
				want = append(want, "ticket.melon.com/done")
			}
			if !reflect.DeepEqual(fixture.requests, want) {
				t.Fatalf("request sequence differs from the HAR: %v", fixture.requests)
			}
		})
	}
}

func TestLoginWithoutSMS(t *testing.T) {
	fixture := newLoginFixture(t, map[string]mockReply{"accounts.kakao.com/api/v2/login/authenticate.json": {200, `{"status":0}`}}, false)
	if _, err := Login(testLoginID, testLoginPassword, func() (string, error) { t.Error("unexpected SMS prompt"); return "", nil }); err != nil {
		t.Fatal(err)
	}
	for _, step := range fixture.requests {
		if strings.Contains(step, "passcode_for_login") {
			t.Fatal("SMS request after successful authenticate")
		}
	}
}

func TestLoginStopsOnFailure(t *testing.T) {
	for _, tc := range []struct {
		name, step, body, want string
		status                 int
	}{
		{"tiara cookie missing", "stat.tiara.kakao.com/track", "pixel", "_T_ANO", 200},
		{"banner HTTP error", "accounts.kakao.com/api/v2/banner/get.json", "failure", "HTTP 503", 503},
		{"banner status error", "accounts.kakao.com/api/v2/banner/get.json", `{"status":-1}`, "status -1", 200},
		{"passkey malformed", "accounts.kakao.com/api/v2/passkey/auth/options", "not-json", "decode passkey", 200},
		{"passkey missing status", "accounts.kakao.com/api/v2/passkey/auth/options", `{}`, "no status", 200},
		{"captcha", "accounts.kakao.com/api/v2/login/authenticate.json", `{"status":-481,"dkaptcha":{"widgetId":"test-widget"},"continueUrl":"https://kauth.kakao.com/oauth/authorize"}`, "status -481", 200},
		{"bad password with continue", "accounts.kakao.com/api/v2/login/authenticate.json", `{"status":-450,"continueUrl":"https://kauth.kakao.com/oauth/authorize"}`, "status -450", 200},
		{"authenticate missing status", "accounts.kakao.com/api/v2/login/authenticate.json", `{}`, "no status", 200},
		{"unsupported second factor", "accounts.kakao.com/api/v2/login/authenticate.json", `{"status":-451,"method":"email"}`, "unsupported", 200},
		{"send SMS rejected", "accounts.kakao.com/api/v2/two_step_verification/send_passcode_for_login.json", `{"status":-1,"token":"must-not-use"}`, "status -1", 200},
		{"send SMS token missing", "accounts.kakao.com/api/v2/two_step_verification/send_passcode_for_login.json", `{"status":0}`, "no token", 200},
		{"verify SMS rejected", "accounts.kakao.com/api/v2/two_step_verification/verify_passcode_for_login.json", `{"status":-1}`, "status -1", 200},
		{"verify SMS malformed", "accounts.kakao.com/api/v2/two_step_verification/verify_passcode_for_login.json", `{"message":"failure"}`, "no status", 200},
		{"verify SMS HTTP error", "accounts.kakao.com/api/v2/two_step_verification/verify_passcode_for_login.json", `{"status":0}`, "HTTP 401", 401},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fixture := newLoginFixture(t, map[string]mockReply{tc.step: {tc.status, tc.body}}, false)
			prompts := 0
			_, err := Login(testLoginID, testLoginPassword, func() (string, error) { prompts++; return "123456", nil })
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want %s", err, tc.want)
			}
			if tc.name == "captcha" && (!errors.Is(err, ErrKakaoCaptchaRequired) || prompts != 0) {
				t.Fatal("CAPTCHA must stop without retries or SMS")
			}
			if got := fixture.requests[len(fixture.requests)-1]; got != tc.step {
				t.Fatalf("login continued after failure: %s", got)
			}
		})
	}
}

func TestKakaoCookieScope(t *testing.T) {
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar}
	if err := seedTiaraProbeCookies(client, "https://accounts.kakao.com/login"); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		target string
		names  []string
	}{
		{"https://accounts.kakao.com/api/v2/banner/get.json", []string{"__T_", "__T_SECURE"}},
		{"http://accounts.kakao.com/", []string{"__T_"}},
		{"https://kauth.kakao.com/", nil},
		{"https://stat.tiara.kakao.com/", nil},
	} {
		u, _ := url.Parse(tc.target)
		var names []string
		for _, c := range jar.Cookies(u) {
			names = append(names, c.Name)
		}
		if !reflect.DeepEqual(names, tc.names) {
			t.Errorf("cookie scope for %s = %v", tc.target, names)
		}
	}
}

func TestSecurityContextTimestampsAndCoordinates(t *testing.T) {
	now := time.Unix(1700000000, 0)
	for _, elapsed := range []time.Duration{0, time.Millisecond, 250 * time.Millisecond, 5 * time.Second} {
		started := now.Add(-elapsed)
		context := syntheticSecurityContext(started, now)
		previous := started.UnixMilli()
		points := context["a"].([]any)
		for _, value := range points {
			point := value.(map[string]any)
			stamp := point["t"].(int64)
			if stamp < previous || stamp > now.UnixMilli() {
				t.Fatal("security context has future or unordered events")
			}
			previous = stamp
			for _, key := range []string{"x", "y"} {
				coordinate, err := strconv.ParseInt(point[key].(string), 16, 64)
				if err != nil || coordinate%10000 != 0 {
					t.Fatal("coordinate does not use the captured clientX/Y encoding")
				}
			}
		}
		if points[len(points)-1].(map[string]any)["e"] != 4 || len(context) != 5 {
			t.Fatal("security context shape differs from the HAR")
		}
	}
}

func TestKakaoStatusAcceptsEmptyVerifyOnly(t *testing.T) {
	if err := checkKakaoStatus(nil, "verify SMS", true); err != nil {
		t.Fatal(err)
	}
	if err := checkKakaoStatus([]byte(`{"status":0}`), "verify SMS", true); err != nil {
		t.Fatal(err)
	}
	if err := checkKakaoStatus(nil, "authenticate", false); err == nil {
		t.Fatal("empty authenticate response must fail")
	}
}

func TestExternalHTTPIsBlocked(t *testing.T) {
	if _, err := http.Get("https://example.invalid/"); err == nil || !strings.Contains(err.Error(), "external network is disabled") {
		t.Fatal("external requests are not blocked")
	}
}
