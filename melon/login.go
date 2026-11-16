package melon

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"math/big"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"
)

// English: Session values issued by accounts.melon.com/login/loginProcs (Domain=melon.com). Korean: loginProcs가 발급하는 세션 값입니다.
type Session struct {
	PCID      string
	KeyCookie string
	MAC       string
	MLCP      string
	MUS       string
}

// English: HAR endpoints and an injectable transport for offline tests. Korean: HAR 엔드포인트와 오프라인 테스트용 교체 가능한 전송 계층입니다.
var (
	melonTicketHomeURL   = "https://ticket.melon.com/main/index.htm"
	melonLoginPageURL    = "https://accounts.melon.com/login/login.htm?cpId=MP15&redirectURL=https://ticket.melon.com/main/readingGate.htm"
	kakaoAuthorizeURL    = "https://kauth.kakao.com/oauth/authorize"
	kakaoAuthenticateURL = "https://accounts.kakao.com/api/v2/login/authenticate.json"
	kakaoBannerURL       = "https://accounts.kakao.com/api/v2/banner/get.json"
	kakaoPasskeyURL      = "https://accounts.kakao.com/api/v2/passkey/auth/options"
	kakaoTiaraURL        = "https://stat.tiara.kakao.com/track"
	kakaoSendSMSURL      = "https://accounts.kakao.com/api/v2/two_step_verification/send_passcode_for_login.json"
	kakaoVerifySMSURL    = "https://accounts.kakao.com/api/v2/two_step_verification/verify_passcode_for_login.json"
	melonOAuthURL        = "https://accounts.melon.com/oauth.htm"
	melonLoginProcsURL   = "https://accounts.melon.com/login/loginProcs"
	loginHTTPTimeout     = 30 * time.Second
	loginTransport       http.RoundTripper
)

const loginUserAgent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/157.0.0.0 Safari/537.36"
const loginAcceptLanguage = "ko-KR,ko;q=0.9,en-US;q=0.8,en;q=0.7"

// English: CAPTCHA requires interaction with the current Kakao challenge; do not retry credentials. Korean: CAPTCHA는 현재 카카오 챌린지와의 상호작용이 필요하므로 자격 증명을 재전송하지 않습니다.
var ErrKakaoCaptchaRequired = errors.New("Kakao CAPTCHA interaction is required; pure HTTP login cannot complete this challenge")

// Login logs in with .env KAKAO_LOGIN_ID / KAKAO_LOGIN_PWD and returns the fresh melon.com session.
// English: If Kakao requires SMS 2FA, promptSMS is called; the returned session is used directly by Reservation without writing .env. Korean: Kakao SMS 2단계 인증이 필요하면 promptSMS를 호출하며, 반환된 세션은 .env에 저장하지 않고 Reservation이 바로 사용합니다.
func Login(loginID, loginPassword string, promptSMS func() (string, error)) (*Session, error) {
	loginID = strings.TrimSpace(loginID)
	if loginID == "" {
		return nil, fmt.Errorf("KAKAO_LOGIN_ID is required")
	}
	if loginPassword == "" {
		return nil, fmt.Errorf("KAKAO_LOGIN_PWD is required")
	}
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, fmt.Errorf("create cookie jar: %w", err)
	}
	client := &http.Client{Jar: jar, Timeout: loginHTTPTimeout, Transport: loginTransport}

	// English: Visit ticket.melon.com first so PCID is issued (HAR: PCID exists before login.htm). Korean: login.htm 이전에 PCID가 발급되도록 ticket.melon.com을 먼저 방문합니다.
	if err := warmTicketHome(client); err != nil {
		return nil, err
	}
	if err := ensurePCID(client); err != nil {
		return nil, err
	}
	// English: Preserve Melon's server-generated OAuth state from login.htm (HAR 145/166). Korean: login.htm이 발급한 OAuth state를 그대로 보존합니다.
	authorizeURL, err := openMelonLoginPage(client)
	if err != nil {
		return nil, err
	}
	loginPage, err := fetchKakaoLoginPage(client, authorizeURL)
	if err != nil {
		return nil, err
	}
	csrf, p, continueURL := loginPage.csrf, loginPage.p, loginPage.continueURL

	// English: Tiara's cookie probes precede all API calls; tracking issues _T_ANO (HAR 168/192). Korean: Tiara 검사 쿠키를 API 호출 전에 설정하고 추적 응답에서 _T_ANO를 받습니다.
	if err := seedTiaraProbeCookies(client, loginPage.finalURL); err != nil {
		return nil, err
	}
	if err := warmKakaoTiara(client, loginPage); err != nil {
		return nil, err
	}
	if err := warmKakaoBanner(client, loginPage.finalURL, csrf, continueURL); err != nil {
		return nil, err
	}
	if err := warmKakaoPasskey(client, loginPage.finalURL, csrf); err != nil {
		return nil, err
	}

	encPassword, err := encryptKakaoPassword(loginPassword, p)
	if err != nil {
		return nil, err
	}

	// English: Authenticate to Kakao (HAR 200). Korean: Kakao에 인증합니다.
	authResp, err := kakaoAuthenticate(client, loginPage, loginID, encPassword)
	if err != nil {
		return nil, err
	}

	// English: Run SMS 2FA when the server asks for it (HAR 200 status -451, then 202/203). Korean: 서버가 요구하면 SMS 2단계 인증을 수행합니다.
	if authResp.status == -451 {
		if authResp.method != "sms" {
			return nil, fmt.Errorf("unsupported Kakao two-step verification method: %q", authResp.method)
		}
		smsToken, err := kakaoSendSMS(client, loginPage.finalURL, csrf)
		if err != nil {
			return nil, err
		}
		code := ""
		if promptSMS != nil {
			code, err = promptSMS()
		} else {
			code = strings.TrimSpace(os.Getenv("KAKAO_SMS_CODE"))
		}
		if err != nil {
			return nil, fmt.Errorf("read SMS code: %w", err)
		}
		if strings.TrimSpace(code) == "" {
			return nil, fmt.Errorf("SMS 2FA required but no code provided; set KAKAO_SMS_CODE or pass promptSMS")
		}
		if err := kakaoVerifySMS(client, loginPage.finalURL, csrf, smsToken, strings.TrimSpace(code)); err != nil {
			return nil, err
		}
	}
	nextContinue := authResp.continueURL
	if nextContinue == "" {
		nextContinue = continueURL
	}
	oauthHTML, oauthURL, err := fetchMelonOAuth(client, nextContinue, loginPage.finalURL)
	if err != nil {
		return nil, err
	}
	accessToken, refreshToken, pocID, redirectURL, err := parseOAuthForm(oauthHTML)
	if err != nil {
		return nil, err
	}
	session, err := melonLoginProcs(client, oauthURL, pocID, redirectURL, accessToken, refreshToken)
	if err != nil {
		return nil, err
	}
	return session, nil
}

func warmTicketHome(client *http.Client) error {
	req, err := http.NewRequest(http.MethodGet, melonTicketHomeURL, nil)
	if err != nil {
		return fmt.Errorf("create ticket home request: %w", err)
	}
	req.Header.Set("User-Agent", loginUserAgent)
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("warm ticket home: %w", err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("ticket home request failed: %s", resp.Status)
	}
	return nil
}

func openMelonLoginPage(client *http.Client) (string, error) {
	req, err := http.NewRequest(http.MethodGet, melonLoginPageURL, nil)
	if err != nil {
		return "", fmt.Errorf("create melon login request: %w", err)
	}
	req.Header.Set("User-Agent", loginUserAgent)
	req.Header.Set("Referer", "https://ticket.melon.com/")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/jxl,image/avif,image/webp,image/apng,*/*;q=0.8")
	req.Header.Set("Accept-Language", "ko-KR,ko;q=0.9,en-US;q=0.8,en;q=0.7")
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("open melon login page: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("read melon login page: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("melon login page request failed: %s", resp.Status)
	}
	if err := seedTiaraProbeCookies(client, resp.Request.URL.String()); err != nil {
		return "", err
	}
	return parseMelonAuthorizeURL(string(body))
}

func parseMelonAuthorizeURL(pageHTML string) (string, error) {
	pattern := regexp.MustCompile(regexp.QuoteMeta(kakaoAuthorizeURL) + `\?[^"'<>\s]+`)
	for _, match := range pattern.FindAllString(pageHTML, -1) {
		u, err := url.Parse(html.UnescapeString(match))
		if err != nil {
			continue
		}
		q := u.Query()
		if q.Get("state") != "" && q.Get("client_id") != "" && q.Get("redirect_uri") == melonOAuthURL && q.Get("response_type") == "code" {
			return u.String(), nil
		}
	}
	return "", fmt.Errorf("Melon login page has no valid Kakao authorize URL; server-generated state is required")
}

func ensurePCID(client *http.Client) error {
	jar := client.Jar
	if jar == nil {
		return fmt.Errorf("login client has no cookie jar")
	}
	ticketURL, err := url.Parse("https://ticket.melon.com/")
	if err != nil {
		return err
	}
	for _, cookie := range jar.Cookies(ticketURL) {
		if cookie.Name == "PCID" && strings.TrimSpace(cookie.Value) != "" {
			return nil
		}
	}
	pcid := newPCID(time.Now())
	jar.SetCookies(ticketURL, []*http.Cookie{{
		Name:   "PCID",
		Value:  pcid,
		Domain: "melon.com",
		Path:   "/",
	}})
	alsoURL, _ := url.Parse("https://accounts.melon.com/")
	jar.SetCookies(alsoURL, []*http.Cookie{{
		Name:   "PCID",
		Value:  pcid,
		Domain: "melon.com",
		Path:   "/",
	}})
	return nil
}

// English: HAR PCID is 23 digits (10-digit Unix seconds + 13 digits). Korean: HAR PCID는 23자리(Unix초 10자리 + 13자리)입니다.
func newPCID(now time.Time) string {
	sec := now.Unix()
	ms := now.Nanosecond() / int(time.Millisecond)
	randPart, _ := rand.Int(rand.Reader, big.NewInt(10000000000))
	return fmt.Sprintf("%d%03d%010d", sec, ms, randPart.Int64())
}

type kakaoLoginPage struct {
	csrf        string
	p           string
	loginURL    string
	continueURL string
	finalURL    string
	locale      string
	loadedAt    time.Time
}

var nextDataPattern = regexp.MustCompile(`(?s)<script id="__NEXT_DATA__" type="application/json">(.*?)</script>`)

// English: randomJitter returns a uniform [0, max) jitter from crypto/rand. Korean: crypto/rand로 균일 난수를 만듭니다.
func randomJitter(max int) int {
	if max <= 0 {
		return 0
	}
	n, err := rand.Int(rand.Reader, big.NewInt(int64(max)))
	if err != nil {
		return max / 2
	}
	return int(n.Int64())
}

// English: Complete both API warmups and keep their rotating cookies (HAR 193/197). Korean: 두 API 사전 요청을 완료하고 갱신되는 쿠키를 유지합니다.
func warmKakaoBanner(client *http.Client, loginPageURL, csrf, continueURL string) error {
	raw, err := postKakaoJSON(client, kakaoBannerURL, loginPageURL, "banner", map[string]any{"_csrf": csrf, "continue": continueURL})
	if err != nil {
		return err
	}
	return checkKakaoStatus(raw, "banner", false)
}

func warmKakaoPasskey(client *http.Client, loginPageURL, csrf string) error {
	raw, err := postKakaoJSON(client, kakaoPasskeyURL, loginPageURL, "passkey options", map[string]any{"_csrf": csrf, "username": "", "userVerification": "required"})
	if err != nil {
		return err
	}
	return checkKakaoStatus(raw, "passkey options", false)
}

// English: Tiara sets __T_ (one trailing underscore) and Secure __T_SECURE before API calls. Korean: Tiara처럼 API 호출 전에 __T_와 Secure 속성의 __T_SECURE를 설정합니다.
func seedTiaraProbeCookies(client *http.Client, loginPageURL string) error {
	if client.Jar == nil {
		return fmt.Errorf("login client has no cookie jar")
	}
	u, err := url.Parse(loginPageURL)
	if err != nil {
		return fmt.Errorf("parse Tiara page URL: %w", err)
	}
	// English: Tiara omits Path, so Kakao /login uses / while Melon /login/login.htm uses /login. Korean: Tiara처럼 Path를 생략하면 카카오는 /, 멜론은 /login 범위를 사용합니다.
	client.Jar.SetCookies(u, []*http.Cookie{
		{Name: "__T_", Value: "1"},
		{Name: "__T_SECURE", Value: "1", Secure: true, SameSite: http.SameSiteNoneMode},
	})
	return nil
}

func fetchKakaoLoginPage(client *http.Client, authorizeURL string) (*kakaoLoginPage, error) {
	req, err := http.NewRequest(http.MethodGet, authorizeURL, nil)
	if err != nil {
		return nil, fmt.Errorf("create kakao authorize request: %w", err)
	}
	req.Header.Set("User-Agent", loginUserAgent)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/jxl,image/avif,image/webp,image/apng,*/*;q=0.8")
	req.Header.Set("Accept-Language", "ko-KR,ko;q=0.9,en-US;q=0.8,en;q=0.7")
	req.Header.Set("Referer", "https://accounts.melon.com/")
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("kakao authorize: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read kakao login page: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("kakao authorize failed: %s", resp.Status)
	}
	page, err := parseNextData(string(body))
	if err != nil {
		return nil, err
	}
	finalURL := authorizeURL
	if resp.Request != nil && resp.Request.URL != nil {
		finalURL = resp.Request.URL.String()
	}
	page.finalURL = finalURL
	page.loadedAt = time.Now()
	return page, nil
}

// English: __NEXT_DATA__ carries _csrf, the password passphrase p, loginUrl and continueUrl. Korean: __NEXT_DATA__에 _csrf, 암호화 passphrase p, loginUrl, continueUrl이 들어 있습니다.
func parseNextData(html string) (*kakaoLoginPage, error) {
	m := nextDataPattern.FindStringSubmatch(html)
	if m == nil || len(m) < 2 {
		return nil, fmt.Errorf("Kakao login page has no __NEXT_DATA__")
	}
	var data struct {
		Props struct {
			PageProps struct {
				PageContext struct {
					CommonContext struct {
						CSRF   string `json:"_csrf"`
						P      string `json:"p"`
						Locale string `json:"locale"`
					} `json:"commonContext"`
					Context struct {
						LoginURL    string `json:"loginUrl"`
						ContinueURL string `json:"continueUrl"`
					} `json:"context"`
				} `json:"pageContext"`
			} `json:"pageProps"`
		} `json:"props"`
	}
	if err := json.Unmarshal([]byte(m[1]), &data); err != nil {
		return nil, fmt.Errorf("decode __NEXT_DATA__: %w", err)
	}
	context := data.Props.PageProps.PageContext
	page := &kakaoLoginPage{csrf: context.CommonContext.CSRF, p: context.CommonContext.P,
		loginURL: context.Context.LoginURL, continueURL: context.Context.ContinueURL, locale: context.CommonContext.Locale}
	if page.csrf == "" || page.p == "" || page.loginURL == "" || page.continueURL == "" {
		return nil, fmt.Errorf("Kakao login page is missing _csrf, p, loginUrl or continueUrl")
	}
	if page.locale == "" {
		page.locale = "ko"
	}
	return page, nil
}

// encryptKakaoPassword mirrors CryptoJS AES (OpenSSL Salted, EvpKDF-MD5, AES-256-CBC, PKCS7).
// English: Verified against the HAR: the captured password decrypts to .env KAKAO_LOGIN_PWD with the p passphrase. Korean: p passphrase로 복호화하면 .env 비밀번호와 일치함을 HAR에서 확인했습니다.
func encryptKakaoPassword(plaintext, passphrase string) (string, error) {
	if passphrase == "" {
		return "", fmt.Errorf("Kakao password passphrase p is required")
	}
	salt := make([]byte, 8)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("generate AES salt: %w", err)
	}
	key, iv := evpBytesToKey([]byte(passphrase), salt, 32, 16)
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("create AES cipher: %w", err)
	}
	plain := []byte(plaintext)
	pad := aes.BlockSize - len(plain)%aes.BlockSize
	for i := 0; i < pad; i++ {
		plain = append(plain, byte(pad))
	}
	ciphertext := make([]byte, len(plain))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ciphertext, plain)
	raw := append([]byte("Salted__"), salt...)
	raw = append(raw, ciphertext...)
	return base64.StdEncoding.EncodeToString(raw), nil
}

func evpBytesToKey(passphrase, salt []byte, keyLen, ivLen int) (key, iv []byte) {
	var derived []byte
	var last []byte
	for len(derived) < keyLen+ivLen {
		hash := md5.New()
		_, _ = hash.Write(last)
		_, _ = hash.Write(passphrase)
		_, _ = hash.Write(salt)
		last = hash.Sum(nil)
		derived = append(derived, last...)
	}
	return derived[:keyLen], derived[keyLen : keyLen+ivLen]
}

type kakaoAuthResult struct {
	status      int
	continueURL string
	method      string
}

func kakaoAuthenticate(client *http.Client, page *kakaoLoginPage, loginID, encPassword string) (*kakaoAuthResult, error) {
	// English: HAR 200 has lang=ko and no captchaToken; a token exists only after a challenge is solved. Korean: HAR 200에는 lang=ko가 있고 captchaToken은 없으며, 챌린지를 해결해야만 토큰이 생깁니다.
	payload := map[string]any{
		"_csrf": page.csrf, "loginId": loginID, "password": encPassword,
		"staySignedIn": false, "saveSignedIn": false, "loginKey": loginID,
		"loginUrl": page.loginURL, "lang": page.locale,
		"security_context": syntheticSecurityContext(page.loadedAt, time.Now()), "k": true,
	}
	raw, err := postKakaoJSON(client, kakaoAuthenticateURL, page.finalURL, "authenticate", payload)
	if err != nil {
		return nil, err
	}
	var parsed struct {
		Status      *int   `json:"status"`
		ContinueURL string `json:"continueUrl"`
		Method      string `json:"method"`
	}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return nil, fmt.Errorf("decode authenticate response: %w", err)
	}
	if parsed.Status == nil {
		return nil, fmt.Errorf("Kakao authenticate response has no status")
	}
	switch *parsed.Status {
	case 0, -451:
		return &kakaoAuthResult{status: *parsed.Status, continueURL: parsed.ContinueURL, method: parsed.Method}, nil
	case -481:
		return nil, fmt.Errorf("%w (status -481)", ErrKakaoCaptchaRequired)
	default:
		return nil, fmt.Errorf("Kakao authenticate failed (status %d)", *parsed.Status)
	}
}

func kakaoSendSMS(client *http.Client, loginPageURL, csrf string) (string, error) {
	raw, err := postKakaoJSON(client, kakaoSendSMSURL, loginPageURL, "send SMS", map[string]any{"_csrf": csrf, "verifyMethod": "sms", "reissue": true})
	if err != nil {
		return "", err
	}
	if err := checkKakaoStatus(raw, "send SMS", false); err != nil {
		return "", err
	}
	var parsed struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return "", fmt.Errorf("decode SMS response: %w", err)
	}
	if parsed.Token == "" {
		return "", fmt.Errorf("Kakao send SMS returned no token")
	}
	return parsed.Token, nil
}

func kakaoVerifySMS(client *http.Client, loginPageURL, csrf, token, passcode string) error {
	raw, err := postKakaoJSON(client, kakaoVerifySMSURL, loginPageURL, "verify SMS", map[string]any{
		"_csrf": csrf, "verifyMethod": "sms", "token": token, "passcode": passcode, "isRememberBrowser": true,
	})
	if err != nil {
		return err
	}
	// English: HAR 203 succeeds with an empty HTTP 200 body; nonempty JSON must still indicate success. Korean: HAR 203의 빈 HTTP 200 응답은 허용하지만 JSON이 있으면 성공 상태를 검사합니다.
	return checkKakaoStatus(raw, "verify SMS", true)
}

func postKakaoJSON(client *http.Client, endpoint, referer, operation string, payload any) ([]byte, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("encode %s request: %w", operation, err)
	}
	req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("create %s request: %w", operation, err)
	}
	setKakaoAPIHeaders(req, referer)
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("Kakao %s: %w", operation, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("Kakao %s failed: HTTP %d", operation, resp.StatusCode)
	}
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read %s response: %w", operation, err)
	}
	return raw, nil
}

func checkKakaoStatus(raw []byte, operation string, allowEmpty bool) error {
	if allowEmpty && len(bytes.TrimSpace(raw)) == 0 {
		return nil
	}
	var result struct {
		Status *int `json:"status"`
	}
	if err := json.Unmarshal(raw, &result); err != nil {
		return fmt.Errorf("decode %s response: %w", operation, err)
	}
	if result.Status == nil {
		return fmt.Errorf("Kakao %s response has no status", operation)
	}
	if *result.Status != 0 {
		return fmt.Errorf("Kakao %s failed (status %d)", operation, *result.Status)
	}
	return nil
}

func fetchMelonOAuth(client *http.Client, continueURL, referer string) (string, string, error) {
	if strings.TrimSpace(continueURL) == "" {
		return "", "", fmt.Errorf("Kakao continue URL is required")
	}
	req, err := http.NewRequest(http.MethodGet, continueURL, nil)
	if err != nil {
		return "", "", fmt.Errorf("create oauth request: %w", err)
	}
	req.Header.Set("User-Agent", loginUserAgent)
	req.Header.Set("Referer", referer)
	req.Header.Set("Accept-Language", loginAcceptLanguage)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	resp, err := client.Do(req)
	if err != nil {
		return "", "", fmt.Errorf("melon oauth: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", "", fmt.Errorf("read melon oauth page: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", "", fmt.Errorf("melon oauth failed: %s", resp.Status)
	}
	finalURL := continueURL
	if resp.Request != nil && resp.Request.URL != nil {
		finalURL = resp.Request.URL.String()
	}
	final, parseErr := url.Parse(finalURL)
	expected, expectedErr := url.Parse(melonOAuthURL)
	if parseErr != nil || expectedErr != nil || final.Scheme != expected.Scheme || final.Host != expected.Host || final.Path != expected.Path {
		return "", "", fmt.Errorf("Kakao authorization did not reach the Melon OAuth callback")
	}
	return string(body), finalURL, nil
}

var hiddenInputPattern = regexp.MustCompile(`(?i)<input[^>]+name="([^"]+)"[^>]+value="([^"]*)"`)

func parseOAuthForm(pageHTML string) (accessToken, refreshToken, pocID, redirectURL string, err error) {
	values := map[string]string{}
	for _, match := range hiddenInputPattern.FindAllStringSubmatch(pageHTML, -1) {
		if len(match) == 3 {
			values[match[1]] = html.UnescapeString(match[2])
		}
	}
	// English: Some templates emit value before name; also accept that order. Korean: value가 name보다 먼저인 템플릿도 받습니다.
	altPattern := regexp.MustCompile(`(?i)<input[^>]+value="([^"]*)"[^>]+name="([^"]+)"`)
	for _, match := range altPattern.FindAllStringSubmatch(pageHTML, -1) {
		if len(match) == 3 {
			if _, ok := values[match[2]]; !ok {
				values[match[2]] = html.UnescapeString(match[1])
			}
		}
	}
	pocID = values["pocId"]
	if pocID == "" {
		pocID = "MP15"
	}
	redirectURL = values["redirectURL"]
	if redirectURL == "" {
		redirectURL = "https://ticket.melon.com/main/readingGate.htm"
	}
	accessToken = values["accessToken"]
	refreshToken = values["refreshToken"]
	if accessToken == "" || refreshToken == "" {
		return "", "", "", "", fmt.Errorf("melon oauth page has no accessToken or refreshToken")
	}
	return accessToken, refreshToken, pocID, redirectURL, nil
}

func melonLoginProcs(client *http.Client, oauthURL, pocID, redirectURL, accessToken, refreshToken string) (*Session, error) {
	form := url.Values{
		"pocId":        {pocID},
		"memberKey":    {""},
		"redirectURL":  {redirectURL},
		"accessToken":  {accessToken},
		"refreshToken": {refreshToken},
		"qrCode":       {""},
		"autoLoginYN":  {""},
		"userAgent":    {""},
	}
	req, err := http.NewRequest(http.MethodPost, melonLoginProcsURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("create loginProcs request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", loginUserAgent)
	req.Header.Set("Referer", oauthURL)
	req.Header.Set("Origin", "https://accounts.melon.com")
	req.Header.Set("Accept-Language", loginAcceptLanguage)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("melon loginProcs: %w", err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("melon loginProcs failed: %s", resp.Status)
	}
	session := &Session{}
	for _, cookie := range resp.Cookies() {
		switch cookie.Name {
		case "keyCookie":
			session.KeyCookie = cookie.Value
		case "MAC":
			session.MAC = cookie.Value
		case "MLCP":
			session.MLCP = cookie.Value
		case "MUS":
			session.MUS = cookie.Value
		}
	}
	// English: set cookies may also live only in the jar; fall back to it. Korean: jar에만 있는 경우도 확인합니다.
	if client.Jar != nil {
		for _, base := range []string{"https://accounts.melon.com/", "https://ticket.melon.com/"} {
			u, _ := url.Parse(base)
			for _, cookie := range client.Jar.Cookies(u) {
				switch cookie.Name {
				case "PCID":
					if session.PCID == "" {
						session.PCID = cookie.Value
					}
				case "keyCookie":
					if session.KeyCookie == "" {
						session.KeyCookie = cookie.Value
					}
				case "MAC":
					if session.MAC == "" {
						session.MAC = cookie.Value
					}
				case "MLCP":
					if session.MLCP == "" {
						session.MLCP = cookie.Value
					}
				case "MUS":
					if session.MUS == "" {
						session.MUS = cookie.Value
					}
				}
			}
		}
	}
	if session.PCID == "" {
		return nil, fmt.Errorf("melon login did not establish PCID")
	}
	if session.KeyCookie == "" || session.MAC == "" || session.MLCP == "" {
		return nil, fmt.Errorf("melon login did not establish keyCookie, MAC or MLCP")
	}
	return session, nil
}

// English: This synthetic compatibility trace is not browser telemetry and cannot guarantee CAPTCHA-free login. Korean: 이 합성 호환 궤적은 브라우저 수집값이 아니므로 CAPTCHA 없는 로그인을 보장하지 않습니다.
func syntheticSecurityContext(started, now time.Time) map[string]any {
	// English: Keep every event inside this page visit and at or before submission, never in the future. Korean: 모든 이벤트를 현재 페이지 방문 이후부터 전송 시각까지의 범위에 둡니다.
	elapsed := now.UnixMilli() - started.UnixMilli()
	if elapsed < 0 {
		elapsed = 0
	}
	count := int(min(elapsed/16, 120))
	if count < 4 {
		count = 4
	}
	points := make([]any, 0, count)
	base := now.UnixMilli() - min(elapsed, int64(count*20))
	x, y := 540, 870
	for i := 0; i < count; i++ {
		x = max(470, min(630, x+randomJitter(7)-3))
		y = max(830, min(940, y+randomJitter(5)-2))
		event := 1
		if i == count-3 {
			event = 2
		}
		if i == count-2 {
			event = 3
		}
		if i == count-1 {
			event = 4
		}
		// English: Kakao's collector encodes round(clientX/Y * 10000) as hexadecimal. Korean: 카카오 수집기처럼 좌표에 10000을 곱한 정수를 16진수로 표현합니다.
		points = append(points, map[string]any{
			"x": fmt.Sprintf("%x", x*10000), "y": fmt.Sprintf("%x", y*10000),
			"t": base + (now.UnixMilli()-base)*int64(i)/int64(count-1), "e": event,
		})
	}

	return map[string]any{
		"a": points,
		"b": map[string]any{
			"a":  "61726d",
			"b":  hex.EncodeToString([]byte("64")),
			"m":  "",
			"pv": hex.EncodeToString([]byte("27.2.1")),
			"fvl": []any{
				map[string]any{"br": hex.EncodeToString([]byte("Not-A.Brand")), "vr": hex.EncodeToString([]byte("99.0.0.0"))},
				map[string]any{"br": hex.EncodeToString([]byte("Google Chrome")), "vr": hex.EncodeToString([]byte("157.0.8103.51"))},
				map[string]any{"br": hex.EncodeToString([]byte("Chromium")), "vr": hex.EncodeToString([]byte("157.0.8103.51"))},
			},
			"mo": 0,
			"p":  hex.EncodeToString([]byte("macOS")),
		},
		"c": false,
		"d": []any{},
		"e": map[string]any{
			"a": "f00",
			"b": "870",
			"c": "4b0",
			"d": "7cf",
			"r": "64",
		},
	}
}
