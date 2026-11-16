package melon

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"time"
)

// English: Use the same HAR browser profile for headers, Tiara and security_context. Korean: 헤더, Tiara, security_context에 동일한 HAR 브라우저 프로필을 사용합니다.
var kakaoBrowserVersions = []map[string]string{
	{"brand": "Not-A.Brand", "version": "99.0.0.0"},
	{"brand": "Google Chrome", "version": "157.0.8103.51"},
	{"brand": "Chromium", "version": "157.0.8103.51"},
}

func setKakaoAPIHeaders(req *http.Request, referer string) {
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Accept-Language", loginAcceptLanguage)
	req.Header.Set("User-Agent", loginUserAgent)
	req.Header.Set("Origin", "https://accounts.kakao.com")
	req.Header.Set("Referer", referer)
	req.Header.Set("Sec-Fetch-Dest", "empty")
	req.Header.Set("Sec-Fetch-Mode", "cors")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	req.Header.Set("Sec-CH-UA", `"Not-A.Brand";v="99", "Google Chrome";v="157", "Chromium";v="157"`)
	req.Header.Set("Sec-CH-UA-Mobile", "?0")
	req.Header.Set("Sec-CH-UA-Platform", `"macOS"`)
	req.Header.Set("Sec-CH-UA-Platform-Version", `"27.2.1"`)
	req.Header.Set("Sec-CH-UA-Full-Version-List", `"Not-A.Brand";v="99.0.0.0", "Google Chrome";v="157.0.8103.51", "Chromium";v="157.0.8103.51"`)
	req.Header.Set("Sec-CH-UA-Model", `""`)
	req.Header.Set("Sec-CH-UA-Form-Factors", `"Desktop"`)
}

// English: Tiara 1.2.7 creates random client IDs, but _T_ANO is an HttpOnly server cookie (HAR 192). Korean: Tiara 1.2.7은 임의 클라이언트 ID를 만들지만 _T_ANO는 서버가 발급하는 HttpOnly 쿠키입니다.
func warmKakaoTiara(client *http.Client, page *kakaoLoginPage) error {
	now := time.Now()
	tuid, err := newTiaraID(now, true)
	if err != nil {
		return err
	}
	uuid, err := newTiaraID(now, false)
	if err != nil {
		return err
	}
	isuid, err := newTiaraID(now, false)
	if err != nil {
		return err
	}
	data := map[string]any{
		"sdk": map[string]string{"type": "WEB", "version": "1.2.7"},
		"env": map[string]any{
			"screen": "3840X2160", "tz": "+9", "cke": "Y",
			"uadata": map[string]any{
				"fullVersionList": kakaoBrowserVersions, "mobile": false,
				"model": "", "platform": "macOS", "platformVersion": "27.2.1",
			},
		},
		// English: The captured pageview omits OAuth query parameters. Korean: 캡처된 페이지뷰처럼 OAuth 쿼리 매개변수를 제외합니다.
		"common": map[string]string{
			"svcdomain": "accounts.kakao.com", "deployment": "production",
			"url": "https://accounts.kakao.com/login/", "referrer": "https://accounts.melon.com/",
			"section": "login", "page": "page-login",
		},
		"etc": map[string]any{"client_info": map[string]any{
			"tuid": tuid, "tsid": tuid, "uuid": uuid, "suid": uuid, "isuid": isuid,
			"send_timestamp": now.UnixMilli(), "elapsed_time": float64(now.Sub(page.loadedAt)) / float64(time.Millisecond),
		}},
		"action": map[string]string{"type": "Pageview", "name": "page-login", "kind": ""},
	}
	body, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("encode Tiara pageview: %w", err)
	}
	u, err := url.Parse(kakaoTiaraURL)
	if err != nil {
		return fmt.Errorf("parse Tiara URL: %w", err)
	}
	q := u.Query()
	q.Set("d", string(body))
	u.RawQuery = q.Encode()
	req, err := http.NewRequest(http.MethodGet, u.String(), nil)
	if err != nil {
		return fmt.Errorf("create Tiara request: %w", err)
	}
	req.Header.Set("User-Agent", loginUserAgent)
	req.Header.Set("Accept-Language", loginAcceptLanguage)
	req.Header.Set("Accept", "image/avif,image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8")
	req.Header.Set("Referer", "https://accounts.kakao.com/")
	req.Header.Set("Sec-Fetch-Dest", "image")
	req.Header.Set("Sec-Fetch-Mode", "no-cors")
	req.Header.Set("Sec-Fetch-Site", "same-site")
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("Kakao Tiara: %w", err)
	}
	defer resp.Body.Close()
	if _, err := io.Copy(io.Discard, resp.Body); err != nil {
		return fmt.Errorf("read Tiara response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("Kakao Tiara failed: HTTP %d", resp.StatusCode)
	}
	loginURL, err := url.Parse(page.finalURL)
	if err != nil {
		return fmt.Errorf("parse Kakao login URL: %w", err)
	}
	if client.Jar != nil {
		for _, cookie := range client.Jar.Cookies(loginURL) {
			if cookie.Name == "_T_ANO" && cookie.Value != "" {
				return nil
			}
		}
	}
	return fmt.Errorf("Kakao Tiara did not establish _T_ANO for the login page")
}

func newTiaraID(now time.Time, withTime bool) (string, error) {
	const alphabet = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	prefix := make([]byte, 12)
	for i := range prefix {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(alphabet))))
		if err != nil {
			return "", fmt.Errorf("generate Tiara ID: %w", err)
		}
		prefix[i] = alphabet[n.Int64()]
	}
	stamp := now.In(time.FixedZone("KST", 9*60*60))
	suffix := stamp.Format("060102150405.000")
	if withTime {
		suffix = suffix[:12] + suffix[13:]
	} else {
		n, err := rand.Int(rand.Reader, big.NewInt(1000000000))
		if err != nil {
			return "", fmt.Errorf("generate Tiara ID suffix: %w", err)
		}
		suffix = stamp.Format("060102") + fmt.Sprintf("%09d", n.Int64())
	}
	return "w-" + string(prefix) + "_" + suffix, nil
}
