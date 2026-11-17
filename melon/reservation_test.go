package melon

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeEnv(t *testing.T, env map[string]string) {
	t.Helper()
	dir := t.TempDir()
	lines := make([]string, 0, len(env))
	for _, key := range []string{"CHKCAPT", "CALLBACK"} {
		if v, ok := env[key]; ok {
			lines = append(lines, key+"="+v)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte(strings.Join(lines, "\n")+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Chdir(dir)
}

func testSession() *Session {
	return &Session{
		PCID:      "17947670315983860514680",
		KeyCookie: "67227440",
		MAC:       "HPLnCPim659ydakPDhEP8IQVRz3283ipYFdvcyyVJtCbHyVKHKdtPawGpWLzNYYJHjyJxNE7PQNKGXu4LNOuPcEAJXjSrGs6F1CN8VmlIFM=",
		MLCP:      "NjcyMjc0NDAlM0IlMjNrYWthb18xOTIxMzAyMTE3NmEwdWZ3cmIyJTNCTiUzQjAlM0JleUpoYkdjaU9pSklVekkxTmlKOS5leUpwYzNNaU9pSmhZMk52ZFc1MGN5SXNJbk4xWWlJNkltMHRhbmQwSWl3aWFXRjBJam94TnprME56WTNNekl5TENKdFpXMWlaWEpMWlhraU9pSTJOekl5TnpRME1DSXNJbUYxZEc5TWIyZHBibGxPSWpvaVRpSjkubS1yNk4tQUFBVGp1S0ptQ1p6eE1yS213UEdZZW04alJzUGF3MmdES3hMYyUzQiUzQjIwMjYxMTE2MDMyODQyJTNCJUVDJTk4JUE0JUVDJTlEJUI0bHhwMDk4NmM0JTNCJTNCeGlvdGUlNDBuYXRlLmNvbSUzQiUzQg==",
	}
}

func testPerfInfo() PerfInfo {
	return PerfInfo{
		ProdID:           "213984",
		POCCode:          "SC0002",
		PerfTypeCode:     "GN0002",
		PerfDate:         "20261231",
		ScheduleNo:       "100036",
		SellTypeCode:     "ST0001",
		PerfMainName:     "뮤지컬 〈레베카〉",
		ProdTypeCode:     "PT0001",
		FlplanTypeCode:   "DR0001",
		ScheduleTypeCode: "SG0001",
		SeatTypeCode:     "SE0001",
	}
}

// English: Verify the in-memory session is sent as cookies, not .env. Korean: 메모리 세션이 쿠키로 전송되는지 확인합니다.
func TestReservationSendsSessionCookies(t *testing.T) {
	const callback = "jQuery360021354934215237897_1794767373460"
	writeEnv(t, map[string]string{
		"CHKCAPT":  "4fUB40qTeySfuXczimRCXdgqsQMMEWj6RXWPnKeCTgE2GfayjVAn6mYfVam/xgN9",
		"CALLBACK": callback,
	})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := fmt.Sprintf("/**/%s(%s)", callback, `{"result":"0000","encryptedSeatIds":"QhbmVZzSsEWSoO8JlYWrAlDTRX5Cgt/V86cqmlW5eqoJUWb2+onmanfrcI52e1Xqa0wSoEmdbn3zWKxgTQHGpQ==","interlockTid":"0","staticDomain":null,"httpsDomain":null,"httpDomain":null,"volumeTypeCode":null,"message":""}`)
		w.Header().Set("Content-Type", "application/javascript;charset=UTF-8")
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()

	oldBase := reservationBaseURL
	reservationBaseURL = srv.URL
	defer func() { reservationBaseURL = oldBase }()

	got, err := (&Melon{session: testSession()}).Reservation(testPerfInfo(), SeatInfo{SeatID: "21_56"})
	if err != nil {
		t.Fatalf("Reservation returned error: %v", err)
	}
	var decoded map[string]json.RawMessage
	if err := json.Unmarshal(got, &decoded); err != nil {
		t.Fatalf("decode result: %v", err)
	}
	if string(decoded["result"]) != `"0000"` {
		t.Fatalf("expected result 0000, got %s", string(got))
	}
}

// English: Verify the request carries PCID without matching HAR headers. Korean: HAR 헤더에 맞추지 않은 채 PCID만 담는지 확인합니다.
func TestReservationRequestCarriesPCIDWithoutHARHeaders(t *testing.T) {
	const pcid = "17947670315983860514680"
	const callback = "jQuery360021354934215237897_1794767373460"
	writeEnv(t, map[string]string{
		"CHKCAPT":  "4fUB40qTeySfuXczimRCXdgqsQMMEWj6RXWPnKeCTgE2GfayjVAn6mYfVam/xgN9",
		"CALLBACK": callback,
	})

	var captured *http.Request
	var capturedBody string
	var capturedForm url.Values
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := fmt.Sprintf("/**/%s(%s)", callback, `{"result":"0000","message":""}`)
		w.Header().Set("Content-Type", "application/javascript;charset=UTF-8")
		if err := r.ParseForm(); err == nil {
			capturedForm = r.Form
		}
		captured = r
		_ = capturedBody
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()

	oldBase := reservationBaseURL
	reservationBaseURL = srv.URL
	defer func() { reservationBaseURL = oldBase }()

	session := testSession()
	session.MLCP = "k"
	if _, err := (&Melon{session: session}).Reservation(testPerfInfo(), SeatInfo{SeatID: "21_56"}); err != nil {
		t.Fatalf("Reservation returned error: %v", err)
	}
	if captured == nil {
		t.Fatal("server never received a request")
	}
	if cookie, _ := captured.Cookie("PC_PCID"); cookie != nil {
		t.Fatalf("request must not send PC_PCID cookie, got %q", cookie.Value)
	}
	pcidCookie, _ := captured.Cookie("PCID")
	if pcidCookie == nil {
		t.Fatal("request missing PCID cookie; cookies were " + captured.Header.Get("Cookie"))
	}
	if pcidCookie.Value != pcid {
		t.Fatalf("PCID cookie = %q, want %q", pcidCookie.Value, pcid)
	}
	// English: prodlimit does not match HAR headers; only Content-Type and the 156 User-Agent are sent. Korean: HAR 헤더에 맞추지 않고 Content-Type와 156 User-Agent만 보냅니다.
	if got := captured.Header.Get("Referer"); got != "" {
		t.Fatalf("Referer = %q, want empty (HAR headers not matched)", got)
	}
	if got := captured.Header.Get("Origin"); got != "" {
		t.Fatalf("Origin = %q, want empty (HAR headers not matched)", got)
	}
	if got := captured.Header.Get("X-Requested-With"); got != "" {
		t.Fatalf("X-Requested-With = %q, want empty (HAR headers not matched)", got)
	}
	if captured.Header.Get("Accept") != "" {
		t.Fatalf("Accept = %q, want empty (HAR headers not matched)", captured.Header.Get("Accept"))
	}
	if !strings.Contains(captured.Header.Get("User-Agent"), "Chrome/156.0.0.0") {
		t.Fatalf("User-Agent = %q, want Chrome/156", captured.Header.Get("User-Agent"))
	}
	if capturedForm.Get("perfDate") != "20261231" || capturedForm.Get("scheduleNo") != "100036" || capturedForm.Get("seatId") != "21_56" {
		t.Fatalf("form perfDate/scheduleNo/seatId = %q/%q/%q", capturedForm.Get("perfDate"), capturedForm.Get("scheduleNo"), capturedForm.Get("seatId"))
	}
}

// English: Verify T9220 (code instead of result) surfaces as the failure code. Korean: result가 아닌 code를 쓰는 T9220 실패가 코드로 드러나는지 확인합니다.
func TestReservationReportsCodeFieldOnLoginExpired(t *testing.T) {
	const callback = "jQuery360024044865307238428_1793556552011"
	writeEnv(t, map[string]string{
		"CHKCAPT":  "WgL+lp8pcCxGzBOnI0PhU4/TdrgCRWrXG8qQHMtV+eDq2pdt6hUnNXZxFzLNYcDV",
		"CALLBACK": callback,
	})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript;charset=UTF-8")
		_, _ = w.Write([]byte(fmt.Sprintf("/**/%s(%s)", callback, `{"code":"T9220","staticDomain":null,"httpsDomain":null,"message":"로그인 시간이 만료되었습니다. 다시 로그인 해주세요.","httpDomain":null}`)))
	}))
	defer srv.Close()

	oldBase := reservationBaseURL
	reservationBaseURL = srv.URL
	defer func() { reservationBaseURL = oldBase }()

	session := testSession()
	session.MAC = "m"
	session.MLCP = "l"
	raw, err := (&Melon{session: session}).Reservation(testPerfInfo(), SeatInfo{SeatID: "21_56"})
	if err == nil {
		t.Fatal("expected T9220 error, got success")
	}
	if !strings.Contains(err.Error(), "T9220") {
		t.Fatalf("error = %q, want it to contain T9220", err.Error())
	}
	if !strings.Contains(err.Error(), "로그인 시간이 만료되었습니다") {
		t.Fatalf("error = %q, want login-expired message", err.Error())
	}
	if len(raw) == 0 {
		t.Fatal("raw body is empty; caller cannot inspect the JSON")
	}
}

// English: A nil or incomplete session must fail before any .env cookie lookup. Korean: 빈 세션은 .env 조회 전에 실패합니다.
func TestReservationRequiresSession(t *testing.T) {
	writeEnv(t, map[string]string{
		"CHKCAPT":  "x",
		"CALLBACK": "cb",
	})
	if _, err := (*Melon)(nil).Reservation(testPerfInfo(), SeatInfo{SeatID: "21_56"}); err == nil || !strings.Contains(err.Error(), "not logged in") {
		t.Fatalf("nil Melon err = %v, want not logged in", err)
	}
	if _, err := (&Melon{}).Reservation(testPerfInfo(), SeatInfo{SeatID: "21_56"}); err == nil || !strings.Contains(err.Error(), "not logged in") {
		t.Fatalf("nil session err = %v, want not logged in", err)
	}
	if _, err := (&Melon{session: &Session{PCID: "p"}}).Reservation(testPerfInfo(), SeatInfo{SeatID: "21_56"}); err == nil || !strings.Contains(err.Error(), "must contain") {
		t.Fatalf("incomplete session err = %v, want must contain", err)
	}
}

// English: Empty CHKCAPT (or missing CHKCAPT entry) must not fail; it is sent as empty. Korean: CHKCAPT가 비어 있어도 실패하지 않고 빈 값으로 전송합니다.
func TestReservationAllowsEmptyChkCapt(t *testing.T) {
	const callback = "jQuery360021354934215237897_1794767373460"
	writeEnv(t, map[string]string{
		"CALLBACK": callback,
		// English: CHKCAPT omitted on purpose to simulate absent value. Korean: CHKCAPT를 의도적으로 생략합니다.
	})
	var capturedForm url.Values
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err == nil {
			capturedForm = r.Form
		}
		body := fmt.Sprintf("/**/%s(%s)", callback, `{"result":"0000","message":""}`)
		w.Header().Set("Content-Type", "application/javascript;charset=UTF-8")
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()

	oldBase := reservationBaseURL
	reservationBaseURL = srv.URL
	defer func() { reservationBaseURL = oldBase }()

	if _, err := (&Melon{session: testSession()}).Reservation(testPerfInfo(), SeatInfo{SeatID: "21_56"}); err != nil {
		t.Fatalf("empty CHKCAPT should not fail: %v", err)
	}
	if got := capturedForm.Get("chkcapt"); got != "" {
		t.Fatalf("chkcapt = %q, want empty", got)
	}
}
