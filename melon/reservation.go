package melon

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/joho/godotenv"
)

type PerfInfo struct {
	ProdID           string
	POCCode          string
	PerfTypeCode     string
	PerfDate         string
	ScheduleNo       string
	SellTypeCode     string
	SellCondNo       string
	PerfMainName     string
	ProdTypeCode     string
	FlplanTypeCode   string
	ScheduleTypeCode string
	SeatTypeCode     string
}

type SeatInfo struct {
	SeatID string
}

// English: Test-seam variables; tests override reservationBaseURL to point at httptest. Korean: 테스트용 변수이며 테스트는 httptest로 교체합니다.
var (
	reservationClient  = &http.Client{Timeout: 15 * time.Second}
	reservationBaseURL = "https://ticket.melon.com/tktapi/reservation/prodlimit.json"
)

// English: Reservation uses the Melon's in-memory login session; the four login cookies no longer come from .env. Korean: 예약은 Melon이 가진 메모리 세션을 사용하며, 네 로그인 쿠키는 .env에서 읽지 않습니다.
func (m *Melon) Reservation(perfInfo PerfInfo, seatInfo SeatInfo) (json.RawMessage, error) {
	if perfInfo.ProdID == "" || perfInfo.PerfDate == "" ||
		perfInfo.ScheduleNo == "" {
		return nil, fmt.Errorf("prodId, perfDate, and scheduleNo are required")
	}
	seatId := strings.TrimSpace(seatInfo.SeatID)
	if seatId == "" {
		return nil, fmt.Errorf("seatInfo.SeatID is required")
	}
	// English: Guard nil/unconstructed Melon so callers get an error instead of a panic. Korean: nil이거나 New로 만들지 않은 Melon은 패닉 대신 에러를 반환합니다.
	if m == nil || m.session == nil {
		return nil, fmt.Errorf("melon is not logged in; create it with melon.New")
	}
	session := m.session
	if strings.TrimSpace(session.PCID) == "" || strings.TrimSpace(session.KeyCookie) == "" ||
		strings.TrimSpace(session.MAC) == "" || strings.TrimSpace(session.MLCP) == "" {
		return nil, fmt.Errorf("session must contain PCID, keyCookie, MAC and MLCP")
	}

	env, err := godotenv.Read(".env")
	if err != nil {
		return nil, fmt.Errorf("read .env: %w", err)
	}
	// English: CHKCAPT may be empty; send it as-is without failing. Korean: CHKCAPT는 비어 있어도 실패시키지 않고 그대로 보냅니다.
	chkCapt := env["CHKCAPT"]
	callback := strings.TrimSpace(env["CALLBACK"])
	if callback == "" {
		return nil, fmt.Errorf("missing CALLBACK in .env")
	}

	form := url.Values{
		"prodId":           {perfInfo.ProdID},
		"pocCode":          {perfInfo.POCCode},
		"perfTypeCode":     {perfInfo.PerfTypeCode},
		"perfDate":         {perfInfo.PerfDate},
		"scheduleNo":       {perfInfo.ScheduleNo},
		"sellTypeCode":     {perfInfo.SellTypeCode},
		"sellCondNo":       {perfInfo.SellCondNo},
		"perfMainName":     {perfInfo.PerfMainName},
		"prodTypeCode":     {perfInfo.ProdTypeCode},
		"flplanTypeCode":   {perfInfo.FlplanTypeCode},
		"scheduleTypeCode": {perfInfo.ScheduleTypeCode},
		"seatTypeCode":     {perfInfo.SeatTypeCode},
		"jType":            {"I"},
		"rsrvStep":         {"SAT"},
		"zamEnabled":       {"0"},
		"trafficCtrlYn":    {"N"},
		"mapClickYn":       {"N"},
		"seatId":           {seatId},
		"chkcapt":          {chkCapt},
	}
	for _, key := range []string{
		"seatGradeNo", "seatGradeName", "blockId", "sntv", "blockTypeCode",
		"floorNo", "floorName", "areaNo", "areaName", "cardGroupId", "cardBpId",
		"cardMid", "zamKey", "netfunnel_key", "stvn_view_list", "basePriceDpYn",
		"bpDcPriceDpYn", "tid", "clipSeatId",
	} {
		form.Set(key, "")
	}

	endpoint := reservationBaseURL + "?v=1&callback=" + url.QueryEscape(callback)
	req, err := http.NewRequest(http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("create reservation request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")

	//HAR의 prodlimit 브라우저 헤더와 맞추지 않음
	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/156.0.0.0 Safari/537.36")

	// // English: Match the browser HAR headers for prodlimit (stepSeat.htm). Korean: HAR의 prodlimit 브라우저 헤더와 맞춥니다.
	// req.Header.Set("Accept", "text/javascript, application/javascript, application/ecmascript, application/x-ecmascript, */*; q=0.01")
	// req.Header.Set("Accept-Language", "ko-KR,ko;q=0.9,en-US;q=0.8,en;q=0.7")
	// req.Header.Set("Origin", "https://ticket.melon.com")
	// req.Header.Set("Referer", "https://ticket.melon.com/reservation/popup/stepSeat.htm")
	// req.Header.Set("X-Requested-With", "XMLHttpRequest")
	// req.Header.Set("Sec-Fetch-Dest", "empty")
	// req.Header.Set("Sec-Fetch-Mode", "cors")
	// req.Header.Set("Sec-Fetch-Site", "same-origin")
	// req.Header.Set("sec-ch-ua", `"Not-A.Brand";v="99", "Google Chrome";v="157", "Chromium";v="157"`)
	// req.Header.Set("sec-ch-ua-mobile", "?0")
	// req.Header.Set("sec-ch-ua-platform", `"macOS"`)
	// req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/157.0.0.0 Safari/537.36")

	// English: The four login cookies come from the in-memory session, not .env. Korean: 네 로그인 쿠키는 .env가 아니라 메모리 세션에서 가져옵니다.
	for _, cookie := range []*http.Cookie{
		{Name: "PCID", Value: session.PCID},
		{Name: "keyCookie", Value: session.KeyCookie},
		{Name: "MAC", Value: session.MAC},
		{Name: "MLCP", Value: session.MLCP},
	} {
		if err := cookie.Valid(); err != nil {
			return nil, fmt.Errorf("invalid %s cookie: %w", cookie.Name, err)
		}
		req.AddCookie(cookie)
	}

	resp, err := reservationClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("send reservation request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("reservation request failed: %s", resp.Status)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read reservation response: %w", err)
	}
	body = bytes.TrimSpace(body)
	body = bytes.TrimSpace(bytes.TrimPrefix(body, []byte("/**/")))

	if !json.Valid(body) {
		body = bytes.TrimSpace(bytes.TrimSuffix(body, []byte(";")))
		prefix := []byte(callback + "(")
		if !bytes.HasPrefix(body, prefix) || !bytes.HasSuffix(body, []byte(")")) {
			return nil, fmt.Errorf("unexpected reservation response format")
		}
		body = bytes.TrimSpace(body[len(prefix) : len(body)-1])
	}

	var status struct {
		Code    string `json:"code"`
		Result  string `json:"result"`
		Message string `json:"message"`
	}
	if err := json.Unmarshal(body, &status); err != nil {
		return nil, fmt.Errorf("decode reservation response: %w", err)
	}
	reservations := json.RawMessage(body)
	// English: Some failures (e.g. T9220 login expired) use code instead of result. Korean: 로그인 만료 같은 실패는 result가 아니라 code를 씁니다.
	failureCode := status.Result
	if failureCode == "" {
		failureCode = status.Code
	}
	if failureCode != "0000" {
		return reservations, fmt.Errorf("reservation failed (%s): %s", failureCode, status.Message)
	}
	return reservations, nil
}
