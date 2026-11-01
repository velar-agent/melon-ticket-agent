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

var reservationClient = &http.Client{Timeout: 15 * time.Second}

func Reservation(perfInfo PerfInfo, seatInfo SeatInfo) (json.RawMessage, error) {
	if perfInfo.ProdID == "" || perfInfo.PerfDate == "" ||
		perfInfo.ScheduleNo == "" {
		return nil, fmt.Errorf("prodId, perfDate, and scheduleNo are required")
	}
	seatId := strings.TrimSpace(seatInfo.SeatID)
	if seatId == "" {
		return nil, fmt.Errorf("seatInfo.SeatID is required")
	}

	env, err := godotenv.Read(".env")
	if err != nil {
		return nil, fmt.Errorf("read .env: %w", err)
	}
	chkCapt := env["CHKCAPT"]
	if strings.TrimSpace(chkCapt) == "" {
		return nil, fmt.Errorf("missing CHKCAPT in .env")
	}
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

	endpoint := "https://ticket.melon.com/tktapi/reservation/prodlimit.json?v=1&callback=" + url.QueryEscape(callback)
	req, err := http.NewRequest(http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("create reservation request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/156.0.0.0 Safari/537.36")

	for _, name := range []string{"PC_PCID", "keyCookie", "MAC", "MLCP"} {
		value := env[name]
		if strings.TrimSpace(value) == "" {
			return nil, fmt.Errorf("missing %s in .env", name)
		}
		cookie := &http.Cookie{Name: name, Value: value}
		if err := cookie.Valid(); err != nil {
			return nil, fmt.Errorf("invalid %s cookie: %w", name, err)
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
		Result  string `json:"result"`
		Message string `json:"message"`
	}
	if err := json.Unmarshal(body, &status); err != nil {
		return nil, fmt.Errorf("decode reservation response: %w", err)
	}
	reservations := json.RawMessage(body)
	if status.Result != "0000" {
		return reservations, fmt.Errorf("reservation failed (%s): %s", status.Result, status.Message)
	}
	return reservations, nil
}
