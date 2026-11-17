package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/joho/godotenv"
	"github.com/velar-agent/melon-ticket-agent/melon"
)

func main() {
	env, err := godotenv.Read(".env")
	if err != nil {
		log.Fatalf("read .env: %v", err)
	}

	// English: Log in with .env account info by constructing Melon; the session stays inside the Melon object. Korean: .env 계정 정보로 Melon을 생성하며 로그인하고, 세션은 Melon 객체 내부에만 둡니다.
	loginID := strings.TrimSpace(env["KAKAO_LOGIN_ID"])
	loginPWD := strings.TrimSpace(env["KAKAO_LOGIN_PWD"])
	// English: Fail early when credentials are absent. Korean: 자격 증명이 없으면 여기서 먼저 종료합니다.
	if loginID == "" || loginPWD == "" {
		log.Fatal("KAKAO_LOGIN_ID and KAKAO_LOGIN_PWD are required in .env")
	}
	m, err := melon.New(loginID, loginPWD, readSMSCode)
	if err != nil {
		log.Fatalf("login: %v", err)
	}
	fmt.Println("Login session established")

	// English: Two Cities performance fixture: prodId=213865, perfDate=20270103, scheduleNo=100071. Korean: 뮤지컬 〈두 도시 이야기〉 공연 테스트 값입니다.
	// English: Keep perfDate and scheduleNo from the same round (daylist groupSch). Korean: daylist의 groupSch과 같은 회차로 perfDate와 scheduleNo를 맞춥니다.
	perfInfo := melon.PerfInfo{
		ProdID:           "213865",
		POCCode:          "SC0002",
		PerfTypeCode:     "GN0002",
		PerfDate:         "20270103",
		ScheduleNo:       "100071",
		SellTypeCode:     "ST0001",
		PerfMainName:     "뮤지컬 〈두 도시 이야기〉",
		ProdTypeCode:     "PT0001",
		FlplanTypeCode:   "DR0001",
		ScheduleTypeCode: "SG0001",
		SeatTypeCode:     "SE0001",
	}

	seatInfo := melon.SeatInfo{
		SeatID: env["SEAT_ID"],
	}

	reservations, err := m.Reservation(perfInfo, seatInfo)
	if len(reservations) > 0 {
		fmt.Println(string(reservations))
	}
	if err != nil {
		log.Fatal(err)
	}
}

// English: Read the 6-digit SMS code for Kakao 2FA from stdin. Korean: Kakao 2단계 인증용 SMS 코드 6자리를 표준 입력에서 읽습니다.
func readSMSCode() (string, error) {
	fmt.Print("Enter the 6-digit Kakao SMS verification code: ")
	reader := bufio.NewReader(os.Stdin)
	code, err := reader.ReadString('\n')
	if err != nil && code == "" {
		return "", err
	}
	code = strings.TrimSpace(code)
	if code == "" {
		return "", fmt.Errorf("empty SMS code")
	}
	return code, nil
}
