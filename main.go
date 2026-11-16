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

	// English: Log in with .env account info and use the fresh session directly for Reservation(). Korean: .env 계정 정보로 먼저 로그인하고, Reservation()에 세션을 메모리로 바로 넘깁니다.
	var session *melon.Session
	if strings.TrimSpace(env["KAKAO_LOGIN_ID"]) != "" && strings.TrimSpace(env["KAKAO_LOGIN_PWD"]) != "" {
		var err error
		session, err = melon.Login(env["KAKAO_LOGIN_ID"], env["KAKAO_LOGIN_PWD"], readSMSCode)
		if err != nil {
			log.Fatalf("login: %v", err)
		}
		fmt.Println("Login session established")
	}

	// English: Rebecca performance fixture: prodId=213984, perfDate=20261231, scheduleNo=100036. Korean: 뮤지컬 레베카 공연 테스트 값입니다.
	// English: Keep perfDate and scheduleNo from the same round (daylist groupSch). Korean: daylist의 groupSch과 같은 회차로 perfDate와 scheduleNo를 맞춥니다.
	// perfInfo := melon.PerfInfo{
	// 	ProdID:           "213984",
	// 	POCCode:          "SC0002",
	// 	PerfTypeCode:     "GN0002",
	// 	PerfDate:         "20261231",
	// 	ScheduleNo:       "100036",
	// 	SellTypeCode:     "ST0001",
	// 	PerfMainName:     "뮤지컬 〈레베카〉",
	// 	ProdTypeCode:     "PT0001",
	// 	FlplanTypeCode:   "DR0001",
	// 	ScheduleTypeCode: "SG0001",
	// 	SeatTypeCode:     "SE0001",
	// }

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

	reservations, err := melon.Reservation(perfInfo, seatInfo, session)
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
