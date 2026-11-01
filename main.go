package main

import (
	"fmt"
	"log"

	"github.com/joho/godotenv"
	"github.com/velar-agent/melon-ticket-agent/melon"
)

func main() {
	env, err := godotenv.Read(".env")
	if err != nil {
		log.Fatalf("read .env: %v", err)
	}

	// 뮤지컬 레베카 테스트, prodId=213984, ScheduleNo=100022
	perfInfo := melon.PerfInfo{
		ProdID:           "213984",
		POCCode:          "SC0002",
		PerfTypeCode:     "GN0002",
		PerfDate:         "20261128",
		ScheduleNo:       "100022",
		SellTypeCode:     "ST0001",
		PerfMainName:     "뮤지컬 〈레베카〉",
		ProdTypeCode:     "PT0001",
		FlplanTypeCode:   "DR0001",
		ScheduleTypeCode: "SG0001",
		SeatTypeCode:     "SE0001",
	}
	seatInfo := melon.SeatInfo{
		SeatID: env["SEAT_ID"],
	}

	reservations, err := melon.Reservation(perfInfo, seatInfo)
	if len(reservations) > 0 {
		fmt.Println(string(reservations))
	}
	if err != nil {
		log.Fatal(err)
	}
}
