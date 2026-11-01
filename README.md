# melon-ticket-agent

멜론티켓의 `https://ticket.melon.com/tktapi/reservation/prodlimit.json` 요청을 실행하고 응답 JSON을 출력하는 Go 프로그램입니다. 공연·회차 정보와 좌석 정보를 받아, `.env`의 쿠키 및 인증 관련 값으로 요청을 구성합니다.

## 빠른 시작

[go.mod](go.mod) 기준으로 Go 1.26.5 이상이 필요합니다. 대상 요청의 쿠키, 캡챠 값, 콜백 이름과 좌석 ID도 준비하세요.

저장소 루트에서 의존성을 받고 설정 파일을 준비합니다. 기존 `.env`가 있으면 그대로 유지합니다.

```sh
go mod download
test -e .env || cp .env.example .env
```

`.env`의 필수값 일곱 개를 채우고, [main.go](main.go)의 `perfInfo`를 원하는 공연·회차에 맞게 수정한 뒤 실행합니다.

```sh
go run .
```

실행하면 설정값을 사용해 멜론티켓 서버로 요청을 전송합니다. 프로그램은 실행 디렉터리의 `.env`를 읽으므로 저장소 루트에서 실행하세요.

## 설정

설정 파일 형식은 [.env.example](.env.example)을 참고하세요. 아래 값은 모두 필요합니다.

| 환경 변수 | 넣을 값 |
|---|---|
| `PC_PCID`, `keyCookie`, `MAC`, `MLCP` | 대상 요청에 사용한 쿠키 네 개의 값 |
| `CHKCAPT` | URL 인코딩 전의 `chkcapt` 값 |
| `CALLBACK` | 요청 URL의 `callback` 값 |
| `SEAT_ID` | 요청 폼의 `seatId` 값 |

`.env`는 [.gitignore](.gitignore)에 따라 Git에서 제외됩니다.

공연 정보는 [main.go](main.go)의 `melon.PerfInfo`에 설정합니다. `ProdID`, `PerfDate`, `ScheduleNo`, `PerfMainName` 및 나머지 코드값을 대상 요청에 맞추세요. 현재는 뮤지컬 레베카의 공연·회차 값이 예제로 들어 있습니다.

좌석 ID는 `.env`에서 읽어 `melon.SeatInfo`에 담습니다. 호출 형식은 `melon.Reservation(perfInfo, seatInfo)`이며 구현은 [melon/reservation.go](melon/reservation.go)에 있습니다.

## 응답과 오류

- JSONP 응답의 `/**/callback(...)` 포장을 제거한 원본 JSON을 표준 출력에 씁니다. 응답의 필드와 값은 그대로 보존합니다.
- 코드에서는 `result`가 `"0000"`이면 성공으로 처리합니다. 다른 결과 코드가 오면 JSON을 먼저 출력하고, 오류 메시지를 표준 오류에 쓴 뒤 종료 코드 1로 종료합니다.
- 설정 파일, 네트워크, 응답 파싱 오류는 오류 메시지로 확인할 수 있습니다. 현재 구현은 HTTP 상태가 2xx가 아닌 경우 응답 본문을 출력하지 않습니다.

## 캡챠와 인증 오류 확인

cURL 폼 데이터에서 인코딩된 `chkcapt`를 복사했다면 URL 디코딩을 한 번 한 뒤 `.env`에 저장하세요. 예를 들어 `%2F`는 `/`로 바꿉니다. 요청을 보낼 때 다시 폼 인코딩하므로, 인코딩된 값을 저장하면 `%252F`처럼 이중 인코딩됩니다.

`CHKCAPT`는 만료될 가능성이 있으며 정확한 유효기간은 확인되지 않았습니다. 인증에 실패하면 현재 요청의 쿠키와 캡챠 값을 확인하고 필요하면 캡챠를 다시 완료해 갱신하세요. `인증예매를 완료해주세요.`라는 문구만으로 만료를 확정할 수는 없습니다.

| 오류 또는 증상 | 확인할 사항 |
|---|---|
| `read .env` | 실행 디렉터리에 `.env`가 있는지 확인하세요. |
| `missing ... in .env` | 오류에 표시된 설정값이 비어 있지 않은지 확인하세요. |
| `seatInfo.SeatID is required` | `.env`의 `SEAT_ID`를 확인하세요. |
| `unexpected reservation response format` | JSON 또는 설정한 콜백의 JSONP 대신 로그인 페이지 등 다른 형식이 반환되었는지 확인하세요. |

## 검증 범위

빌드와 정적 검사는 다음 명령으로 실행할 수 있습니다.

```sh
go build ./...
go vet ./...
```

작업 중 요청 구성, JSONP 처리, 원본 JSON 출력은 임시 공간의 모의 테스트로 확인했습니다. 현재 저장소에는 자동 테스트 파일이 포함되어 있지 않습니다.

실제 인증값을 사용한 멜론티켓 서버의 인증 성공이나 예매 성공은 검증하지 않았습니다. 구체적인 관찰 결과와 검증 범위는 [프로젝트 스킬](.agents/skills/debug-melon-reservation/SKILL.md)에 기록되어 있습니다.
