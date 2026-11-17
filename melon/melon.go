package melon

// English: Melon is a logged-in melon ticket client; the session stays internal and is never passed by callers. Korean: Melon은 로그인된 멜론 티켓 클라이언트이며, 세션은 내부에만 두고 호출자가 넘기지 않습니다.
type Melon struct {
	session *Session
}

// English: New logs in with loginID/loginPWD and returns a Melon holding the fresh session; promptSMS is called if Kakao requires SMS 2FA. Korean: New는 loginID/loginPWD로 로그인한 뒤 세션을 담은 Melon을 반환하며, Kakao SMS 2단계 인증이 필요하면 promptSMS를 호출합니다.
func New(loginID, loginPWD string, promptSMS func() (string, error)) (*Melon, error) {
	session, err := Login(loginID, loginPWD, promptSMS)
	if err != nil {
		return nil, err
	}
	return &Melon{session: session}, nil
}
