package melon

import "testing"

// English: New must not return a Melon when login fails. Korean: 로그인에 실패하면 New는 Melon을 반환하지 않아야 합니다.
func TestNewReturnsLoginError(t *testing.T) {
	m, err := New("", "pwd", func() (string, error) { return "", nil })
	if err == nil {
		t.Fatal("New with empty loginID returned nil error")
	}
	if m != nil {
		t.Fatalf("New returned non-nil Melon on login failure: %+v", m)
	}
}
