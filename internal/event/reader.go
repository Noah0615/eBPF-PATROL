// 커널 -> Go 프로그램
package event

import (
	"bytes"
	"encoding/binary"
	"errors"
	"strings"

	"github.com/cilium/ebpf/ringbuf"
)

// eBPF에서 읽은 원시 데이터를 ExecEvent 구조체로 변환하는 코드
type execEventRaw struct {
	Pid  uint32
	Tgid uint32
	Uid  uint32
	Comm [16]byte
	File [256]byte
}

// eBPF에서 읽은 원시 데이터를 ExecEvent 구조체로 변환하는 코드
func ReadExecEvent(rd *ringbuf.Reader) (ExecEvent, error) {
	record, err := rd.Read()
	if err != nil {
		return ExecEvent{}, err
	}

	var raw execEventRaw
	if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &raw); err != nil {
		return ExecEvent{}, err
	}

	return ExecEvent{
		Pid:  raw.Pid,
		Tgid: raw.Tgid,
		Uid:  raw.Uid,
		Comm: cString(raw.Comm[:]),
		File: cString(raw.File[:]),
	}, nil
}

// C 스타일의 null-terminated 문자열을 Go 문자열로 변환하는 함수
func cString(b []byte) string {
	idx := bytes.IndexByte(b, 0)
	if idx == -1 {
		idx = len(b)
	}
	return strings.TrimSpace(string(b[:idx]))
}

// Reader가 닫혔을 때 반환할 수 있는 오류
var ErrClosed = errors.New("reader closed")