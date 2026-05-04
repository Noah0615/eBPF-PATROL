package event

import (
	"bytes"
	"encoding/binary"
	"errors"
	"strings"

	"github.com/cilium/ebpf/ringbuf"
)

type rawEvent struct {
	Type      uint32
	Pid       uint32
	Tgid      uint32
	Ppid      uint32
	Uid       uint32
	Gid       uint32
	CgroupID  uint64
	Timestamp uint64
	Comm      [16]byte
	Arg1      [128]byte
	Arg2      [128]byte
	Flags     uint32
}

func ReadEvent(rd *ringbuf.Reader) (*Event, error) {
	record, err := rd.Read()
	if err != nil {
		if errors.Is(err, ringbuf.ErrClosed) {
			return nil, err
		}
		return nil, err
	}

	var raw rawEvent
	if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &raw); err != nil {
		return nil, err
	}

	return &Event{
		Type:      EventType(raw.Type),
		Pid:       raw.Pid,
		Tgid:      raw.Tgid,
		Ppid:      raw.Ppid,
		Uid:       raw.Uid,
		Gid:       raw.Gid,
		CgroupID:  raw.CgroupID,
		Timestamp: raw.Timestamp,
		Comm:      cString(raw.Comm[:]),
		Arg1:      cString(raw.Arg1[:]),
		Arg2:      cString(raw.Arg2[:]),
		Flags:     raw.Flags,
	}, nil
}

func cString(b []byte) string {
	idx := bytes.IndexByte(b, 0)
	if idx == -1 {
		idx = len(b)
	}
	return strings.TrimSpace(string(b[:idx]))
}