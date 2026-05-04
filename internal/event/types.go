package event

type ExecEvent struct {
	Pid  uint32 // Process ID
	Tgid uint32 // Thread Group ID (실제 프로세스 ID)
	Uid  uint32 // User ID
	Comm string // Command (프로세스 이름 (짧은 이름))
	File string // Executable file path (실행된 파일 경로)
}