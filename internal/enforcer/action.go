package enforcer

import "os"

func Kill(pid uint32) error {
	process, err := os.FindProcess(int(pid))
	if err != nil {
		return err
	}
	return process.Kill()
}
