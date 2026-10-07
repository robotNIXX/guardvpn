package process

import "golang.org/x/sys/unix"

type darwinLister struct{}

// NewLister returns the macOS process lister (sysctl + proc_pidpath).
// The path is read on every scan and never cached: exec(2) changes it
// without changing the PID or start time.
func NewLister() Lister { return darwinLister{} }

func (darwinLister) List() ([]Proc, error) {
	kps, err := unix.SysctlKinfoProcSlice("kern.proc.all")
	if err != nil {
		return nil, err
	}
	out := make([]Proc, 0, len(kps))
	for i := range kps {
		kp := &kps[i]
		pid := int(kp.Proc.P_pid)
		if pid <= 0 {
			continue
		}
		out = append(out, Proc{
			PID:   pid,
			PPID:  int(kp.Eproc.Ppid),
			Start: startOf(kp),
			Name:  commName(kp.Proc.P_comm[:]),
			Path:  pidPath(pid),
		})
	}
	return out, nil
}

func startOf(kp *unix.KinfoProc) int64 {
	tv := kp.Proc.P_starttime
	return int64(tv.Sec)*1_000_000 + int64(tv.Usec)
}

func commName(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}

// currentStart returns the start time of pid, or ok=false if it is gone.
func currentStart(pid int) (int64, bool) {
	kp, err := unix.SysctlKinfoProc("kern.proc.pid", pid)
	if err != nil || kp == nil || int(kp.Proc.P_pid) != pid {
		return 0, false
	}
	if kp.Proc.P_stat == 5 { // SZOMB: exited, waiting to be reaped
		return 0, false
	}
	return startOf(kp), true
}
