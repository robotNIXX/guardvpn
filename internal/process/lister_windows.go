package process

import (
	"errors"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

type windowsLister struct {
	mu    sync.Mutex
	paths map[Key]string
}

// NewLister returns the Windows process lister (Toolhelp32 + QueryFullProcessImageName).
func NewLister() Lister { return &windowsLister{paths: map[Key]string{}} }

func (l *windowsLister) List() ([]Proc, error) {
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(snap)

	var pe windows.ProcessEntry32
	pe.Size = uint32(unsafe.Sizeof(pe))
	if err := windows.Process32First(snap, &pe); err != nil {
		return nil, err
	}

	l.mu.Lock()
	defer l.mu.Unlock()
	seen := map[Key]bool{}
	var out []Proc
	for {
		pid := int(pe.ProcessID)
		if pid > 4 { // 0 = Idle, 4 = System
			p := Proc{PID: pid, PPID: int(pe.ParentProcessID), Name: windows.UTF16ToString(pe.ExeFile[:])}
			if h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pe.ProcessID)); err == nil {
				if start, ok := creationTime(h); ok {
					p.Start = start
					k := p.Key()
					seen[k] = true
					if cached, ok := l.paths[k]; ok {
						p.Path = cached
					} else if p.Path = imagePath(h); p.Path != "" {
						l.paths[k] = p.Path
					}
				}
				windows.CloseHandle(h)
			}
			out = append(out, p)
		}
		if err := windows.Process32Next(snap, &pe); err != nil {
			if errors.Is(err, windows.ERROR_NO_MORE_FILES) {
				break
			}
			return nil, err
		}
	}
	for k := range l.paths {
		if !seen[k] {
			delete(l.paths, k)
		}
	}
	return out, nil
}

func creationTime(h windows.Handle) (int64, bool) {
	var c, e, k, u windows.Filetime
	if err := windows.GetProcessTimes(h, &c, &e, &k, &u); err != nil {
		return 0, false
	}
	return int64(c.HighDateTime)<<32 | int64(c.LowDateTime), true
}

func imagePath(h windows.Handle) string {
	buf := make([]uint16, windows.MAX_LONG_PATH)
	n := uint32(len(buf))
	if err := windows.QueryFullProcessImageName(h, 0, &buf[0], &n); err != nil {
		return ""
	}
	return windows.UTF16ToString(buf[:n])
}
