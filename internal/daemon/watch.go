package daemon

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/fsnotify/fsnotify"
)

const (
	configPoll     = 5 * time.Second
	configDebounce = 250 * time.Millisecond
)

// watchConfig triggers a reload when the config file changes. fsnotify on
// the config directory (editors and atomic saves replace the file) gives
// an immediate reload; a slow stat poll is the fallback.
func (d *Daemon) watchConfig(ctx context.Context) {
	dir, name := filepath.Dir(d.configPath), filepath.Base(d.configPath)

	var events <-chan fsnotify.Event
	if w, err := fsnotify.NewWatcher(); err != nil {
		d.log.Warn("config watcher unavailable, polling only", "err", err)
	} else if err := w.Add(dir); err != nil {
		d.log.Warn("config watcher unavailable, polling only", "dir", dir, "err", err)
		w.Close()
	} else {
		defer w.Close()
		events = w.Events
		go func() {
			for err := range w.Errors {
				d.log.Warn("config watcher error", "err", err)
			}
		}()
	}

	stopSignals := watchSignals(func() { d.requestReload("SIGHUP") })
	defer stopSignals()

	poll := time.NewTicker(configPoll)
	defer poll.Stop()
	stamp := fileStamp(d.configPath)
	var debounce <-chan time.Time

	for {
		select {
		case <-ctx.Done():
			return
		case ev, ok := <-events:
			if !ok {
				events = nil
				continue
			}
			if filepath.Base(ev.Name) == name {
				debounce = time.After(configDebounce)
			}
		case <-debounce:
			debounce = nil
			stamp = fileStamp(d.configPath)
			d.requestReload("config file changed")
		case <-poll.C:
			if s := fileStamp(d.configPath); s != stamp {
				stamp = s
				d.requestReload("config file changed")
			}
		}
	}
}

func fileStamp(path string) string {
	st, err := os.Stat(path)
	if err != nil {
		return "error:" + err.Error()
	}
	return fmt.Sprintf("%d/%d", st.ModTime().UnixNano(), st.Size())
}
