package main

import (
	"fmt"
	"log"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/wailsapp/wails/v3/pkg/application"
	"github.com/wailsapp/wails/v3/pkg/events"

	"github.com/robotNIXX/guardvpn/internal/ipc"
)

var stateLabels = map[string]string{
	"ALLOWED":        "разрешено",
	"BLOCKED":        "заблокировано",
	"CHECKING":       "проверка сети…",
	"INITIALIZING":   "запуск…",
	"UNKNOWN":        "сеть не подтверждена",
	"DISABLED":       "не контролируется",
	"NOT CONFIGURED": "не настроено для этой ОС",
}

func label(state string) string {
	if l, ok := stateLabels[state]; ok {
		return l
	}
	return strings.ToLower(state)
}

type agent struct {
	app    *application.App
	window *application.WebviewWindow
	tray   *application.SystemTray

	mu        sync.Mutex
	lastState string
	lastMenu  string
	poke      chan struct{}
}

func runApp(showOnStart, elevated bool) {
	a := &agent{poke: make(chan struct{}, 1)}
	api := &API{
		PickApp:  a.pickApp,
		OpenLogs: openLogs,
		Changed:  a.refreshSoon,
	}
	if elevateSupported {
		api.Elevate = func() error {
			if err := elevate(); err != nil {
				return err
			}
			go func() { time.Sleep(300 * time.Millisecond); a.app.Quit() }()
			return nil
		}
	}

	opts := application.Options{
		Name:        "VPN Guard",
		Description: "VPN Guard status and settings",
		Assets: application.AssetOptions{
			Handler:        api.Handler(),
			DisableLogging: true,
		},
		Mac: application.MacOptions{
			// Menu bar app: no Dock icon.
			ActivationPolicy: application.ActivationPolicyAccessory,
		},
	}
	if !elevated {
		opts.SingleInstance = &application.SingleInstanceOptions{
			UniqueID: "com.vpnguard.agent",
			OnSecondInstanceLaunch: func(application.SecondInstanceData) {
				a.showWindow()
			},
		}
	}
	a.app = application.New(opts)

	a.window = a.app.Window.NewWithOptions(application.WebviewWindowOptions{
		Name:      "settings",
		Title:     "VPN Guard",
		Width:     940,
		Height:    700,
		MinWidth:  760,
		MinHeight: 560,
		URL:       "/",
		Hidden:    !showOnStart && !elevated,
	})
	// Closing the window only hides it; the agent lives in the tray.
	a.window.RegisterHook(events.Common.WindowClosing, func(e *application.WindowEvent) {
		a.window.Hide()
		e.Cancel()
	})

	a.tray = a.app.SystemTray.New()
	a.tray.SetIcon(iconFor(""))
	a.tray.SetTooltip("VPN Guard")
	a.tray.SetMenu(a.buildMenu(nil, nil))
	if runtime.GOOS == "windows" {
		a.tray.OnClick(a.showWindow)
	}

	go a.pollLoop()

	if err := a.app.Run(); err != nil {
		log.Fatal(err)
	}
}

func (a *agent) showWindow() {
	a.window.Show()
	a.window.Focus()
}

func (a *agent) refreshSoon() {
	select {
	case a.poke <- struct{}{}:
	default:
	}
}

func (a *agent) pollLoop() {
	t := time.NewTicker(2 * time.Second)
	defer t.Stop()
	for {
		st, err := ipc.Call(ipc.CmdStatus, 3*time.Second)
		a.update(st, err)
		select {
		case <-t.C:
		case <-a.poke:
		}
	}
}

func (a *agent) update(st *ipc.Status, err error) {
	state, tooltip := "", "VPN Guard: служба недоступна"
	if err == nil {
		state = st.State
		tooltip = "VPN Guard: " + label(st.State)
		if st.Country != "" {
			tooltip += " · " + st.Country
		}
	}
	// Rebuild the menu only when its content changes.
	key := menuKey(st, err)
	a.mu.Lock()
	stateChanged := state != a.lastState
	menuChanged := key != a.lastMenu
	a.lastState, a.lastMenu = state, key
	a.mu.Unlock()

	if stateChanged {
		a.tray.SetIcon(iconFor(state))
	}
	a.tray.SetTooltip(tooltip)
	if menuChanged {
		a.tray.SetMenu(a.buildMenu(st, err))
	}
}

func menuKey(st *ipc.Status, err error) string {
	if err != nil {
		return "err:" + err.Error()
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%s|%s|%s|%s", st.State, st.Country, st.IPv4, st.ConfigError)
	for _, ap := range st.Apps {
		fmt.Fprintf(&b, "|%s=%s:%d", ap.Name, ap.State, len(ap.PIDs))
	}
	return b.String()
}

func (a *agent) buildMenu(st *ipc.Status, err error) *application.Menu {
	m := a.app.NewMenu()
	switch {
	case st == nil && err == nil:
		m.Add("VPN Guard: подключение…").SetEnabled(false)
	case err != nil:
		m.Add("Служба VPN Guard недоступна").SetEnabled(false)
	default:
		head := "Сеть: " + label(st.State)
		if st.Country != "" {
			head += " — " + st.Country
		}
		m.Add(head).SetEnabled(false)
		if st.IPv4 != "" {
			m.Add("IP: " + st.IPv4).SetEnabled(false)
		}
		if st.ConfigError != "" {
			m.Add("Ошибка конфигурации — приложения заблокированы").SetEnabled(false)
		}
		if len(st.Apps) > 0 {
			m.AddSeparator()
		}
		for _, ap := range st.Apps {
			mark := "•"
			switch ap.State {
			case "ALLOWED":
				mark = "✓"
			case "BLOCKED", "UNKNOWN", "CHECKING", "INITIALIZING":
				mark = "✕"
			}
			text := fmt.Sprintf("%s %s — %s", mark, ap.Name, label(ap.State))
			if len(ap.PIDs) > 0 {
				text += " (запущено)"
			}
			m.Add(text).SetEnabled(false)
		}
	}
	m.AddSeparator()
	m.Add("Открыть VPN Guard…").OnClick(func(*application.Context) { a.showWindow() })
	m.Add("Проверить сеть сейчас").OnClick(func(*application.Context) {
		go func() {
			_, _ = ipc.Call(ipc.CmdCheck, 20*time.Second)
			a.refreshSoon()
		}()
	})
	m.Add("Открыть журнал").OnClick(func(*application.Context) { _ = openLogs() })
	m.AddSeparator()
	m.Add("Выйти из VPN Guard").OnClick(func(*application.Context) { a.app.Quit() })
	return m
}

// pickApp shows a native dialog for choosing an application.
//
// On macOS an .app is a directory (package). No file-type filter is set:
// Wails' filter makes NSOpenPanel refuse bundles, so packages are allowed
// as a whole and the choice is validated by process.Inspect.
func (a *agent) pickApp() (string, error) {
	d := a.app.Dialog.OpenFile().
		SetTitle("Выберите приложение").
		SetButtonText("Выбрать").
		CanChooseFiles(true)
	if runtime.GOOS == "darwin" {
		d = d.SetDirectory("/Applications").
			CanChooseDirectories(true).
			TreatsFilePackagesAsDirectories(false)
	} else {
		d = d.CanChooseDirectories(false).AddFilter("Программы", "*.exe")
	}
	return d.PromptForSingleSelection()
}
