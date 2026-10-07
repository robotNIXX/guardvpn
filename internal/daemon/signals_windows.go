package daemon

// watchSignals is a no-op on Windows: use `vpn-guard reload` instead.
func watchSignals(func()) (stop func()) { return func() {} }
