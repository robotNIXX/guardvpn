// Command vpn-guard-agent is the per-user tray application of VPN Guard:
// it shows the daemon state and edits the settings. It never enforces
// anything itself; the root daemon / LocalSystem service does.
package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
)

func main() {
	serve := flag.String("serve", "", "development: serve the UI over HTTP on this address instead of running the tray app")
	show := flag.Bool("show", false, "open the settings window on start")
	elevated := flag.Bool("elevated", false, "internal: started with administrator rights by the agent itself")
	flag.Parse()

	if *serve != "" {
		api := &API{OpenLogs: openLogs}
		fmt.Fprintf(os.Stderr, "serving VPN Guard UI on http://%s\n", *serve)
		log.Fatal(http.ListenAndServe(*serve, api.Handler()))
	}
	runApp(*show, *elevated)
}
