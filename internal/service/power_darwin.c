#include <CoreFoundation/CoreFoundation.h>
#include <IOKit/pwr_mgt/IOPMLib.h>
#include <IOKit/IOMessage.h>

extern void goPowerEvent(int);

static io_connect_t vg_root_port;

static void vg_power_cb(void *ref, io_service_t service, natural_t type, void *arg) {
	switch (type) {
	case kIOMessageCanSystemSleep:
		IOAllowPowerChange(vg_root_port, (long)arg);
		break;
	case kIOMessageSystemWillSleep:
		goPowerEvent(1);
		IOAllowPowerChange(vg_root_port, (long)arg);
		break;
	case kIOMessageSystemHasPoweredOn:
		goPowerEvent(2);
		break;
	}
}

// Registers for system power notifications and runs the current thread's
// run loop forever. Returns -1 if registration fails.
int vg_power_run(void) {
	IONotificationPortRef port = NULL;
	io_object_t notifier;
	vg_root_port = IORegisterForSystemPower(NULL, &port, vg_power_cb, &notifier);
	if (vg_root_port == 0) {
		return -1;
	}
	CFRunLoopAddSource(CFRunLoopGetCurrent(), IONotificationPortGetRunLoopSource(port), kCFRunLoopCommonModes);
	CFRunLoopRun();
	return 0;
}
