package process

/*
#cgo LDFLAGS: -framework CoreFoundation -framework Security
#include <stdlib.h>
#include <string.h>
#include <libproc.h>
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>

static int vg_pidpath(int pid, char *buf, int size) {
	return proc_pidpath(pid, buf, (uint32_t)size);
}

static void vg_cfstr(CFTypeRef v, char *out, int outlen) {
	out[0] = 0;
	if (v != NULL && CFGetTypeID(v) == CFStringGetTypeID()) {
		CFStringGetCString((CFStringRef)v, out, outlen, kCFStringEncodingUTF8);
	}
}

// Parses an Info.plist (XML or binary) and extracts identifier and executable.
static int vg_plist_info(const void *data, long len, char *bid, int bidlen, char *exe, int exelen, char *name, int namelen) {
	bid[0] = 0;
	exe[0] = 0;
	name[0] = 0;
	CFDataRef d = CFDataCreate(NULL, (const UInt8 *)data, (CFIndex)len);
	if (d == NULL) return -1;
	CFPropertyListRef pl = CFPropertyListCreateWithData(NULL, d, kCFPropertyListImmutable, NULL, NULL);
	CFRelease(d);
	if (pl == NULL) return -2;
	if (CFGetTypeID(pl) != CFDictionaryGetTypeID()) {
		CFRelease(pl);
		return -3;
	}
	vg_cfstr(CFDictionaryGetValue((CFDictionaryRef)pl, CFSTR("CFBundleIdentifier")), bid, bidlen);
	vg_cfstr(CFDictionaryGetValue((CFDictionaryRef)pl, CFSTR("CFBundleExecutable")), exe, exelen);
	vg_cfstr(CFDictionaryGetValue((CFDictionaryRef)pl, CFSTR("CFBundleDisplayName")), name, namelen);
	if (name[0] == 0) {
		vg_cfstr(CFDictionaryGetValue((CFDictionaryRef)pl, CFSTR("CFBundleName")), name, namelen);
	}
	CFRelease(pl);
	return 0;
}

// Reads the embedded code signature (without validating resources).
static int vg_signing(const char *path, char *team, int tlen, char *ident, int ilen) {
	team[0] = 0;
	ident[0] = 0;
	CFURLRef url = CFURLCreateFromFileSystemRepresentation(NULL, (const UInt8 *)path, (CFIndex)strlen(path), false);
	if (url == NULL) return -1;
	SecStaticCodeRef code = NULL;
	OSStatus st = SecStaticCodeCreateWithPath(url, kSecCSDefaultFlags, &code);
	CFRelease(url);
	if (st != errSecSuccess) return (int)st;
	CFDictionaryRef info = NULL;
	st = SecCodeCopySigningInformation(code, kSecCSSigningInformation, &info);
	if (st == errSecSuccess && info != NULL) {
		vg_cfstr(CFDictionaryGetValue(info, kSecCodeInfoTeamIdentifier), team, tlen);
		vg_cfstr(CFDictionaryGetValue(info, kSecCodeInfoIdentifier), ident, ilen);
		CFRelease(info);
	}
	CFRelease(code);
	return (int)st;
}
*/
import "C"

import (
	"fmt"
	"os"
	"unsafe"
)

const procPidPathMax = 4 * 1024 // PROC_PIDPATHINFO_MAXSIZE

func pidPath(pid int) string {
	buf := make([]byte, procPidPathMax)
	n := C.vg_pidpath(C.int(pid), (*C.char)(unsafe.Pointer(&buf[0])), C.int(len(buf)))
	if n <= 0 {
		return ""
	}
	return string(buf[:n])
}

// bundleInfo reads <bundle>/Contents/Info.plist.
func bundleInfo(bundle string) (id, exe string, err error) {
	id, exe, _, err = bundlePlist(bundle)
	return id, exe, err
}

func bundlePlist(bundle string) (id, exe, name string, err error) {
	data, err := os.ReadFile(bundle + "/Contents/Info.plist")
	if err != nil {
		return "", "", "", err
	}
	if len(data) == 0 {
		return "", "", "", fmt.Errorf("empty Info.plist")
	}
	bid := make([]byte, 512)
	ex := make([]byte, 512)
	nm := make([]byte, 512)
	rc := C.vg_plist_info(unsafe.Pointer(&data[0]), C.long(len(data)),
		(*C.char)(unsafe.Pointer(&bid[0])), C.int(len(bid)),
		(*C.char)(unsafe.Pointer(&ex[0])), C.int(len(ex)),
		(*C.char)(unsafe.Pointer(&nm[0])), C.int(len(nm)))
	if rc != 0 {
		return "", "", "", fmt.Errorf("parse Info.plist: code %d", int(rc))
	}
	return cstr(bid), cstr(ex), cstr(nm), nil
}

// signingInfo returns the Team ID and signing identifier of a bundle or binary.
func signingInfo(path string) (team, ident string, err error) {
	cp := C.CString(path)
	defer C.free(unsafe.Pointer(cp))
	t := make([]byte, 256)
	i := make([]byte, 512)
	rc := C.vg_signing(cp, (*C.char)(unsafe.Pointer(&t[0])), C.int(len(t)),
		(*C.char)(unsafe.Pointer(&i[0])), C.int(len(i)))
	if rc != 0 {
		return "", "", fmt.Errorf("code signature: OSStatus %d", int(rc))
	}
	return cstr(t), cstr(i), nil
}

func cstr(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}
