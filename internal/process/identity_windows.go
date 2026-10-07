package process

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/robotNIXX/guardvpn/internal/config"
)

// windowsIdentity matches a process when any of these holds:
//  1. its executable lies inside the application's install directory
//     (or equals the configured exe when that directory is a shared root
//     such as C:\Program Files);
//  2. its VERSIONINFO OriginalFilename equals the target's and it carries a
//     valid Authenticode signature from the same publisher (a copy of the
//     signed exe placed elsewhere).
//
// A process merely named Target.exe matches neither rule.
type windowsIdentity struct {
	exePath    string // lower-cased, cleaned
	installDir string // lower-cased; "" when exe sits in a shared root
	origName   string // OriginalFilename (lower-cased)
	product    string
	publisher  string // expected signer display name

	mu    sync.Mutex
	cache map[string]bool // exe path -> rule 2 verdict
}

// NewIdentity builds the identity from config. The identity is always
// returned (usable for fail-closed enforcement); err reports problems that
// must keep the guard blocked.
func NewIdentity(app *config.WindowsApp) (Identity, error) {
	if app == nil {
		return nil, fmt.Errorf("no application.windows section")
	}
	id := &windowsIdentity{
		exePath:   normPath(app.Path),
		publisher: app.Publisher,
		cache:     map[string]bool{},
	}
	if id.exePath == "" {
		return id, errors.New("application path is empty")
	}
	dir := filepath.Dir(id.exePath)
	if depth(dir) >= 3 { // e.g. c:\program files\target
		id.installDir = dir
	}

	var problems []string
	if orig, product, err := versionStrings(app.Path); err != nil {
		problems = append(problems, fmt.Sprintf("read version info: %v", err))
	} else {
		id.origName, id.product = strings.ToLower(orig), product
	}
	signer, err := authenticodeSigner(app.Path)
	switch {
	case err != nil:
		if app.Publisher != "" {
			problems = append(problems, fmt.Sprintf("publisher configured but %v", err))
		}
	case app.Publisher != "" && !strings.EqualFold(signer, app.Publisher):
		problems = append(problems, fmt.Sprintf("exe is signed by %q, expected %q", signer, app.Publisher))
	default:
		id.publisher = signer
	}
	if len(problems) > 0 {
		return id, errors.New(strings.Join(problems, "; "))
	}
	return id, nil
}

func normPath(p string) string {
	if p == "" {
		return ""
	}
	p = strings.TrimPrefix(p, `\\?\`)
	if r, err := filepath.EvalSymlinks(p); err == nil {
		p = r
	}
	return strings.ToLower(filepath.Clean(p))
}

func depth(p string) int {
	return len(strings.FieldsFunc(p, func(r rune) bool { return r == '\\' || r == '/' }))
}

func (w *windowsIdentity) Describe() []Field {
	return []Field{
		{"Application", w.exePath},
		{"Install dir", w.installDir},
		{"Original name", w.origName},
		{"Product", w.product},
		{"Publisher", w.publisher},
	}
}

func (w *windowsIdentity) IsTarget(p Proc) bool {
	if p.Path == "" {
		return false
	}
	path := strings.ToLower(filepath.Clean(strings.TrimPrefix(p.Path, `\\?\`)))
	if path == w.exePath {
		return true
	}
	if w.installDir != "" && strings.HasPrefix(path, w.installDir+`\`) {
		return true
	}
	if w.origName == "" || w.publisher == "" {
		return false
	}
	if strings.HasPrefix(path, `c:\windows\`) {
		return false
	}

	w.mu.Lock()
	defer w.mu.Unlock()
	if v, ok := w.cache[path]; ok {
		return v
	}
	v := false
	if orig, _, err := versionStrings(p.Path); err == nil && strings.EqualFold(orig, w.origName) {
		if signer, err := authenticodeSigner(p.Path); err == nil && strings.EqualFold(signer, w.publisher) {
			v = true
		}
	}
	if len(w.cache) > 4096 {
		clear(w.cache)
	}
	w.cache[path] = v
	return v
}

// versionStrings reads OriginalFilename and ProductName from VERSIONINFO.
func versionStrings(path string) (orig, product string, err error) {
	size, err := windows.GetFileVersionInfoSize(path, nil)
	if err != nil {
		return "", "", err
	}
	buf := make([]byte, size)
	if err := windows.GetFileVersionInfo(path, 0, size, unsafe.Pointer(&buf[0])); err != nil {
		return "", "", err
	}
	var tp unsafe.Pointer
	var tl uint32
	if err := windows.VerQueryValue(unsafe.Pointer(&buf[0]), `\VarFileInfo\Translation`, unsafe.Pointer(&tp), &tl); err != nil || tl < 4 {
		return "", "", errors.New("no version translation table")
	}
	langs := unsafe.Slice((*uint16)(tp), tl/2)
	query := func(lang, cp uint16, name string) string {
		var vp unsafe.Pointer
		var vl uint32
		sub := fmt.Sprintf(`\StringFileInfo\%04x%04x\%s`, lang, cp, name)
		if err := windows.VerQueryValue(unsafe.Pointer(&buf[0]), sub, unsafe.Pointer(&vp), &vl); err != nil || vl == 0 {
			return ""
		}
		return windows.UTF16PtrToString((*uint16)(vp))
	}
	for i := 0; i+1 < len(langs); i += 2 {
		orig = query(langs[i], langs[i+1], "OriginalFilename")
		product = query(langs[i], langs[i+1], "ProductName")
		if orig != "" {
			return orig, product, nil
		}
	}
	return "", "", errors.New("OriginalFilename not set")
}

var (
	modcrypt32           = windows.NewLazySystemDLL("crypt32.dll")
	procCryptMsgGetParam = modcrypt32.NewProc("CryptMsgGetParam")
	procCryptMsgClose    = modcrypt32.NewProc("CryptMsgClose")
)

const cmsgSignerCertInfoParam = 7

// authenticodeSigner verifies the embedded Authenticode signature and
// returns the signer certificate's display name.
func authenticodeSigner(path string) (string, error) {
	p16, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return "", err
	}
	data := &windows.WinTrustData{
		Size:             uint32(unsafe.Sizeof(windows.WinTrustData{})),
		UIChoice:         windows.WTD_UI_NONE,
		RevocationChecks: windows.WTD_REVOKE_NONE,
		UnionChoice:      windows.WTD_CHOICE_FILE,
		StateAction:      windows.WTD_STATEACTION_VERIFY,
		FileOrCatalogOrBlobOrSgnrOrCert: unsafe.Pointer(&windows.WinTrustFileInfo{
			Size:     uint32(unsafe.Sizeof(windows.WinTrustFileInfo{})),
			FilePath: p16,
		}),
	}
	verr := windows.WinVerifyTrustEx(windows.InvalidHWND, &windows.WINTRUST_ACTION_GENERIC_VERIFY_V2, data)
	data.StateAction = windows.WTD_STATEACTION_CLOSE
	_ = windows.WinVerifyTrustEx(windows.InvalidHWND, &windows.WINTRUST_ACTION_GENERIC_VERIFY_V2, data)
	if verr != nil {
		return "", fmt.Errorf("signature not trusted: %w", verr)
	}

	var enc, ctype, ftype uint32
	var store, msg windows.Handle
	if err := windows.CryptQueryObject(windows.CERT_QUERY_OBJECT_FILE, unsafe.Pointer(p16),
		windows.CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED, windows.CERT_QUERY_FORMAT_FLAG_BINARY,
		0, &enc, &ctype, &ftype, &store, &msg, nil); err != nil {
		return "", fmt.Errorf("CryptQueryObject: %w", err)
	}
	defer windows.CertCloseStore(store, 0)
	defer procCryptMsgClose.Call(uintptr(msg))

	var size uint32
	if r, _, e := procCryptMsgGetParam.Call(uintptr(msg), cmsgSignerCertInfoParam, 0, 0, uintptr(unsafe.Pointer(&size))); r == 0 {
		return "", fmt.Errorf("CryptMsgGetParam: %v", e)
	}
	info := make([]byte, size)
	if r, _, e := procCryptMsgGetParam.Call(uintptr(msg), cmsgSignerCertInfoParam, 0,
		uintptr(unsafe.Pointer(&info[0])), uintptr(unsafe.Pointer(&size))); r == 0 {
		return "", fmt.Errorf("CryptMsgGetParam: %v", e)
	}
	cert, err := windows.CertFindCertificateInStore(store, enc, 0, windows.CERT_FIND_SUBJECT_CERT, unsafe.Pointer(&info[0]), nil)
	if err != nil {
		return "", fmt.Errorf("signer certificate: %w", err)
	}
	defer windows.CertFreeCertificateContext(cert)

	name := make([]uint16, 256)
	n := windows.CertGetNameString(cert, windows.CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, nil, &name[0], uint32(len(name)))
	if n <= 1 {
		return "", errors.New("signer has no display name")
	}
	return windows.UTF16ToString(name[:n]), nil
}
