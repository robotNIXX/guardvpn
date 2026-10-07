package process

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Inspect reads the identity of an .exe.
func Inspect(path string) (AppInfo, error) {
	path = filepath.Clean(path)
	if !strings.EqualFold(filepath.Ext(path), ".exe") {
		return AppInfo{}, fmt.Errorf("%s is not an .exe", path)
	}
	if st, err := os.Stat(path); err != nil {
		return AppInfo{}, err
	} else if st.IsDir() {
		return AppInfo{}, fmt.Errorf("%s is a directory", path)
	}
	info := AppInfo{Path: path}
	if orig, product, err := versionStrings(path); err == nil {
		info.OriginalName, info.Product = orig, product
	}
	info.Name = info.Product
	if info.Name == "" {
		info.Name = strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
	}
	if signer, err := authenticodeSigner(path); err == nil {
		info.Publisher = signer
	} else {
		info.Warning = "у exe нет действительной подписи Authenticode: копии вне папки установки не будут распознаваться"
	}
	if depth(filepath.Dir(path)) < 3 {
		w := "exe лежит в общей папке: контролируется только этот файл"
		if info.Warning != "" {
			w = info.Warning + "; " + w
		}
		info.Warning = w
	}
	return info, nil
}
