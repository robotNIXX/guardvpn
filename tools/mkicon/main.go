// Command mkicon renders the VPN Guard app icon as PNG files for iconutil
// (macOS .icns) and as a multi-size .ico (Windows).
//
//	go run ./tools/mkicon -iconset build/AppIcon.iconset -ico build/vpn-guard.ico
package main

import (
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"log"
	"math"
	"os"
	"path/filepath"
)

func main() {
	iconset := flag.String("iconset", "", "output .iconset directory")
	ico := flag.String("ico", "", "output .ico file")
	flag.Parse()
	if *iconset != "" {
		if err := os.MkdirAll(*iconset, 0o755); err != nil {
			log.Fatal(err)
		}
		for _, s := range []int{16, 32, 128, 256, 512} {
			write(filepath.Join(*iconset, fmt.Sprintf("icon_%dx%d.png", s, s)), render(s))
			write(filepath.Join(*iconset, fmt.Sprintf("icon_%dx%d@2x.png", s, s)), render(2*s))
		}
	}
	if *ico != "" {
		writeICO(*ico, []int{16, 24, 32, 48, 64, 128, 256})
	}
}

func write(path string, data []byte) {
	if err := os.WriteFile(path, data, 0o644); err != nil {
		log.Fatal(err)
	}
}

// render draws a rounded-square tile with a white shield.
func render(size int) []byte {
	img := image.NewNRGBA(image.Rect(0, 0, size, size))
	s := float64(size)
	top := color.NRGBA{0x2b, 0x7c, 0xf0, 0xff}
	bot := color.NRGBA{0x14, 0x4f, 0xb8, 0xff}
	const ss = 3
	for py := 0; py < size; py++ {
		for px := 0; px < size; px++ {
			var tile, shield int
			for sy := 0; sy < ss; sy++ {
				for sx := 0; sx < ss; sx++ {
					x := (float64(px) + (float64(sx)+0.5)/ss) / s
					y := (float64(py) + (float64(sy)+0.5)/ss) / s
					if inTile(x, y) {
						tile++
						if inShield(x, y) {
							shield++
						}
					}
				}
			}
			if tile == 0 {
				continue
			}
			t := float64(py) / s
			bg := color.NRGBA{
				uint8(float64(top.R)*(1-t) + float64(bot.R)*t),
				uint8(float64(top.G)*(1-t) + float64(bot.G)*t),
				uint8(float64(top.B)*(1-t) + float64(bot.B)*t), 0xff,
			}
			f := float64(shield) / float64(tile)
			c := color.NRGBA{
				uint8(float64(bg.R)*(1-f) + 255*f),
				uint8(float64(bg.G)*(1-f) + 255*f),
				uint8(float64(bg.B)*(1-f) + 255*f),
				uint8(255 * tile / (ss * ss)),
			}
			img.SetNRGBA(px, py, c)
		}
	}
	var buf bytes.Buffer
	_ = png.Encode(&buf, img)
	return buf.Bytes()
}

func inTile(x, y float64) bool {
	const m, r = 0.08, 0.2 // margin, corner radius
	if x < m || y < m || x > 1-m || y > 1-m {
		return false
	}
	cx := math.Max(m+r-x, math.Max(0, x-(1-m-r)))
	cy := math.Max(m+r-y, math.Max(0, y-(1-m-r)))
	return cx*cx+cy*cy <= r*r
}

func inShield(x, y float64) bool {
	u := (x - 0.5) / 0.26
	v := (y - 0.24) / 0.54
	if v < 0 || v > 1 || math.Abs(u) > 1 {
		return false
	}
	if v < 0.5 {
		return true
	}
	return math.Abs(u) <= math.Cos((v-0.5)/0.5*math.Pi/2)
}

// writeICO writes PNG-compressed entries (supported since Windows Vista).
func writeICO(path string, sizes []int) {
	var imgs [][]byte
	for _, s := range sizes {
		imgs = append(imgs, render(s))
	}
	var b bytes.Buffer
	binary.Write(&b, binary.LittleEndian, [3]uint16{0, 1, uint16(len(imgs))})
	offset := 6 + 16*len(imgs)
	for i, s := range sizes {
		dim := uint8(s)
		if s >= 256 {
			dim = 0
		}
		binary.Write(&b, binary.LittleEndian, struct {
			W, H, Colors, Reserved uint8
			Planes, BPP            uint16
			Size, Offset           uint32
		}{dim, dim, 0, 0, 1, 32, uint32(len(imgs[i])), uint32(offset)})
		offset += len(imgs[i])
	}
	for _, im := range imgs {
		b.Write(im)
	}
	write(path, b.Bytes())
}
