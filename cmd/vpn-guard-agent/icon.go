package main

import (
	"bytes"
	"image"
	"image/color"
	"image/png"
	"math"
)

// Tray icon colours per daemon state.
var stateColors = map[string]color.NRGBA{
	"ALLOWED":      {0x1f, 0xa3, 0x5b, 0xff},
	"BLOCKED":      {0xd9, 0x36, 0x36, 0xff},
	"UNKNOWN":      {0xe0, 0x6a, 0x10, 0xff},
	"CHECKING":     {0xe0, 0xa1, 0x00, 0xff},
	"INITIALIZING": {0xe0, 0xa1, 0x00, 0xff},
	"":             {0x8a, 0x8a, 0x8a, 0xff}, // daemon unreachable
}

// shieldIcon draws a shield of the given colour (size px square).
func shieldIcon(c color.NRGBA, size int) []byte {
	img := image.NewNRGBA(image.Rect(0, 0, size, size))
	s := float64(size)
	inside := func(x, y float64) bool {
		// Normalised coordinates: u in [-1,1], v in [0,1] top to bottom.
		u := (x - s/2) / (s * 0.42)
		v := (y - s*0.06) / (s * 0.88)
		if v < 0 || v > 1 || math.Abs(u) > 1 {
			return false
		}
		if v < 0.12 { // slightly dipped top edge
			return v > 0.12*(1-math.Abs(u))*0.6
		}
		if v < 0.55 {
			return true
		}
		// Lower half narrows to a point.
		t := (v - 0.55) / 0.45
		return math.Abs(u) <= math.Cos(t*math.Pi/2)
	}
	const ss = 4 // supersampling for smooth edges
	for py := 0; py < size; py++ {
		for px := 0; px < size; px++ {
			hits := 0
			for sy := 0; sy < ss; sy++ {
				for sx := 0; sx < ss; sx++ {
					if inside(float64(px)+(float64(sx)+0.5)/ss, float64(py)+(float64(sy)+0.5)/ss) {
						hits++
					}
				}
			}
			if hits > 0 {
				a := uint8(int(c.A) * hits / (ss * ss))
				img.SetNRGBA(px, py, color.NRGBA{c.R, c.G, c.B, a})
			}
		}
	}
	var buf bytes.Buffer
	_ = png.Encode(&buf, img)
	return buf.Bytes()
}

func iconFor(state string) []byte {
	c, ok := stateColors[state]
	if !ok {
		c = stateColors[""]
	}
	return shieldIcon(c, 44)
}
