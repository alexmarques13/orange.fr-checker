package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

const trustVersion = "2.11.0"

var browserTrustFields = []string{
	"version", "service", "time", "uuid", "step",
	"screen_h", "screen_w", "screen_ah", "screen_aw",
	"window_h", "window_w", "availWidth", "availHeight",
	"ua", "platform", "languages", "tz", "timezone",
	"deviceMemory", "hardwareConcurrency", "maxTouchPoints",
	"colorDepth", "pixelDepth", "plugins", "webdriver", "isHeadless",
	"vendor", "renderer", "canvas", "audio", "webgl", "touch",
}

var (
	chromeVersions = []string{"120", "121", "122", "123", "124", "125", "126", "127", "128", "129", "130", "131"}
	screenSizes    = []screenSize{
		{1280, 720}, {1366, 768}, {1440, 900}, {1536, 864},
		{1600, 900}, {1920, 1080}, {1920, 1200}, {2560, 1440},
	}
	deviceMemoryOptions        = []int{4, 8, 16}
	hardwareConcurrencyOptions = []int{4, 8, 12, 16}
	webglVendors               = []string{
		"Google Inc. (Intel)",
		"Google Inc. (NVIDIA)",
		"Google Inc. (AMD)",
	}
	webglRenderers = []string{
		"ANGLE (Intel, Intel(R) UHD Graphics 630 Direct3D11 vs_5_0 ps_5_0, D3D11)",
		"ANGLE (NVIDIA, NVIDIA GeForce GTX 1660 SUPER Direct3D11 vs_5_0 ps_5_0, D3D11)",
		"ANGLE (AMD, AMD Radeon RX 580 Series Direct3D11 vs_5_0 ps_5_0, D3D11)",
	}
	frenchTimezones = []string{"Europe/Paris"}
	languageSets    = [][]string{
		{"fr-FR", "fr"},
		{"fr", "fr-FR"},
		{"fr-FR", "fr", "en"},
		{"fr-FR"},
	}
)

type screenSize struct {
	w, h int
}

type browserProfile struct {
	UserAgent           string
	ChromeMajor         string
	ChromeFull          string
	ScreenW             int
	ScreenH             int
	ScreenAW            int
	ScreenAH            int
	WindowW             int
	WindowH             int
	Platform            string
	TZ                  string
	TimezoneOffset      int
	Languages           []string
	DeviceMemory        int
	HardwareConcurrency int
	MaxTouchPoints      int
	ColorDepth          int
	PixelDepth          int
	WebGLVendor         string
	WebGLRenderer       string
	CanvasHash          string
	AudioHash           string
	WebGLHash           string
	Touch               bool
}

func (p browserProfile) acceptLanguage() string {
	if len(p.Languages) == 0 {
		return "fr-FR,fr;q=0.9"
	}
	parts := make([]string, len(p.Languages))
	for i, lang := range p.Languages {
		if i == 0 {
			parts[i] = lang
		} else {
			q := 0.9 - float64(i-1)*0.1
			if q < 0.1 {
				q = 0.1
			}
			parts[i] = fmt.Sprintf("%s;q=%.1f", lang, q)
		}
	}
	return strings.Join(parts, ",")
}

func (p browserProfile) secChUA() string {
	return fmt.Sprintf(`"Chromium";v="%s", "Google Chrome";v="%s", "Not-A.Brand";v="99"`, p.ChromeMajor, p.ChromeMajor)
}

func (p browserProfile) applyHeaders(h http.Header) {
	h.Set("User-Agent", p.UserAgent)
	h.Set("Accept-Language", p.acceptLanguage())
	h.Set("sec-ch-ua", p.secChUA())
	h.Set("sec-ch-ua-mobile", "?0")
	h.Set("sec-ch-ua-platform", `"Windows"`)
}

type sessionIdentity struct {
	profile browserProfile
	fpUUID  string
	sid     string
}

func (id sessionIdentity) trustFingerprint() map[string]interface{} {
	p := id.profile
	return map[string]interface{}{
		"version":             trustVersion,
		"service":             "idme",
		"time":                time.Now().UnixMilli(),
		"uuid":                id.fpUUID,
		"step":                "init",
		"screen_h":            p.ScreenH,
		"screen_w":            p.ScreenW,
		"screen_ah":           p.ScreenAH,
		"screen_aw":           p.ScreenAW,
		"window_h":            p.WindowH,
		"window_w":            p.WindowW,
		"availWidth":          p.ScreenAW,
		"availHeight":         p.ScreenAH,
		"ua":                  p.UserAgent,
		"platform":            p.Platform,
		"languages":           p.Languages,
		"tz":                  p.TZ,
		"timezone":            p.TimezoneOffset,
		"deviceMemory":        p.DeviceMemory,
		"hardwareConcurrency": p.HardwareConcurrency,
		"maxTouchPoints":      p.MaxTouchPoints,
		"colorDepth":          p.ColorDepth,
		"pixelDepth":          p.PixelDepth,
		"plugins":             []string{},
		"webdriver":           false,
		"isHeadless":          false,
		"vendor":              p.WebGLVendor,
		"renderer":            p.WebGLRenderer,
		"canvas":              p.CanvasHash,
		"audio":               p.AudioHash,
		"webgl":               p.WebGLHash,
		"touch":               p.Touch,
	}
}

func fingerprintDigest(fp map[string]interface{}) string {
	b, _ := json.Marshal(fp)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:8])
}

func compareFingerprint(l *log, fp map[string]interface{}) {
	have := make(map[string]struct{}, len(fp))
	for k := range fp {
		have[k] = struct{}{}
	}

	var missing, extra []string
	for _, k := range browserTrustFields {
		if _, ok := have[k]; !ok {
			missing = append(missing, k)
		}
	}
	for k := range fp {
		found := false
		for _, ref := range browserTrustFields {
			if ref == k {
				found = true
				break
			}
		}
		if !found {
			extra = append(extra, k)
		}
	}

	l.info("fingerprint digest=" + fingerprintDigest(fp))
	if len(missing) == 0 && len(extra) == 0 {
		l.ok("fingerprint matches browser trust.js " + trustVersion)
		return
	}
	if len(missing) > 0 {
		l.warn("missing vs browser: " + strings.Join(missing, ", "))
	}
	if len(extra) > 0 {
		l.warn("extra vs browser: " + strings.Join(extra, ", "))
	}
}

func newSessionIdentity() sessionIdentity {
	return sessionIdentity{
		profile: newBrowserProfile(),
		fpUUID:  newUUID(),
		sid:     uuidHex(),
	}
}

func (id sessionIdentity) summary() string {
	return id.profile.summary() + " uuid=" + id.fpUUID[:8]
}

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func randUint32() uint32 {
	var b [4]byte
	_, _ = rand.Read(b[:])
	return binary.BigEndian.Uint32(b[:])
}

func randChoice[T any](items []T) T {
	return items[randUint32()%uint32(len(items))]
}

func parisTimezoneOffsetInt() int {
	loc, err := time.LoadLocation("Europe/Paris")
	if err != nil {
		return -60
	}
	_, offset := time.Now().In(loc).Zone()
	return -offset / 60
}

func newBrowserProfile() browserProfile {
	screen := randChoice(screenSizes)
	taskbar := 40 + int(randUint32()%41)
	outerW := 0
	if randUint32()%3 == 0 {
		outerW = 8 + int(randUint32()%9)
	}
	windowW := screen.w - outerW
	windowH := screen.h - taskbar
	if windowW < 800 {
		windowW = screen.w
	}
	if windowH < 600 {
		windowH = screen.h - 40
	}

	major := randChoice(chromeVersions)
	patch := 6100 + int(randUint32()%800)
	chromeFull := fmt.Sprintf("%s.0.%d.0", major, patch)
	ua := fmt.Sprintf(
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/%s Safari/537.36",
		chromeFull,
	)

	langs := randChoice(languageSets)
	langCopy := make([]string, len(langs))
	copy(langCopy, langs)

	return browserProfile{
		UserAgent:           ua,
		ChromeMajor:         major,
		ChromeFull:          chromeFull,
		ScreenW:             screen.w,
		ScreenH:             screen.h,
		ScreenAW:            screen.w,
		ScreenAH:            screen.h - taskbar,
		WindowW:             windowW,
		WindowH:             windowH,
		Platform:            "Win32",
		TZ:                  randChoice(frenchTimezones),
		TimezoneOffset:      parisTimezoneOffsetInt(),
		Languages:           langCopy,
		DeviceMemory:        randChoice(deviceMemoryOptions),
		HardwareConcurrency: randChoice(hardwareConcurrencyOptions),
		MaxTouchPoints:      0,
		ColorDepth:          24,
		PixelDepth:          24,
		WebGLVendor:         randChoice(webglVendors),
		WebGLRenderer:       randChoice(webglRenderers),
		CanvasHash:          randHex(16),
		AudioHash:           randHex(16),
		WebGLHash:           randHex(16),
		Touch:               false,
	}
}

func (p browserProfile) summary() string {
	return fmt.Sprintf("Chrome/%s %dx%d %s %v mem=%d cores=%d",
		p.ChromeFull, p.ScreenW, p.ScreenH, p.TZ, p.Languages, p.DeviceMemory, p.HardwareConcurrency)
}
