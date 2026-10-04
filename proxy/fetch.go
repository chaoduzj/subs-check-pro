package proxies

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/metacubex/mihomo/common/convert"
	"github.com/sinspired/subs-check-pro/v3/config"
	"github.com/sinspired/subs-check-pro/v3/proxy/parse"
	"github.com/sinspired/subs-check-pro/v3/utils"
)

// 日期占位符正则表达式
var (
	dateRegexes = []struct {
		re     *regexp.Regexp
		format string
	}{
		{regexp.MustCompile(`(?i)\{ymd\}`), "20060102"},
		{regexp.MustCompile(`(?i)\{y-m-d\}`), "2006-01-02"},
		{regexp.MustCompile(`(?i)\{y_m_d\}`), "2006_01_02"},
		{regexp.MustCompile(`(?i)\{yy\}`), "2006"},
		{regexp.MustCompile(`(?i)\{y\}`), "2006"},
		{regexp.MustCompile(`(?i)\{mm\}`), "01"},
		{regexp.MustCompile(`(?i)\{m\}`), "1"},
		{regexp.MustCompile(`(?i)\{dd\}`), "02"},
		{regexp.MustCompile(`(?i)\{d\}`), "2"},
	}
)

const (
	// maxSubscriptionBytes 单个订阅允许读取的最大字节数。
	maxSubscriptionBytes = 50 << 20

	// maxPreallocBytes 按 Content-Length 预分配缓冲区的上限，
	// 防止恶意/错误的超大 Content-Length 让我们白白申请一大块内存。
	maxPreallocBytes = 32 << 20

	// sniffBytes 读取响应体开头这么多字节，用于尽早识别“明显不是订阅”的二进制内容。
	sniffBytes = 1024

	// dialTimeout 建立 TCP 连接（含 DNS 解析）的最长耗时。
	//
	// 原实现的 Transport 没有设置拨号超时，对黑洞地址（SYN 被丢弃）只能等到
	// 整个请求超时（>=10s）才放弃；死链越多，被白白占用的并发槽位越多。
	dialTimeout = 8 * time.Second

	// tlsHandshakeTimeout TLS 握手最长耗时。
	tlsHandshakeTimeout = 8 * time.Second

	// hostBreakerTTL 主机熔断的有效期。到期后会重新放行探测一次。
	hostBreakerTTL = 5 * time.Minute
)

var (
	// errNotText 响应体头部含 NUL 字节：二进制文件（图片/压缩包/可执行文件等），不可能是订阅。
	errNotText = errors.New("响应内容为二进制数据，不是有效订阅")

	// errTooLarge 订阅文件超过 maxSubscriptionBytes。
	errTooLarge = errors.New("订阅文件过大")
)

// clientMap 用于缓存不同代理策略的 HTTP Client
// key: "direct" 或 proxyUrl (e.g. "http://127.0.0.1:7890")
// clientMapCache 使用 sync.Map 存储复用的 http.Client
// Key: proxyAddr (string), Value: *http.Client
var clientMapCache sync.Map

// failClass 描述一次失败「值不值得再试」。
//
// 原实现只区分 404/410（fatal）与其它，其余一律整轮重试：
// 对“域名不存在 / 拒绝连接 / 证书错误”这类确定性失败，白白重试 (SubUrlsReTry+1) 轮，
// 每轮还要 sleep，且全程占用一个并发槽位，死链一多整体就被拖垮。
type failClass int

const (
	// failTransient 瞬时错误，重试（并换 UA）可能成功：5xx、429、401/403、连接被重置、EOF 等。
	failTransient failClass = iota
	// failTimeout 连接已建立后的超时（等待响应头 / 读取响应体）。
	// 对端可能只是首次生成订阅较慢、二次请求有缓存，所以允许再试一次，再超时就放弃。
	//
	// 连接阶段（拨号 / TLS 握手）的超时不属于此类：对端挂死、黑洞丢包时重试几乎不可能成功，
	// 只会让每个死链额外多占用一整个超时周期，这类超时直接归为 failPermanent，见 classifyTransportError。
	failTimeout
	// failPermanent 确定性失败，重试没有意义：DNS 不存在、拒绝连接、证书错误、其它 4xx、非文本内容等。
	failPermanent
)

// fetchFailure 单次请求失败的完整描述。
type fetchFailure struct {
	err        error
	class      failClass
	fatal      bool // 404/410/文件过大：不再尝试其它策略与重试（日期占位符链接除外），沿用原语义
	hostLevel  bool // 连接层失败（DNS/拒绝连接/拨号或 TLS 握手超时），计入熔断
	proxyLevel bool // 连接的是上游代理本身失败：熔断记在代理上，而不是目标主机上
	definitive bool // 结论确定（DNS 域名不存在），熔断阈值为 1
}

// statusError HTTP 状态码错误。
// Error() 必须保持返回纯数字字符串：proxies.go 中 logFatal / getErrorReason 依赖 strconv.Atoi(err.Error()) 识别状态码。
type statusError struct{ code int }

func (e *statusError) Error() string { return strconv.Itoa(e.code) }

// classifyStatus 按状态码分类。
func classifyStatus(code int) *fetchFailure {
	f := &fetchFailure{err: &statusError{code: code}, class: failPermanent}
	switch {
	case code == http.StatusNotFound || code == http.StatusGone:
		f.fatal = true
	case code == http.StatusUnauthorized || code == http.StatusForbidden || // 换 UA / 换策略可能放行
		code == http.StatusRequestTimeout || code == http.StatusTooEarly ||
		code == http.StatusTooManyRequests || code >= 500:
		f.class = failTransient
	}
	return f
}

// classifyTransportError 对网络层错误分类。
func classifyTransportError(err error) *fetchFailure {
	f := &fetchFailure{err: err, class: failTransient}

	// 1. DNS 域名不存在：确定性结果
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
		f.class, f.hostLevel, f.definitive = failPermanent, true, true
		return f
	}

	msg := strings.ToLower(err.Error())

	// 2. 证书 / 协议不匹配：换 UA、重试都不会改变结果
	var (
		unknownAuth x509.UnknownAuthorityError
		hostnameErr x509.HostnameError
		invalidCert x509.CertificateInvalidError
		verifyErr   *tls.CertificateVerificationError
		recordErr   tls.RecordHeaderError
	)
	if errors.As(err, &unknownAuth) || errors.As(err, &hostnameErr) ||
		errors.As(err, &invalidCert) || errors.As(err, &verifyErr) || errors.As(err, &recordErr) ||
		strings.Contains(msg, "server gave http response to https client") {
		f.class = failPermanent
		return f
	}

	// 3. 拒绝连接 / 网络不可达：主机或端口确实不在服务
	//    Windows 的报错文案不同（"actively refused"），errors.Is(syscall.ECONNREFUSED) 在 Windows 上也不可靠，故用文案匹配。
	if strings.Contains(msg, "connection refused") || strings.Contains(msg, "actively refused") ||
		strings.Contains(msg, "no route to host") || strings.Contains(msg, "network is unreachable") {
		f.class, f.hostLevel = failPermanent, true
		return f
	}

	// 4. 超时：区分“连接阶段”（主机大概率已死，不重试）与“响应阶段”（允许再试一次）
	if errors.Is(err, context.DeadlineExceeded) || isTimeoutErr(err) {
		if hasDialOp(err) || strings.Contains(msg, "tls handshake timeout") {
			f.class, f.hostLevel = failPermanent, true
		} else {
			f.class = failTimeout
		}
	}
	// 连接上游代理失败（含拒绝连接、拨号超时）：记在代理上
	if f.hostLevel && hasProxyConnectOp(err) {
		f.proxyLevel = true
	}

	return f
}

// isTimeoutErr 判断错误链中是否有 Timeout() == true 的 net.Error。
func isTimeoutErr(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// hasDialOp 判断错误链中是否出现拨号阶段的 net.OpError（含连接代理失败 proxyconnect）。
func hasDialOp(err error) bool {
	var op *net.OpError
	return errors.As(err, &op) && (op.Op == "dial" || op.Op == "proxyconnect")
}

// hasProxyConnectOp 判断是否是连接上游代理本身失败（net/http 对此使用 Op=="proxyconnect"）。
func hasProxyConnectOp(err error) bool {
	var op *net.OpError
	return errors.As(err, &op) && op.Op == "proxyconnect"
}

// hostBreaker 主机级熔断器。
//
// 订阅清单里经常有大量链接指向同一个已经挂掉的域名/服务器（例如整站下线）。
// 逐个请求都要各自等一遍拨号超时，是死链拖慢整体速度的主要原因之一。
// 同一「代理策略 + host:port」连接层连续失败达到阈值后，在 TTL 内直接短路后续请求。
//
// 只统计连接层失败（DNS 不存在、拒绝连接、拨号/TLS 握手超时），不统计 HTTP 状态码，
// 因此不会因为某个 URL 返回 404/429 而误伤同主机上的其它订阅。
type hostBreaker struct {
	mu sync.Mutex
	m  map[string]*breakerEntry
}

type breakerEntry struct {
	fails int
	until time.Time // 非零表示熔断中
	err   error
}

var subHostBreaker hostBreaker

// check 熔断中返回缓存的错误，否则返回 nil。
func (b *hostBreaker) check(key string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	e := b.m[key]
	if e == nil || e.until.IsZero() {
		return nil
	}
	if time.Now().After(e.until) {
		delete(b.m, key)
		return nil
	}
	return e.err
}

// fail 记录一次连接层失败。definitive 为 true（如 DNS 域名不存在）时 1 次即熔断，否则 2 次。
func (b *hostBreaker) fail(key string, err error, definitive bool) {
	threshold := 2
	if definitive {
		threshold = 1
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.m == nil {
		b.m = make(map[string]*breakerEntry)
	}
	e := b.m[key]
	if e == nil {
		e = &breakerEntry{}
		b.m[key] = e
	}
	e.fails++
	if e.fails >= threshold {
		e.until = time.Now().Add(hostBreakerTTL)
		e.err = err
	}
}

// ok 请求成功，清除失败记录。
func (b *hostBreaker) ok(key string) {
	b.mu.Lock()
	delete(b.m, key)
	b.mu.Unlock()
}

// clear 清空（每轮检测开始时由 ClearCache 调用）。
func (b *hostBreaker) clear() {
	b.mu.Lock()
	b.m = nil
	b.mu.Unlock()
}


// FetchSubsData 获取数据 (包含重试、占位符处理、代理策略)
func FetchSubsData(rawURL string) ([]byte, error) {
	// 清洗 URL
	rawURL = parse.CleanURL(rawURL)

	if _, err := url.Parse(rawURL); err != nil {
		return nil, err
	}

	slog.Debug("正在下载订阅", "URL", rawURL)

	conf := config.GlobalConfig
	maxRetries := max(1, conf.SubUrlsReTry)
	timeout := max(10, conf.SubUrlsTimeout)

	// 处理为标准的GitHub raw地址
	rawURL = utils.NormalizeGitHubRawURL(rawURL)

	candidates, hasPlaceholder := buildCandidateURLs(rawURL)
	var lastErr error

	// 定义请求策略
	type strategy struct {
		useProxy bool
		urlFunc  func(string) string
	}

	strategies := []strategy{}

	warpFunc := func(s string) string { return utils.WarpURL(parse.EnsureScheme(s), true) }
	originFunc := parse.EnsureScheme

	if utils.IsLocalURL(rawURL) {
		strategies = append(strategies, strategy{false, warpFunc})
	} else {
		// 1. 系统代理 (External utils)
		if utils.IsSysProxyAvailable {
			strategies = append(strategies, strategy{true, originFunc})
		}
		// 2. Github 代理 (External utils)
		if utils.IsGhProxyAvailable {
			strategies = append(strategies, strategy{false, warpFunc})
		}
		// 3. 直连兜底
		strategies = append(strategies, strategy{false, originFunc})
	}

	// UA 列表池
	uaList := []string{
		convert.RandUserAgent(),
		"mihomo/1.19.27",
		"v2ray",
		"sing-box/1.13.0",
		"ClashMetaForAndroid/2.11.30",
	}

	// GitHub 地址使用浏览器 ua 和curl
	if strings.Contains(rawURL, "githubusercontent.com") {
		uaList = []string{
			convert.RandUserAgent(),
			"curl/8.16.0",
		}
	}

	var (
		// permDead 已确认「重试也没用」的 (目标URL|是否代理)，后续轮次直接跳过
		permDead = make(map[string]struct{})
		// timeoutCnt 每个 (目标URL|是否代理) 的超时次数，达到 2 次后不再尝试
		timeoutCnt = make(map[string]int)
		rounds     int
	)

	for i := range maxRetries + 1 {
		rounds++
		ua := uaList[i%len(uaList)]
		if i > 0 {
			time.Sleep(time.Duration(max(1, conf.SubUrlsRetryInterval)) * time.Second)
		}

		// 本轮是否还存在「值得下一轮再试」的失败
		retryable := false

		for _, candidate := range candidates {
			triedInThisLoop := make(map[string]struct{})

			for _, strat := range strategies {
				targetURL := strat.urlFunc(candidate)

				key := targetURL + "|" + strconv.FormatBool(strat.useProxy)

				if _, tried := triedInThisLoop[key]; tried {
					continue
				}
				triedInThisLoop[key] = struct{}{}

				// 之前的轮次已确认不可恢复，不再浪费时间
				if _, dead := permDead[key]; dead {
					continue
				}

				// 保持 Debug，过于频繁的尝试详情不需要 Info
				slog.Debug("尝试下载", "Target", targetURL, "Proxy", strat.useProxy)

				body, fail := fetchOnce(targetURL, strat.useProxy, timeout, ua)
				if fail == nil {
					return body, nil
				}
				lastErr = fail.err

				if fail.fatal && !hasPlaceholder {
					return nil, fail.err
				}

				switch fail.class {
				case failPermanent:
					permDead[key] = struct{}{}
				case failTimeout:
					timeoutCnt[key]++
					if timeoutCnt[key] >= 2 {
						permDead[key] = struct{}{}
					} else {
						retryable = true
					}
				default:
					retryable = true
				}

				// 401/403 时给一个提示，方便调试
				var se *statusError
				if errors.As(fail.err, &se) && (se.code == 401 || se.code == 403) && strat.useProxy {
					slog.Debug("代理访问被拒，尝试下一策略", "URL", targetURL, "status", se.code)
				}
			}
		}
		if hasPlaceholder {
			return nil, ErrIgnore
		}
		// 本轮没有任何值得重试的失败：立即结束，不再 sleep、不再空转下一轮
		if !retryable {
			break
		}
	}

	if lastErr == nil {
		lastErr = errors.New("未知错误")
	}
	// 首轮就没有可重试项：原样返回底层错误，保留状态码/DNS 等可识别信息，便于报告展示
	if rounds == 1 {
		return nil, lastErr
	}
	return nil, fmt.Errorf("%d次重试后失败: %w", maxRetries, lastErr)
}

// getClient 根据代理地址获取复用的 Client
func getClient(proxyAddr string) *http.Client {
	if v, ok := clientMapCache.Load(proxyAddr); ok {
		return v.(*http.Client)
	}

	// 创建新的 Transport
	transport := &http.Transport{
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: false},
		MaxIdleConns:        100,              // 全局最大空闲连接
		MaxIdleConnsPerHost: 20,               // 每个 Host 最大空闲连接
		IdleConnTimeout:     90 * time.Second, // 空闲超时
		DisableKeepAlives:   false,            // 开启长连接复用

		// 连接阶段快速失败：死链/黑洞地址不再傻等整个请求超时
		DialContext: (&net.Dialer{
			Timeout:   dialTimeout,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		TLSHandshakeTimeout: tlsHandshakeTimeout,
	}

	// 设置代理
	if proxyAddr != "direct" {
		if u, err := url.Parse(proxyAddr); err == nil {
			transport.Proxy = http.ProxyURL(u)
		}
	} else {
		transport.Proxy = nil
	}

	// 创建 Client
	// timeout := max(10, config.GlobalConfig.SubUrlsTimeout)
	// 设置一个较大的超时，以在调用时控制超时
	newClient := &http.Client{
		Transport: transport,
		Timeout:   60 * time.Second,
	}

	// LoadOrStore 保证并发安全：如果其他协程已经创建了，就用它的，否则用我的
	actual, loaded := clientMapCache.LoadOrStore(proxyAddr, newClient)
	if loaded {
		// 并发竞争中落败：释放自己多建的 Transport，避免连接/goroutine 泄漏
		transport.CloseIdleConnections()
	}
	return actual.(*http.Client)
}

// fetchOnce 执行单次 HTTP 请求 (使用连接池)。成功返回 (body, nil)，失败返回 (nil, 失败描述)。
func fetchOnce(target string, useProxy bool, timeoutSec int, ua string) ([]byte, *fetchFailure) {
	// 1. 确定 Client Key
	proxyKey := "direct"
	if useProxy {
		if p := config.GlobalConfig.SystemProxy; p != "" {
			proxyKey = p // 使用代理地址作为 Key
		}
	}

	// 2. 获取复用的 Client
	client := getClient(proxyKey)

	// 3. 创建带超时的连接
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeoutSec)*time.Second)

	defer cancel()

	// 4. 创建请求
	req, err := http.NewRequestWithContext(ctx, "GET", target, nil)
	if err != nil {
		return nil, &fetchFailure{err: err, class: failPermanent}
	}

	// 4.0 熔断：「代理策略 + host:port」或上游代理本身已被判定不可达，直接短路
	breakerKey := proxyKey + "|" + req.URL.Host
	proxyBreakerKey := ""
	if proxyKey != "direct" {
		proxyBreakerKey = proxyKey + "|<proxy>"
		if cached := subHostBreaker.check(proxyBreakerKey); cached != nil {
			slog.Debug("上游代理已熔断，跳过", "Target", target, "原因", cached)
			return nil, &fetchFailure{err: cached, class: failPermanent}
		}
	}
	if cached := subHostBreaker.check(breakerKey); cached != nil {
		slog.Debug("主机已熔断，跳过", "Target", target, "原因", cached)
		return nil, &fetchFailure{err: cached, class: failPermanent}
	}

	if len(ua) <= 1 {
		ua = convert.RandUserAgent()
	}
	req.Header.Set("User-Agent", ua)

	// 4.1 GitHub 域名：使用 Token 提升速率限制 (未认证 60次/h → 认证 5000次/h)
	if isGitHubRequest(req.URL) {
		req.Header.Set("Accept", "application/vnd.github.v3+json")
		// GitHub 域名：使用 Token 提升速率限制 (未认证 60次/h → 认证 5000次/h)
		utils.InjectGitHubToken(req, config.GlobalConfig.GithubToken)
	}

	// 4.2 处理本地请求特殊 Header
	if isLocalRequest(req.URL) {
		req.Header.Set("X-From-Subs-Check-pro", "true")
		req.Header.Set("X-API-Key", config.GlobalConfig.APIKey)
		q := req.URL.Query()
		q.Set("from_subs_check", "true")
		req.URL.RawQuery = q.Encode()
	}

	// 5. 执行请求
	resp, err := client.Do(req)
	if err != nil {
		f := classifyTransportError(err)
		switch {
		case f.proxyLevel && proxyBreakerKey != "":
			subHostBreaker.fail(proxyBreakerKey, err, false)
		case f.hostLevel:
			subHostBreaker.fail(breakerKey, err, f.definitive)
		}
		return nil, f
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		// 读取128KB，超过的放弃连接复用
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 128*1024))
		slog.Debug("错误", "url", req.URL, "代理", useProxy, "状态码", resp.StatusCode, "UA", req.UserAgent())
		// 能收到 HTTP 响应说明主机（及上游代理）是通的，清除熔断计数
		subHostBreaker.ok(breakerKey)
		if proxyBreakerKey != "" {
			subHostBreaker.ok(proxyBreakerKey)
		}
		// 401/403 仅是"访问受阻"，不阻断后续策略；404/410 为 fatal
		return nil, classifyStatus(resp.StatusCode)
	}

	body, fail := readSubscriptionBody(resp)
	if fail != nil {
		return nil, fail
	}
	subHostBreaker.ok(breakerKey)
	if proxyBreakerKey != "" {
		subHostBreaker.ok(proxyBreakerKey)
	}
	return body, nil
}

// readSubscriptionBody 读取响应体。
//
// 相比原先的 io.ReadAll(LimitReader(100MB))：
//  1. 先读 sniffBytes 做嗅探，含 NUL 的二进制内容立即中止，不再把几十上百 MB 的垃圾文件读进内存；
//  2. Content-Length 已知时一次性预分配，避免 ReadAll 的倍增扩容（峰值内存约为数据量的 2~3 倍）。
func readSubscriptionBody(resp *http.Response) ([]byte, *fetchFailure) {
	// 如果 Content-Length 存在且超过限制，直接报错，避免无谓的读取
	if resp.ContentLength > maxSubscriptionBytes {
		return nil, &fetchFailure{
			err:   fmt.Errorf("%w: %d MB", errTooLarge, resp.ContentLength>>20),
			class: failPermanent,
			fatal: true,
		}
	}

	// 1. 头部嗅探
	head := make([]byte, sniffBytes)
	n, err := io.ReadFull(resp.Body, head)
	head = head[:n]
	if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
		return nil, classifyTransportError(err)
	}
	if bytes.IndexByte(head, 0) >= 0 {
		return nil, &fetchFailure{err: errNotText, class: failPermanent}
	}
	if err != nil {
		// 响应体不足 sniffBytes，已经读完
		return head, nil
	}

	// 2. 读取剩余部分
	capHint := 64 << 10
	if cl := resp.ContentLength; cl > 0 {
		// 额外留出 bytes.MinRead：Buffer.ReadFrom 每轮都要求至少 MinRead 的空闲空间，
		// 否则在读到 EOF 之前会多触发一次整体倍增扩容。
		capHint = int(min(cl, maxPreallocBytes)) + bytes.MinRead
	}
	capHint = max(capHint, n+bytes.MinRead)

	buf := bytes.NewBuffer(make([]byte, 0, capHint))
	buf.Write(head)
	// 多读 1 字节用于判断是否超限
	if _, err := buf.ReadFrom(io.LimitReader(resp.Body, maxSubscriptionBytes-int64(n)+1)); err != nil {
		return nil, classifyTransportError(err)
	}
	if buf.Len() > maxSubscriptionBytes {
		return nil, &fetchFailure{
			err:   fmt.Errorf("%w: 超过 %d MB 限制", errTooLarge, maxSubscriptionBytes>>20),
			class: failPermanent,
			fatal: true,
		}
	}
	return buf.Bytes(), nil
}

// buildCandidateURLs 生成候选链接
func buildCandidateURLs(u string) ([]string, bool) {
	if !hasDatePlaceholder(u) {
		return []string{u}, false
	}
	now := time.Now()
	yest := now.AddDate(0, 0, -1)
	today := replaceDatePlaceholders(u, now)
	yesterday := replaceDatePlaceholders(u, yest)
	slog.Debug("检测到日期占位符，将尝试今日和昨日日期")
	return []string{today, yesterday}, true
}

func hasDatePlaceholder(s string) bool {
	ls := strings.ToLower(s)
	return strings.Contains(ls, "{ymd}") || strings.Contains(ls, "{y}") ||
		strings.Contains(ls, "{m}") || strings.Contains(ls, "{mm}") ||
		strings.Contains(ls, "{d}") || strings.Contains(ls, "{dd}") ||
		strings.Contains(ls, "{y-m-d}") || strings.Contains(ls, "{y_m_d}")
}

func replaceDatePlaceholders(s string, t time.Time) string {
	out := s
	for _, item := range dateRegexes {
		// 只有当字符串包含 { 时才执行正则，提升极大性能
		if strings.Contains(out, "{") {
			out = item.re.ReplaceAllString(out, t.Format(item.format))
		}
	}
	return out
}

func isLocalRequest(u *url.URL) bool {
	return utils.IsLocalURL(u.Hostname()) &&
		(strings.Contains(u.Fragment, "Keep") || strings.Contains(u.Path, "history") || strings.Contains(u.Path, "all"))
}

// isGitHubRequest 判断是否为 GitHub 相关域名
// 涵盖 API、raw 内容、releases 下载等场景
func isGitHubRequest(u *url.URL) bool {
	host := strings.ToLower(u.Hostname())
	return host == "github.com" ||
		host == "api.github.com" ||
		host == "raw.githubusercontent.com" ||
		host == "objects.githubusercontent.com" ||
		strings.HasSuffix(host, ".github.com") ||
		strings.HasSuffix(host, ".githubusercontent.com")
}
