// sub-store\loon_net.go
package substore

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	dnsTimeout    = 6 * time.Second
	systemTimeout = 2500 * time.Millisecond
	hedgeStagger  = 150 * time.Millisecond
	v6Grace       = 30 * time.Millisecond
	dialStagger   = 250 * time.Millisecond
	dnsCacheTTL   = 10 * time.Minute
)

var defaultPublicDNS = []string{"223.5.5.5:53", "119.29.29.29:53", "114.114.114.114:53", "8.8.8.8:53", "1.1.1.1:53"}

var (
	dnsServers atomic.Pointer[[]string]
	dnsRR      atomic.Uint32
	dialer     = &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
)

func init() {
	servers := parseDNSList(os.Getenv("SUBSTORE_DNS"))
	if len(servers) == 0 {
		servers = append(servers, defaultPublicDNS...)
	}
	dnsServers.Store(&servers)

	// Android 没有 /etc/resolv.conf，Go 会退回到 [::1]:53 导致解析必败
	if runtime.GOOS == "android" {
		net.DefaultResolver = &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			list := *dnsServers.Load()
			return dialer.DialContext(ctx, network, list[int(dnsRR.Add(1)-1)%len(list)])
		}}
	}
}

// SetFallbackDNS 供 Android 壳层传入系统真实 DNS；传空则恢复默认公共 DNS。
func SetFallbackDNS(servers ...string) {
	list := parseDNSList(strings.Join(servers, ","))
	if len(list) == 0 {
		list = append(list, defaultPublicDNS...)
	}
	dnsServers.Store(&list)
}

func parseDNSList(s string) []string {
	var out []string
	for _, f := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ';' || r == ' ' || r == '\t' || r == '\n' }) {
		if ap, err := netip.ParseAddrPort(f); err == nil {
			out = append(out, ap.String())
		} else if ip, err := netip.ParseAddr(strings.Trim(f, "[]")); err == nil {
			out = append(out, netip.AddrPortFrom(ip, 53).String())
		}
	}
	return out
}

type cacheEntry struct {
	addrs  []netip.Addr
	expire time.Time
}

type lookupCall struct {
	done  chan struct{}
	addrs []netip.Addr
	err   error
}

type resolver struct {
	system   *net.Resolver // nil 表示无系统 DNS 可用（Android），直接走公共 DNS
	cache    sync.Map
	mu       sync.Mutex
	inflight map[string]*lookupCall
}

func newResolver() *resolver {
	r := &resolver{inflight: map[string]*lookupCall{}}
	if runtime.GOOS != "android" {
		r.system = &net.Resolver{PreferGo: true}
	}
	return r
}

var (
	sharedResolver = newResolver()
	dialContext    = sharedResolver.dial
	loopback       = []netip.Addr{netip.AddrFrom4([4]byte{127, 0, 0, 1}), netip.IPv6Loopback()}
)

func hostKey(host string) string { return strings.ToLower(strings.TrimSuffix(host, ".")) }

func isNotFound(err error) bool {
	var de *net.DNSError
	return errors.As(err, &de) && de.IsNotFound
}

// lookup 返回 IPv4 在前的地址列表；cached 表示结果来自缓存。
func (r *resolver) lookup(ctx context.Context, host string) (addrs []netip.Addr, cached bool, err error) {
	if ip, e := netip.ParseAddr(host); e == nil {
		return []netip.Addr{ip.Unmap()}, false, nil
	}
	key := hostKey(host)
	if key == "localhost" || strings.HasSuffix(key, ".localhost") {
		return loopback, false, nil
	}
	var stale []netip.Addr
	if v, ok := r.cache.Load(key); ok {
		e := v.(cacheEntry)
		if time.Now().Before(e.expire) {
			return e.addrs, true, nil
		}
		stale = e.addrs
	}
	addrs, err = r.resolve(ctx, key)
	if err != nil && len(stale) > 0 && !isNotFound(err) {
		return stale, true, nil
	}
	return addrs, false, err
}

// resolve 对同一主机的并发解析只发一次查询；解析过程与单个调用方的 ctx 解耦。
func (r *resolver) resolve(ctx context.Context, key string) ([]netip.Addr, error) {
	r.mu.Lock()
	c, ok := r.inflight[key]
	if !ok {
		c = &lookupCall{done: make(chan struct{})}
		r.inflight[key] = c
		go func() {
			qctx, cancel := context.WithTimeout(context.Background(), dnsTimeout)
			defer cancel()
			c.addrs, c.err = r.query(qctx, key)
			if c.err == nil {
				r.cache.Store(key, cacheEntry{c.addrs, time.Now().Add(dnsCacheTTL)})
			}
			r.mu.Lock()
			delete(r.inflight, key)
			r.mu.Unlock()
			close(c.done)
		}()
	}
	r.mu.Unlock()

	select {
	case <-c.done:
		return c.addrs, c.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (r *resolver) query(ctx context.Context, host string) ([]netip.Addr, error) {
	if r.system != nil {
		sctx, cancel := context.WithTimeout(ctx, systemTimeout)
		addrs, err := lookupDual(sctx, r.system, host)
		cancel()
		if err == nil || isNotFound(err) {
			return addrs, err
		}
	}
	return hedgedLookup(ctx, host)
}

// hedgedLookup 对公共 DNS 并发查询，最先成功者胜出：前两个同时发出，其余依次错开 hedgeStagger 再启动，
// 既避免首个服务器无响应时干等，也让境外 DNS 仅在国内服务器都没回应时才参与。
func hedgedLookup(ctx context.Context, host string) ([]netip.Addr, error) {
	servers := *dnsServers.Load()
	attempts := max(len(servers), 3)
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	type result struct {
		addrs []netip.Addr
		err   error
	}
	ch := make(chan result, attempts)
	for i := 0; i < attempts; i++ {
		go func(i int) {
			if i > 1 {
				select {
				case <-time.After(time.Duration(i-1) * hedgeStagger):
				case <-ctx.Done():
					ch <- result{err: ctx.Err()}
					return
				}
			}
			server := servers[i%len(servers)]
			res := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return dialer.DialContext(ctx, network, server)
			}}
			a, err := lookupDual(ctx, res, host)
			ch <- result{a, err}
		}(i)
	}

	var lastErr, notFound error
	for i := 0; i < attempts; i++ {
		res := <-ch
		if res.err == nil {
			return res.addrs, nil
		}
		if isNotFound(res.err) {
			notFound = res.err
		}
		lastErr = res.err
	}
	if notFound != nil {
		return nil, notFound
	}
	return nil, lastErr
}

// lookupDual 分别查询 A 与 AAAA：A 一到就返回，AAAA 最多再等 v6Grace。
// Go 自带的 "ip" 查询会等两者都结束，AAAA 被丢包时整次解析要白等到超时。
func lookupDual(ctx context.Context, res *net.Resolver, host string) ([]netip.Addr, error) {
	type result struct {
		addrs []netip.Addr
		err   error
	}
	c4, c6 := make(chan result, 1), make(chan result, 1)
	go func() { a, e := res.LookupNetIP(ctx, "ip4", host); c4 <- result{a, e} }()
	go func() { a, e := res.LookupNetIP(ctx, "ip6", host); c6 <- result{a, e} }()

	r4 := <-c4
	if r4.err != nil || len(r4.addrs) == 0 {
		if r6 := <-c6; r6.err == nil && len(r6.addrs) > 0 {
			return orderAddrs(r6.addrs), nil
		}
		if r4.err == nil {
			r4.err = &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
		}
		return nil, r4.err
	}
	select {
	case r6 := <-c6:
		if r6.err == nil {
			return orderAddrs(append(r4.addrs, r6.addrs...)), nil
		}
	case <-time.After(v6Grace):
	}
	return orderAddrs(r4.addrs), nil
}

// orderAddrs 去重并让 IPv4 在前（国内网络下 IPv6 到海外站点往往更慢或不通）。
func orderAddrs(in []netip.Addr) []netip.Addr {
	var v4, v6 []netip.Addr
	seen := make(map[netip.Addr]bool, len(in))
	for _, a := range in {
		a = a.Unmap()
		if seen[a] {
			continue
		}
		seen[a] = true
		if a.Is4() {
			v4 = append(v4, a)
		} else {
			v6 = append(v6, a)
		}
	}
	return append(v4[:min(len(v4), 4)], v6[:min(len(v6), 2)]...)
}

func filterNetwork(addrs []netip.Addr, network string) []netip.Addr {
	if network != "tcp4" && network != "tcp6" {
		return addrs
	}
	out := make([]netip.Addr, 0, len(addrs))
	for _, a := range addrs {
		if a.Is4() == (network == "tcp4") {
			out = append(out, a)
		}
	}
	return out
}

func sameAddrs(a, b []netip.Addr) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func tcpDial(ctx context.Context, endpoint string) (net.Conn, error) {
	return dialer.DialContext(ctx, "tcp", endpoint)
}

func (r *resolver) dial(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return dialer.DialContext(ctx, network, addr)
	}
	addrs, cached, err := r.lookup(ctx, host)
	if err != nil {
		return nil, &net.OpError{Op: "dial", Net: network, Err: err}
	}
	conn, err := raceDial(ctx, filterNetwork(addrs, network), port, tcpDial)
	if err == nil || ctx.Err() != nil {
		return conn, err
	}

	// 全部连不上：丢弃缓存；若缓存的 IP 已过时，用新解析结果再试一次
	r.cache.Delete(hostKey(host))
	if cached {
		if fresh, _, e := r.lookup(ctx, host); e == nil && !sameAddrs(fresh, addrs) {
			return raceDial(ctx, filterNetwork(fresh, network), port, tcpDial)
		}
	}
	return nil, err
}

// raceDial 按 dialStagger 错开依次发起连接，前一个失败则立即启动下一个，最先建立成功的胜出。
func raceDial(ctx context.Context, addrs []netip.Addr, port string, dial func(context.Context, string) (net.Conn, error)) (net.Conn, error) {
	switch len(addrs) {
	case 0:
		return nil, &net.AddrError{Err: "no suitable address found", Addr: port}
	case 1:
		return dial(ctx, net.JoinHostPort(addrs[0].String(), port))
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	type result struct {
		conn net.Conn
		err  error
	}
	ch := make(chan result, len(addrs))
	launched, done := 0, 0
	launch := func() {
		ep := net.JoinHostPort(addrs[launched].String(), port)
		launched++
		go func() {
			c, err := dial(ctx, ep)
			ch <- result{c, err}
		}()
	}

	launch()
	var firstErr error
	for {
		var next <-chan time.Time
		if launched < len(addrs) {
			next = time.After(dialStagger)
		}
		select {
		case <-next:
			launch()
		case res := <-ch:
			done++
			if res.err == nil {
				go func(n int) { // 回收落败但已连通的连接
					for ; n > 0; n-- {
						if r := <-ch; r.conn != nil {
							r.conn.Close()
						}
					}
				}(launched - done)
				return res.conn, nil
			}
			if firstErr == nil {
				firstErr = res.err
			}
			if launched < len(addrs) {
				launch()
			} else if done == launched {
				return nil, firstErr
			}
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

var loonClient = sync.OnceValue(func() *http.Client {
	return &http.Client{Transport: &http.Transport{
		DialContext:           dialContext,
		ForceAttemptHTTP2:     true,
		TLSClientConfig:       &tls.Config{ClientSessionCache: tls.NewLRUClientSessionCache(128)},
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: time.Second,
		ReadBufferSize:        32 << 10,
		WriteBufferSize:       32 << 10,
	}}
})

// loonHTTPClient 返回脚本请求共用的客户端；总超时由每个请求自己的 context 决定。
func loonHTTPClient() *http.Client { return loonClient() }

// localAPIClient 用于访问本机 Sub-Store 接口，超时略大于引擎 3 分钟的执行上限。
var localAPIClient = &http.Client{
	Timeout: 4 * time.Minute,
	Transport: func() *http.Transport {
		t := http.DefaultTransport.(*http.Transport).Clone()
		t.Proxy = nil
		return t
	}(),
}

// jsRuntimeLimits 返回 QuickJS 内存与栈上限；Android 的 cgo 线程栈仅约 1MB，需更小的 JS 栈。
// 可用 SUBSTORE_JS_STACK_KB / SUBSTORE_JS_MEM_MB 覆盖。
func jsRuntimeLimits() (memLimit, stackSize uint64) {
	memLimit, stackSize = 512<<20, 16<<20
	if runtime.GOOS == "android" {
		memLimit, stackSize = 256<<20, 768<<10
	}
	if kb := envInt("SUBSTORE_JS_STACK_KB"); kb > 0 {
		stackSize = uint64(kb) << 10
	}
	if mb := envInt("SUBSTORE_JS_MEM_MB"); mb > 0 {
		memLimit = uint64(mb) << 20
	}
	return
}

func envInt(key string) (n int) {
	for _, c := range strings.TrimSpace(os.Getenv(key)) {
		if c < '0' || c > '9' {
			return 0
		}
		n = n*10 + int(c-'0')
	}
	return
}

const maxAttempts = 3

var retryDelay = 200 * time.Millisecond

func isTransient(err error) bool {
	if err == nil || errors.Is(err, context.Canceled) {
		return false
	}
	var de *net.DNSError
	if errors.As(err, &de) {
		return !de.IsNotFound
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return true
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "connection reset") || strings.Contains(msg, "unexpected eof")
}

// doWithRetry 仅对幂等请求在遇到瞬时网络错误时重试；拿到任何 HTTP 响应都原样返回。
func doWithRetry(ctx context.Context, c *http.Client, req *http.Request, canRetry bool) (*http.Response, error) {
	delay := retryDelay
	for attempt := 1; ; attempt++ {
		r := req
		if attempt > 1 {
			r = req.Clone(ctx)
		}
		resp, err := c.Do(r)
		if err == nil || !canRetry || attempt >= maxAttempts || ctx.Err() != nil || !isTransient(err) {
			return resp, err
		}
		select {
		case <-time.After(delay):
		case <-ctx.Done():
			return nil, err
		}
		delay *= 3
	}
}
