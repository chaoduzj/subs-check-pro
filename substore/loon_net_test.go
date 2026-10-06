// sub-store\loon_net_test.go
package substore

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"
)

// startFakeDNS 启动本地 UDP DNS：A 记录返回 127.0.0.1，AAAA 返回空应答。
// dropAll 丢弃全部查询；dropAAAA 只丢弃 AAAA 查询。
func startFakeDNS(t *testing.T, dropAll, dropAAAA bool) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	go func() {
		buf := make([]byte, 512)
		for {
			n, peer, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			q := buf[:n]
			i := 12
			for i < len(q) && q[i] != 0 {
				i += int(q[i]) + 1
			}
			if dropAll || i+3 >= len(q) {
				continue
			}
			qtype := int(q[i+1])<<8 | int(q[i+2])
			if dropAAAA && qtype == 28 {
				continue
			}
			resp := append([]byte(nil), q[:i+5]...)
			resp[2], resp[3] = 0x81, 0x80
			resp[6], resp[7], resp[8], resp[9], resp[10], resp[11] = 0, 0, 0, 0, 0, 0
			if qtype == 1 {
				resp[7] = 1
				resp = append(resp, 0xC0, 0x0C, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 127, 0, 0, 1)
			}
			_, _ = pc.WriteTo(resp, peer)
		}
	}()
	return pc.LocalAddr().String()
}

func newTestResolver(system *net.Resolver) *resolver {
	return &resolver{system: system, inflight: map[string]*lookupCall{}}
}

func lookupTimed(t *testing.T, r *resolver) (time.Duration, []netip.Addr) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	start := time.Now()
	addrs, _, err := r.lookup(ctx, "raw.githubusercontent.com")
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	return time.Since(start), addrs
}

// 首个 DNS 无响应时，第二个立即接上；前两个都无响应时，由第三个在一个错开间隔后接力
func TestHedgedLookupSkipsDeadServers(t *testing.T) {
	dead1, dead2, live := startFakeDNS(t, true, false), startFakeDNS(t, true, false), startFakeDNS(t, false, false)
	t.Cleanup(func() { SetFallbackDNS() })

	SetFallbackDNS(dead1, live)
	if d, addrs := lookupTimed(t, newTestResolver(nil)); len(addrs) == 0 || d > hedgeStagger/2 {
		t.Fatalf("首个无响应时应立即由第二个接上: %v %v", d, addrs)
	}

	SetFallbackDNS(dead1, dead2, live)
	if d, _ := lookupTimed(t, newTestResolver(nil)); d < hedgeStagger/2 || d > hedgeStagger+300*time.Millisecond {
		t.Fatalf("耗时 %v，应约等于 %v", d, hedgeStagger)
	}
}

// AAAA 被丢包时，不应拖住 A 记录的结果
func TestLookupDoesNotWaitForDroppedAAAA(t *testing.T) {
	SetFallbackDNS(startFakeDNS(t, false, true))
	t.Cleanup(func() { SetFallbackDNS() })

	if d, _ := lookupTimed(t, newTestResolver(nil)); d > 300*time.Millisecond {
		t.Fatalf("耗时 %v，不应等待 AAAA 超时", d)
	}
}

// 系统 DNS 不可用时转入公共 DNS
func TestSystemResolverFailureFallsBack(t *testing.T) {
	SetFallbackDNS(startFakeDNS(t, false, false))
	t.Cleanup(func() { SetFallbackDNS() })

	broken := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
		return nil, errors.New("connection refused")
	}}
	if _, addrs := lookupTimed(t, newTestResolver(broken)); len(addrs) == 0 {
		t.Fatal("应通过公共 DNS 解析成功")
	}
}

// 第一个 IP 黑洞时，由第二个 IP 在 dialStagger 后接管；第一个直接失败时立即换下一个
func TestRaceDial(t *testing.T) {
	addrs := []netip.Addr{netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("10.0.0.2")}
	good, _ := net.Pipe()

	blackhole := func(ctx context.Context, ep string) (net.Conn, error) {
		if ep == "10.0.0.1:443" {
			<-ctx.Done()
			return nil, ctx.Err()
		}
		return good, nil
	}
	start := time.Now()
	conn, err := raceDial(context.Background(), addrs, "443", blackhole)
	if err != nil || conn != good {
		t.Fatalf("应连上第二个 IP: %v", err)
	}
	if d := time.Since(start); d < dialStagger/2 || d > dialStagger+300*time.Millisecond {
		t.Fatalf("黑洞场景耗时 %v，应约等于 %v", d, dialStagger)
	}

	refused := func(ctx context.Context, ep string) (net.Conn, error) {
		if ep == "10.0.0.1:443" {
			return nil, errors.New("refused")
		}
		return good, nil
	}
	start = time.Now()
	if _, err := raceDial(context.Background(), addrs, "443", refused); err != nil {
		t.Fatal(err)
	}
	if d := time.Since(start); d > dialStagger/2 {
		t.Fatalf("首个失败后应立即换下一个，实际耗时 %v", d)
	}
}

type flakyTransport struct {
	failures atomic.Int32
	calls    atomic.Int32
}

func (f *flakyTransport) RoundTrip(*http.Request) (*http.Response, error) {
	if f.calls.Add(1) <= f.failures.Load() {
		return nil, &net.DNSError{Err: "i/o timeout", IsTimeout: true}
	}
	return &http.Response{StatusCode: 200, Body: http.NoBody}, nil
}

// 幂等请求遇到瞬时错误会重试；非幂等或服务器明确答复则不重试
func TestDoWithRetry(t *testing.T) {
	retryDelay = time.Millisecond
	do := func(failures int32, canRetry bool) (int32, error) {
		tr := &flakyTransport{}
		tr.failures.Store(failures)
		req, _ := http.NewRequest("GET", "http://x.test/", nil)
		_, err := doWithRetry(context.Background(), &http.Client{Transport: tr}, req, canRetry)
		return tr.calls.Load(), err
	}
	if n, err := do(2, true); err != nil || n != 3 {
		t.Fatalf("应第 3 次成功: calls=%d err=%v", n, err)
	}
	if n, err := do(99, true); err == nil || n != maxAttempts {
		t.Fatalf("应在 %d 次后放弃: calls=%d err=%v", maxAttempts, n, err)
	}
	if n, _ := do(99, false); n != 1 {
		t.Fatalf("不可重试的请求只应尝试 1 次: calls=%d", n)
	}
}
