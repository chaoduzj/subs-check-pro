package utils

import (
	"context"
	"log/slog"
	"math/rand/v2"
	"net"
	"sync/atomic"
	"time"
)

// 本机网络健康探针（拥塞保护）
//
// 背景：检测时会同时打开大量到代理服务器的连接，并且测速会跑满带宽。
// 家用路由器的 NAT/conntrack 连接表、DNS、上下行队列很容易被打满，
// 表现为「本来存活的节点」也大面积超时，检测结束后紧接着的通知请求也会超时。
//
// 做法：独立于任何代理，直连几个公共 TCP 端口，持续测量「本机网络本身」是否健康。
// 检测流程据此：①拥塞时暂缓发起新任务（自然降低并发）；②拥塞期间失败的节点不直接判死，
// 等网络恢复后复核一次；③检测结束 / 发送通知前，先等网络恢复。

const (
	ngProbeTimeout  = 2 * time.Second         // 单次探测超时
	ngProbeInterval = time.Second             // 探测间隔
	ngMinRTTLimit   = 1500 * time.Millisecond // 判定拥塞的最小 RTT 阈值
)

// ngProbeTargets 探测目标，任意一个连通即视为本机网络正常。
// 选用公共 DNS 的 TCP 端口，只做握手后立即关闭，不产生实际流量。
var ngProbeTargets = []string{"223.5.5.5:53", "119.29.29.29:53", "1.1.1.1:443"}

type netGuard struct {
	running  atomic.Bool  // 后台探针是否在运行
	degraded atomic.Bool  // 当前是否判定为拥塞
	everOK   atomic.Bool  // 进程生命周期内是否探测成功过（用于识别「探针目标在本环境不可用」）
	lastBad  atomic.Int64 // 最近一次探测异常的时间 (UnixNano)
	baseRTT  atomic.Int64 // 检测开始前校准出的基准 RTT
}

// NetGuard 全局本机网络健康探针
var NetGuard = &netGuard{}

// limit 返回当前判定「变慢」的 RTT 阈值：基准的 5 倍，且不低于 1.5s。
func (g *netGuard) limit() time.Duration {
	if b := time.Duration(g.baseRTT.Load()); b > 0 {
		return max(ngMinRTTLimit, b*5)
	}
	return ngMinRTTLimit
}

// probe 并发探测所有目标，返回最先连通的目标的 RTT。
func (g *netGuard) probe(ctx context.Context) (time.Duration, bool) {
	pctx, cancel := context.WithTimeout(ctx, ngProbeTimeout)
	defer cancel()

	type res struct {
		rtt time.Duration
		ok  bool
	}
	ch := make(chan res, len(ngProbeTargets)) // 带缓冲，提前返回时其余 goroutine 不会阻塞泄漏

	for _, addr := range ngProbeTargets {
		go func(addr string) {
			start := time.Now()
			var d net.Dialer
			conn, err := d.DialContext(pctx, "tcp", addr)
			if err != nil {
				ch <- res{}
				return
			}
			_ = conn.Close()
			ch <- res{rtt: time.Since(start), ok: true}
		}(addr)
	}

	for range ngProbeTargets {
		select {
		case r := <-ch:
			if r.ok {
				g.everOK.Store(true)
				return r.rtt, true
			}
		case <-pctx.Done():
			return 0, false
		}
	}
	return 0, false
}

// Start 校准基准 RTT 并启动后台探针，ctx 结束后探针自动停止。
// 若校准阶段所有探测都失败，说明探针目标在当前环境不可用，直接禁用保护（不影响检测）。
func (g *netGuard) Start(ctx context.Context) {
	if !g.running.CompareAndSwap(false, true) {
		return
	}

	var base time.Duration
	for range 3 {
		if rtt, ok := g.probe(ctx); ok && (base == 0 || rtt < base) {
			base = rtt
		}
	}
	if base == 0 {
		slog.Warn("本机网络探针不可用，已禁用拥塞保护")
		g.running.Store(false)
		return
	}
	g.baseRTT.Store(int64(base))
	g.degraded.Store(false)

	go func() {
		defer func() {
			g.running.Store(false)
			g.degraded.Store(false)
		}()

		ticker := time.NewTicker(ngProbeInterval)
		defer ticker.Stop()

		bad, good := 0, 0
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}

			rtt, ok := g.probe(ctx)
			if ctx.Err() != nil {
				return
			}
			if ok && rtt <= g.limit() {
				good++
				bad = 0
				// 连续 2 次正常才认为恢复，避免抖动
				if good >= 2 && g.degraded.CompareAndSwap(true, false) {
					slog.Info("本机网络已恢复，继续检测")
				}
				continue
			}

			bad++
			good = 0
			g.lastBad.Store(time.Now().UnixNano())
			// 连续 2 次异常才判定拥塞
			if bad >= 2 && g.degraded.CompareAndSwap(false, true) {
				slog.Warn("检测到本机网络拥塞（连接数或带宽过高），暂缓新任务并复核失败节点", "rtt", rtt, "ok", ok)
			}
		}
	}()
}

// Wait 在拥塞期间阻塞，直到恢复 / ctx 结束 / 超过 maxWait。
// 未启动探针或网络正常时立即返回 true；恢复后随机抖动一小段时间，避免大量 worker 同时恢复造成瞬时冲击。
func (g *netGuard) Wait(ctx context.Context, maxWait time.Duration) bool {
	if !g.running.Load() || !g.degraded.Load() {
		return true
	}
	deadline := time.Now().Add(maxWait)
	for g.running.Load() && g.degraded.Load() {
		if time.Now().After(deadline) {
			return false
		}
		select {
		case <-ctx.Done():
			return false
		case <-time.After(200 * time.Millisecond):
		}
	}
	select {
	case <-ctx.Done():
	case <-time.After(time.Duration(rand.Int64N(int64(800 * time.Millisecond)))):
	}
	return true
}

// BadSince 判断从 t 起到现在，本机网络是否出现过异常。
// 用于复核：节点测活失败期间本机网络有问题，则失败原因可能不在节点。
func (g *netGuard) BadSince(t time.Time) bool {
	if !g.running.Load() {
		return false
	}
	return g.degraded.Load() || g.lastBad.Load() >= t.UnixNano()
}

// WaitSettled 主动探测直到本机网络连续 2 次正常（不依赖后台探针），用于检测结束后、发送通知前。
// 探针目标在本环境从未成功过时不做等待，避免无谓延迟。最多等待 maxWait。
func (g *netGuard) WaitSettled(ctx context.Context, maxWait time.Duration) bool {
	deadline := time.Now().Add(maxWait)
	good, announced := 0, false
	for {
		rtt, ok := g.probe(ctx)
		if ok && rtt <= g.limit() {
			good++
			if good >= 2 {
				return true
			}
		} else {
			good = 0
			if !g.everOK.Load() {
				return false // 探针在本环境不可用
			}
			if !announced {
				slog.Info("本机网络尚未恢复，等待恢复后再继续", "rtt", rtt, "ok", ok)
				announced = true
			}
		}
		if time.Now().After(deadline) {
			slog.Warn("等待本机网络恢复超时，继续执行")
			return false
		}
		select {
		case <-ctx.Done():
			return false
		case <-time.After(500 * time.Millisecond):
		}
	}
}
