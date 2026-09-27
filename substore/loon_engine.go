// sub-store\loon_engine.go
package substore

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/goccy/go-json"
	"github.com/sinspired/subs-check-pro/v3/config"
	"github.com/sinspired/subs-check-pro/v3/utils"

	"github.com/buke/quickjs-go"
)

type LoonHTTPRequest struct {
	URL     string
	Method  string
	Headers map[string]string
	Body    string
}

type LoonHTTPResponse struct {
	Status  int
	Headers map[string]string
	Body    string
}

type netTiming struct {
	start                     time.Time
	total                     time.Duration
	dnsStart, dnsDone         time.Time
	connectStart, connectDone time.Time
	tlsStart, tlsDone         time.Time
	gotFirstByte              time.Time
}

func (t *netTiming) trace() *httptrace.ClientTrace {
	return &httptrace.ClientTrace{
		DNSStart:             func(httptrace.DNSStartInfo) { t.dnsStart = time.Now() },
		DNSDone:              func(httptrace.DNSDoneInfo) { t.dnsDone = time.Now() },
		ConnectStart:         func(string, string) { t.connectStart = time.Now() },
		ConnectDone:          func(string, string, error) { t.connectDone = time.Now() },
		TLSHandshakeStart:    func() { t.tlsStart = time.Now() },
		TLSHandshakeDone:     func(tls.ConnectionState, error) { t.tlsDone = time.Now() },
		GotFirstResponseByte: func() { t.gotFirstByte = time.Now() },
	}
}

type LoonEngine struct {
	scriptSrc  string
	store      *LoonKVStore
	scriptTag  string
	timeout    time.Duration
	logger     *slog.Logger
	httpClient *http.Client
	netDebug   bool

	bannerPrinted    atomic.Bool
	subStoreBytecode []byte
}

func NewLoonEngine(scriptSrc []byte, scriptTag string, store *LoonKVStore, logger *slog.Logger) (*LoonEngine, error) {
	if logger == nil {
		logger = slog.Default()
	}

	dialer := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second, Resolver: &net.Resolver{PreferGo: true}}
	transport := &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			if network == "tcp" || network == "tcp6" {
				network = "tcp4"
			}
			return dialer.DialContext(ctx, network, addr)
		},
		MaxIdleConns: 100, MaxIdleConnsPerHost: 100, IdleConnTimeout: 90 * time.Second, TLSHandshakeTimeout: 10 * time.Second,
	}

	httpClient := &http.Client{Timeout: 30 * time.Second, Transport: transport}

	rt := quickjs.NewRuntime()
	ctx := rt.NewContext()

	// 使用真实的 iPhone 及 Loon 参数，提高严苛机场订阅的拉取成功率
	bLoon, _ := json.Marshal(map[string]any{
		"deviceName":     "iPhone 16 Pro",
		"systemVersion":  "18.0",
		"loonVersion":    "3.2.1(750)",
		"build":          "750",
		"isSubsCheckPro": true,
		"backendName":    "Subs Check Pro",
	})

	bScript, _ := json.Marshal(map[string]any{"name": scriptTag, "startTime": time.Now().UnixMilli()})

	initScript := string(initScriptBytes)
	initScript = strings.Replace(initScript, "__LOON_JSON_OBJ__", string(bLoon), 1)
	initScript = strings.Replace(initScript, "__SCRIPT_JSON_OBJ__", string(bScript), 1)
	initScript = strings.Replace(initScript, "__SCRIPT_SRC__", string(scriptSrc), 1)

	bytecode, err := ctx.Compile(initScript)
	if err != nil {
		ctx.Close()
		rt.Close()
		return nil, fmt.Errorf("编译 Sub-Store 字节码失败: %w", err)
	}

	ctx.Close()
	rt.Close()

	engine := &LoonEngine{
		scriptSrc:        string(scriptSrc),
		store:            store,
		scriptTag:        scriptTag,
		timeout:          3 * time.Minute,
		logger:           logger,
		httpClient:       httpClient,
		netDebug:         os.Getenv("SUBSTORE_NET_DEBUG") == "1",
		subStoreBytecode: bytecode,
	}

	if engine.netDebug {
		engine.logger.Info("已开启 Sub-Store 网络诊断模式", "env", "SUBSTORE_NET_DEBUG=1")
	}

	return engine, nil
}

type loonResult struct {
	meta string
	body string
}

func (e *LoonEngine) Execute(execCtx context.Context, req *LoonHTTPRequest, argument string) (*LoonHTTPResponse, error) {
	execStart := time.Now()

	doneCh := make(chan loonResult, 1)
	failCh := make(chan error, 1)

	go func() {
		// 必须将此 Goroutine 绑定到固定的 OS 线程！
		// 否则 Go 调度器进行线程迁移时，会破坏 QuickJS 的 C 层栈边界检测，导致引擎卡死或崩溃。
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()

		rt := quickjs.NewRuntime()
		rt.SetMemoryLimit(512 * 1024 * 1024)
		rt.SetMaxStackSize(16 * 1024 * 1024)
		defer rt.Close()

		ctx := rt.NewContext()
		defer ctx.Close()

		defer func() {
			if r := recover(); r != nil {
				failCh <- fmt.Errorf("QuickJS 引擎崩溃 (已拦截): %v", r)
			}
		}()

		httpBodies := make(map[string]string)
		var httpBodiesMu sync.Mutex
		reqIdCounter := 0

		globals := ctx.Globals()

		globals.Set("__done", ctx.NewFunction(func(ctx *quickjs.Context, this *quickjs.Value, args []*quickjs.Value) *quickjs.Value {
			metaJson := "{}"
			if len(args) > 0 && !args[0].IsNull() && !args[0].IsUndefined() {
				metaJson = args[0].String()
			}
			bodyStr := ""
			if len(args) > 1 && !args[1].IsNull() && !args[1].IsUndefined() {
				bodyStr = args[1].String()
			}

			select {
			case doneCh <- loonResult{meta: metaJson, body: bodyStr}:
			default:
			}

			ctx.Eval(`if(globalThis.__resolve_done) globalThis.__resolve_done();`).Free()
			return ctx.Undefined()
		}))

		globals.Set("__ps_read", ctx.NewFunction(func(ctx *quickjs.Context, this *quickjs.Value, args []*quickjs.Value) *quickjs.Value {
			if len(args) == 0 {
				return ctx.Undefined()
			}
			val := e.store.Read(args[0].String())
			if val == nil {
				return ctx.Undefined()
			}
			str := fmt.Sprint(val)
			if str == "undefined" || str == "null" {
				return ctx.Undefined()
			}
			return ctx.String(str)
		}))

		globals.Set("__ps_write", ctx.NewFunction(func(ctx *quickjs.Context, this *quickjs.Value, args []*quickjs.Value) *quickjs.Value {
			if len(args) < 2 {
				return ctx.Undefined()
			}
			valArg := args[0]
			key := args[1].String()
			var valPtr *string
			str := valArg.String()
			if valArg.IsNull() || valArg.IsUndefined() || str == "undefined" || str == "null" {
				valPtr = nil
			} else {
				valPtr = &str
			}
			e.store.Write(valPtr, key)
			return ctx.Undefined()
		}))

		globals.Set("__notify_post", ctx.NewFunction(func(ctx *quickjs.Context, this *quickjs.Value, args []*quickjs.Value) *quickjs.Value {
			// 接管通知逻辑，将重要报错推送到日志面板
			if len(args) >= 3 {
				title := args[0].String()
				subtitle := args[1].String()
				content := args[2].String()
				e.logger.Info("🔔 [通知] "+title, "subtitle", subtitle, "content", content)

				// 接管推送逻辑
				pushConfig := config.GlobalConfig.SubStorePushService
				if pushConfig != "" {
					go func(cfg, t, st, c string) {
						// 拼接副标题和内容
						pushMsg := c
						if st != "" {
							pushMsg = st + "  \n" + c
						}

						// 1. 兼容原版 GET 替换模式 (如: https://api.day.app/XXX/[推送标题]/[推送内容])
						if strings.Contains(cfg, "[推送内容]") {
							finalURL := strings.Replace(cfg, "[推送标题]", url.PathEscape(t), 1)
							finalURL = strings.Replace(finalURL, "[推送内容]", url.PathEscape(pushMsg), 1)
							resp, err := http.Get(finalURL)
							if err == nil {
								defer resp.Body.Close()
							} else {
								e.logger.Warn("Sub-Store HTTP 推送失败", "err", err)
							}
							return
						}

						// 2. Apprise 模式
						var targetURLs string
						if strings.ToLower(strings.TrimSpace(cfg)) == "apprise" {
							// 填了 "apprise"，直接复用主程序中配好的接收渠道
							targetURLs = strings.Join(config.GlobalConfig.RecipientURL, ",")
						} else {
							// 填了单独的 Apprise URI (如 bark://xxx, tgram://xxx)
							targetURLs = cfg
						}

						if targetURLs == "" {
							return
						}

						// 组装 Apprise 请求并交由 utils 处理
						req := utils.NotifyRequest{
							URLs:   targetURLs,
							Body:   pushMsg,
							Title:  t,
							Format: "markdown",
						}

						// 直接调用 Notify 模块
						if err := utils.Notify(req, ""); err != nil {
							e.logger.Warn("Sub-Store Apprise 推送失败", "err", err)
						} else {
							e.logger.Debug("Sub-Store Apprise 推送成功")
						}
					}(pushConfig, title, subtitle, content)
				}
			}
			return ctx.Undefined()
		}))

		globals.Set("__console_log", ctx.NewFunction(func(ctx *quickjs.Context, this *quickjs.Value, args []*quickjs.Value) *quickjs.Value {
			if len(args) < 2 {
				return ctx.Undefined()
			}
			level, msg := args[0].String(), args[1].String()
			if strings.Contains(msg, "┅┅┅┅") || strings.Contains(msg, "Sub-Store -- v") {
				if e.bannerPrinted.CompareAndSwap(false, true) {
					e.logger.Info(msg)
				}
				return ctx.Undefined()
			}
			if strings.Contains(msg, "[CORS] allowed origins:") {
				return ctx.Undefined()
			}
			switch level {
			case "info":
				e.logger.Info(msg)
			case "warn":
				e.logger.Warn(msg)
			case "error":
				e.logger.Error(msg)
			default:
				e.logger.Debug(msg)
			}
			return ctx.Undefined()
		}))

		globals.Set("__go_http_request_async", ctx.NewFunction(func(ctx *quickjs.Context, this *quickjs.Value, args []*quickjs.Value) *quickjs.Value {
			if len(args) < 3 {
				return ctx.Undefined()
			}
			method, reqOptsJSON, jsReqId := args[0].String(), args[1].String(), args[2].String()

			type RequestOpts struct {
				URL          string            `json:"url"`
				Headers      map[string]string `json:"headers"`
				Body         string            `json:"body"`
				BodyB64      bool              `json:"body-base64"`
				BodyBase64   bool              `json:"bodyBase64"`
				Timeout      int               `json:"timeout"`
				AutoRedirect *bool             `json:"auto-redirect"`
				Redirection  *bool             `json:"redirection"`
				BinaryMode   bool              `json:"binary-mode"`
			}
			var opts RequestOpts
			_ = json.Unmarshal([]byte(reqOptsJSON), &opts)

			type ResponseObject struct {
				Status  int               `json:"status"`
				Headers map[string]string `json:"headers"`
			}
			type GoResult struct {
				Error    *string         `json:"error"`
				Response *ResponseObject `json:"response"`
				ReqId    string          `json:"reqId,omitempty"`
			}

			go func() {
				res := GoResult{}
				var bodyReader io.Reader
				if opts.Body != "" {
					if opts.BodyB64 || opts.BodyBase64 {
						if decoded, err := base64.StdEncoding.DecodeString(opts.Body); err == nil {
							bodyReader = bytes.NewReader(decoded)
						}
					} else {
						bodyReader = strings.NewReader(opts.Body)
					}
				}

				// 支持脚本自定超时，增加上限阻断死锁
				timeoutMs := 30000
				if opts.Timeout > 0 {
					timeoutMs = min(opts.Timeout, 300000)
				}
				reqCtx, cancel := context.WithTimeout(execCtx, time.Duration(timeoutMs)*time.Millisecond)
				defer cancel()

				httpReq, err := http.NewRequestWithContext(reqCtx, method, opts.URL, bodyReader)
				if err != nil {
					errStr := err.Error()
					res.Error = &errStr
				} else {
					for k, v := range opts.Headers {
						httpReq.Header.Set(k, v)
					}
					var timing *netTiming
					if e.netDebug {
						timing = &netTiming{start: time.Now()}
						httpReq = httpReq.WithContext(httptrace.WithClientTrace(httpReq.Context(), timing.trace()))
					}

					// 拦截重定向支持
					client := e.httpClient
					shouldRedirect := true
					if opts.AutoRedirect != nil {
						shouldRedirect = *opts.AutoRedirect
					} else if opts.Redirection != nil {
						shouldRedirect = *opts.Redirection
					}
					if !shouldRedirect {
						clientCopy := *client
						clientCopy.CheckRedirect = func(req *http.Request, via []*http.Request) error {
							return http.ErrUseLastResponse
						}
						client = &clientCopy
					}

					httpResp, err := client.Do(httpReq)
					if timing != nil {
						timing.total = time.Since(timing.start)
					}

					if err != nil {
						errStr := err.Error()
						res.Error = &errStr
					} else {
						defer httpResp.Body.Close()
						bodyBytes, _ := io.ReadAll(io.LimitReader(httpResp.Body, 64<<20))
						res.Response = &ResponseObject{
							Status:  httpResp.StatusCode,
							Headers: make(map[string]string),
						}
						for k, v := range httpResp.Header {
							res.Response.Headers[strings.ToLower(k)] = v[0]
						}

						// 处理二进制响应要求为 Base64
						var storeBodyStr string
						if opts.BinaryMode {
							storeBodyStr = base64.StdEncoding.EncodeToString(bodyBytes)
							res.Response.Headers["__is_binary__"] = "true" // 附加元数据标识
						} else {
							storeBodyStr = string(bodyBytes)
						}

						httpBodiesMu.Lock()
						reqIdCounter++
						reqId := fmt.Sprintf("req-%d", reqIdCounter)
						httpBodies[reqId] = storeBodyStr
						httpBodiesMu.Unlock()

						res.ReqId = reqId
					}
				}
				resBytes, _ := json.Marshal(res)
				ctx.Schedule(func(inner *quickjs.Context) {
					dispatchCode := fmt.Sprintf(`__dispatch_http_response("%s", %s);`, jsReqId, strconv.Quote(string(resBytes)))
					resVal := inner.Eval(dispatchCode)
					resVal.Free()
				})
			}()
			return ctx.Undefined()
		}))

		globals.Set("__go_http_request_body", ctx.NewFunction(func(ctx *quickjs.Context, this *quickjs.Value, args []*quickjs.Value) *quickjs.Value {
			if len(args) == 0 {
				return ctx.Undefined()
			}
			reqId := args[0].String()
			httpBodiesMu.Lock()
			bodyStr, exists := httpBodies[reqId]
			if exists {
				delete(httpBodies, reqId)
			}
			httpBodiesMu.Unlock()
			if exists {
				return ctx.String(bodyStr)
			}
			return ctx.Null()
		}))

		reqMap := map[string]any{"url": req.URL, "method": req.Method, "headers": req.Headers}
		if req.Body != "" {
			reqMap["body"] = req.Body
		}
		bReq, _ := json.Marshal(reqMap)

		globals.Set("__req_json", ctx.String(string(bReq)))
		globals.Set("__arg_str", ctx.String(argument))

		scriptStart := time.Now()

		bytecodeVal := ctx.EvalBytecode(e.subStoreBytecode)
		if bytecodeVal.IsException() {
			err := ctx.Exception()
			failCh <- fmt.Errorf("执行字节码异常: %w", err)
			bytecodeVal.Free()
			return
		}
		bytecodeVal.Free()

		runScript := `
		new Promise((resolve, reject) => {
			globalThis.__resolve_done = resolve;
			setTimeout(() => { reject(new Error("Sub-Store script timeout inside QuickJS")); }, 179000); // 放宽至将近 3 分钟
			try {
				$request = JSON.parse(__req_json);
				$argument = __arg_str;
				__run_sub_store_script();
			} catch (e) {
				reject(e);
			}
		});
		`
		promiseVal := ctx.Eval(runScript)
		if promiseVal.IsException() {
			err := ctx.Exception()
			failCh <- fmt.Errorf("执行入口脚本失败: %w", err)
			promiseVal.Free()
			return
		}

		resVal := ctx.Await(promiseVal)
		promiseVal.Free()

		if resVal.IsException() {
			err := ctx.Exception()
			failCh <- fmt.Errorf("脚本执行或回调崩溃: %w", err)
			resVal.Free()
			return
		}
		resVal.Free()

		if e.netDebug {
			e.logger.Info("脚本内部执行耗时分析", "scriptMs", time.Since(scriptStart).Milliseconds())
		}
	}()

	var resp *LoonHTTPResponse
	var retErr error

	select {
	case res := <-doneCh:
		resp = parseLoonResponse(res.meta, res.body)
	case err := <-failCh:
		retErr = err
	case <-execCtx.Done():
		retErr = execCtx.Err()
	case <-time.After(e.timeout):
		retErr = fmt.Errorf("Sub-Store 脚本执行超时 (%v)", e.timeout)
	}

	if e.netDebug {
		e.logger.Info("请求端到端耗时诊断", "url", req.URL, "totalMs", time.Since(execStart).Milliseconds())
	}

	return resp, retErr
}

func parseLoonResponse(metaJson string, bodyStr string) *LoonHTTPResponse {
	resp := &LoonHTTPResponse{Status: 200, Headers: map[string]string{}}

	type rawResp struct {
		Status     *int              `json:"status"`
		StatusCode *int              `json:"statusCode"`
		Headers    map[string]string `json:"headers"`
	}
	type rawLoon struct {
		Response *rawResp `json:"response"`
		rawResp
	}

	var obj rawLoon
	if err := json.Unmarshal([]byte(metaJson), &obj); err == nil {
		target := &obj.rawResp
		if obj.Response != nil {
			target = obj.Response
		}

		if target.Status != nil {
			resp.Status = *target.Status
		} else if target.StatusCode != nil {
			resp.Status = *target.StatusCode
		}

		if target.Headers != nil {
			resp.Headers = target.Headers
		}
	}

	resp.Body = bodyStr
	return resp
}
