// sub-store\loon_server.go
package substore

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"github.com/goccy/go-json"
	"github.com/robfig/cron/v3"
	"github.com/sinspired/subs-check-pro/v3/config"
)

// LoonServer 现在只持有单个 engine
// engine 用 atomic.Pointer 存放，支持资产更新后不重启进程即可热替换。
type LoonServer struct {
	engine      atomic.Pointer[LoonEngine]
	frontendDir string
	backendPath string
	httpServer  *http.Server
}

func NewLoonServer(addr string, engine *LoonEngine, frontendDir, backendPath string) *LoonServer {
	s := &LoonServer{
		frontendDir: frontendDir,
		backendPath: backendPath,
	}
	s.engine.Store(engine)
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handle)
	s.httpServer = &http.Server{Addr: addr, Handler: mux}
	return s
}

// UpdateEngine 用新引擎原子替换旧引擎，旧引擎里尚未完成的请求继续用旧的执行
func (s *LoonServer) UpdateEngine(e *LoonEngine) {
	s.engine.Store(e)
}

func (s *LoonServer) handle(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept, Authorization")
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	host := strings.Split(r.Host, ":")[0]
	path := r.URL.Path

	isBackend := false

	// 规则 A：匹配配置的安全后端前缀
	if s.backendPath != "" && strings.HasPrefix(path, s.backendPath) {
		isBackend = true
	}
	// 规则 B：匹配 sub.store 局域网/代理环境劫持
	if host == "sub.store" {
		if strings.HasPrefix(path, "/api/") || strings.HasPrefix(path, "/download/") {
			isBackend = true
		}
	}

	if isBackend {
		s.handleBackend(w, r)
		return
	}

	s.handleFrontend(w, r)
}

func (s *LoonServer) handleBackend(w http.ResponseWriter, r *http.Request) {
	bodyBytes, err := io.ReadAll(io.LimitReader(r.Body, 30<<20))
	if err != nil {
		http.Error(w, "读取请求体失败", http.StatusBadRequest)
		return
	}

	headers := make(map[string]string, len(r.Header))
	for k, v := range r.Header {
		headers[k] = strings.Join(v, ", ")
	}

	// 剥离安全前缀，构造供脚本内部路由匹配的路径 (如 /api/sync)
	strippedPath := strings.TrimPrefix(r.URL.Path, s.backendPath)
	if strippedPath == "" || !strings.HasPrefix(strippedPath, "/") {
		strippedPath = "/" + strippedPath
	}

	// 动态判断 Scheme (兼容 TLS 和 Nginx 等反向代理)
	scheme := "http"
	if r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https" {
		scheme = "https"
	}

	// 3. 构造完整 URL：依赖真实请求的 r.Host
	fullURL := scheme + "://" + r.Host + strippedPath
	if r.URL.RawQuery != "" {
		fullURL += "?" + r.URL.RawQuery
	}

	req := &LoonHTTPRequest{
		URL:     fullURL,
		Method:  r.Method,
		Headers: headers,
		Body:    string(bodyBytes),
	}

	// 4. 处理跨域 Origin 标识
	origin := r.Header.Get("Origin")
	if origin == "" {
		origin = scheme + "://" + r.Host
	}
	argument := "cors=" + url.QueryEscape(origin)

	resp, err := s.engine.Load().Execute(r.Context(), req, argument)
	if err != nil {
		slog.Error("Sub-Store 脚本执行失败", "error", err, "url", fullURL)
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(err.Error()))
		return
	}

	if strings.Contains(req.URL, "/api/utils/env") {
		var envData map[string]any
		if err := json.Unmarshal([]byte(resp.Body), &envData); err == nil {
			if data, ok := envData["data"].(map[string]any); ok {
				meta, _ := data["meta"].(map[string]any)
				if meta == nil {
					meta = make(map[string]any)
					data["meta"] = meta
				}
				node, _ := meta["node"].(map[string]any)
				if node == nil {
					node = make(map[string]any)
					meta["node"] = node
				}
				envMap, _ := node["env"].(map[string]any)
				if envMap == nil {
					envMap = make(map[string]any)
					node["env"] = envMap
				}

				// 设置后端名称和图标
				envMap["SUB_STORE_BACKEND_CUSTOM_NAME"] = "Subs Check Pro"
				envMap["SUB_STORE_BACKEND_CUSTOM_ICON"] = "/scp/scp-app.svg"

				// 注入配置变量
				envMap["SUB_STORE_FRONTEND_BACKEND_PATH"] = config.GlobalConfig.SubStorePath
				if config.GlobalConfig.SubStoreSyncCron != "" {
					envMap["SUB_STORE_BACKEND_SYNC_CRON"] = config.GlobalConfig.SubStoreSyncCron
				}
				if config.GlobalConfig.SubStoreProduceCron != "" {
					envMap["SUB_STORE_PRODUCE_CRON"] = config.GlobalConfig.SubStoreProduceCron
				}
				if config.GlobalConfig.SubStorePushService != "" {
					envMap["SUB_STORE_PUSH_SERVICE"] = config.GlobalConfig.SubStorePushService
				}
				envMap["SUB_STORE_BODY_JSON_LIMIT"] = "30mb"
				envMap["SUB_STORE_CORS_ALLOWED_ORIGINS"] = "*"

				if modifiedBody, err := json.Marshal(envData); err == nil {
					resp.Body = string(modifiedBody)
				}
			}
		}
	}

	for k, v := range resp.Headers {
		if strings.EqualFold(k, "Content-Length") || strings.EqualFold(k, "Transfer-Encoding") {
			continue
		}
		w.Header().Set(k, v)
	}
	status := resp.Status
	if status == 0 {
		status = http.StatusOK
	}
	w.WriteHeader(status)
	_, _ = w.Write([]byte(resp.Body))
}

func (s *LoonServer) handleFrontend(w http.ResponseWriter, r *http.Request) {
	root, err := filepath.Abs(s.frontendDir)
	if err != nil {
		http.Error(w, "前端资源目录不可用", http.StatusInternalServerError)
		return
	}
	rel := strings.TrimPrefix(r.URL.Path, "/")
	requested := filepath.Join(root, filepath.FromSlash(rel))
	absRequested, err := filepath.Abs(requested)
	if err != nil || !strings.HasPrefix(absRequested, root) {
		http.Error(w, "非法路径", http.StatusForbidden)
		return
	}

	// 拦截逻辑：防止逃逸到官方前端，非法路径强行打回 /
	stat, err := os.Stat(absRequested)
	if os.IsNotExist(err) || (err == nil && stat.IsDir()) {
		if r.URL.Path != "/" && r.URL.Path != "/index.html" {
			http.Redirect(w, r, "/", http.StatusFound)
			return
		}
		http.ServeFile(w, r, filepath.Join(root, "index.html"))
		return
	}

	http.ServeFile(w, r, absRequested)
}

func (s *LoonServer) Start() error {
	ln, err := net.Listen("tcp", s.httpServer.Addr)
	if err != nil {
		return err
	}
	go func() {
		if err := s.httpServer.Serve(ln); err != nil && err != http.ErrServerClosed {
			slog.Error("Sub-Store(SCP) 服务异常退出", "error", err)
		}
	}()

	// 自己给自己发个 OPTIONS 请求，收到回复才算真正的完全启动
	tcpAddr, ok := ln.Addr().(*net.TCPAddr)
	if ok {
		client := &http.Client{Timeout: 100 * time.Millisecond}
		probeURL := fmt.Sprintf("http://127.0.0.1:%d/", tcpAddr.Port)

		started := false
		for i := 0; i < 20 && !started; i++ {
			req, _ := http.NewRequest(http.MethodOptions, probeURL, nil)
			if resp, err := client.Do(req); err == nil {
				resp.Body.Close()
				started = true
				break
			}
			time.Sleep(50 * time.Millisecond)
		}
		if !started {
			s.httpServer.Close()
			return fmt.Errorf("HTTP 引擎探活超时，服务无法响应")
		}
	}
	return nil // 返回 nil 说明端口已通
}

func (s *LoonServer) Shutdown(ctx context.Context) error {
	return s.httpServer.Shutdown(ctx)
}

// StartSubStoreCronJobs 解析配置并启动定时任务
// 返回 *cron.Cron 以便在外层通过 defer 优雅关闭
func StartSubStoreCronJobs(serverPort string, backendPath string) *cron.Cron {
	c := cron.New()

	apiBase := fmt.Sprintf("http://127.0.0.1:%s%s", serverPort, backendPath)
	hasTask := false

	// 1. 同步 Gist 任务: sub-store-sync-cron
	syncCron := strings.TrimSpace(config.GlobalConfig.SubStoreSyncCron)
	if syncCron != "" {
		_, err := c.AddFunc(syncCron, func() {
			slog.Debug("触发定时任务: 同步 Sub-Store 配置 (Sync)")

			resp, err := http.Get(apiBase + "/api/sync")
			if err != nil {
				slog.Error("❌ 定时同步请求失败", "err", err)
				return
			}
			defer resp.Body.Close()

			slog.Debug(
				"定时同步任务执行完毕",
				"status",
				resp.StatusCode,
			)
		})

		if err != nil {
			slog.Error(
				"解析 Sync Cron 配置失败",
				"err",
				err,
				"expr",
				syncCron,
			)
		} else {
			hasTask = true
		}
	}

	// 2. 更新订阅任务: sub-store-produce-cron
	produceCronStr := strings.TrimSpace(config.GlobalConfig.SubStoreProduceCron)
	if produceCronStr != "" {
		tasks := strings.SplitSeq(produceCronStr, ";")

		for task := range tasks {
			task = strings.TrimSpace(task)
			if task == "" {
				continue
			}

			parts := strings.SplitN(task, ",", 3)
			if len(parts) != 3 {
				slog.Error(
					"Sub-Store Produce Cron 配置格式错误",
					"task",
					task,
				)
				continue
			}

			cronExpr := strings.TrimSpace(parts[0])
			targetType := strings.TrimSpace(parts[1]) // sub 或 col
			targetName := strings.TrimSpace(parts[2]) // 订阅名

			// 明确复制到局部变量，避免闭包捕获循环变量问题
			expr := cronExpr
			typ := targetType
			name := targetName

			_, err := c.AddFunc(expr, func() {
				slog.Debug(
					"触发定时任务: 处理订阅 (缓存)",
					"type",
					typ,
					"name",
					name,
				)

				var targetURL string

				if typ == "col" {
					targetURL = fmt.Sprintf(
						"%s/download/collection/%s",
						apiBase,
						url.PathEscape(name),
					)
				} else {
					targetURL = fmt.Sprintf(
						"%s/download/%s",
						apiBase,
						url.PathEscape(name),
					)
				}

				resp, err := http.Get(targetURL)
				if err != nil {
					slog.Error(
						"❌ 定时缓存任务请求失败",
						"name",
						name,
						"err",
						err,
					)
					return
				}
				defer resp.Body.Close()

				slog.Debug(
					"定时缓存任务执行完毕",
					"name",
					name,
					"status",
					resp.StatusCode,
				)
			})

			if err != nil {
				slog.Error(
					"解析 Produce Cron 配置失败",
					"err",
					err,
					"expr",
					expr,
				)
			} else {
				hasTask = true
			}
		}
	}

	if hasTask {
		c.Start()
		slog.Info("Sub-Store 定时任务", "Gist同步", syncCron, "订阅缓存", produceCronStr)
		return c
	}

	return nil
}
