// sub-store\update_substore_assets.go
package substore

import (
	"archive/zip"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/buke/quickjs-go"
	"github.com/goccy/go-json"
	"github.com/sinspired/subs-check-pro/v3/config"
	"github.com/sinspired/subs-check-pro/v3/utils"
)

const subStoreAssetName = "sub-store.min.js"

// SubStoreUpdateResult 包含了 Sub-Store 资产更新的结果信息
type SubStoreUpdateResult struct {
	UpdatedBackend  bool
	UpdatedFrontend bool
	NewBackendVer   string
	NewFrontendVer  string
}

// 进度条追踪器
type progressReader struct {
	io.Reader
	total    int64
	current  int64
	title    string
	lastStr  string
	finished bool
}

func (pr *progressReader) Read(p []byte) (int, error) {
	n, err := pr.Reader.Read(p)
	pr.current += int64(n)
	pr.printProgress(err == io.EOF)
	return n, err
}

func (pr *progressReader) printProgress(isEOF bool) {
	if !config.GlobalConfig.PrintProgress || pr.total <= 0 || pr.finished {
		return
	}
	percent := float64(pr.current) / float64(pr.total) * 100
	if percent > 100 {
		percent = 100
	}

	barWidth := 40
	barFilled := int(percent / 100 * float64(barWidth))
	bar := strings.Repeat("=", barFilled)
	if barFilled < barWidth {
		bar += ">" + strings.Repeat(" ", barWidth-barFilled-1)
	}

	curKB, totKB := pr.current/1024, pr.total/1024
	str := fmt.Sprintf("\r\033[K%s: [%s] %.1f%% (%dKB/%dKB)", pr.title, bar, percent, curKB, totKB)

	if str != pr.lastStr {
		fmt.Print(str)
		pr.lastStr = str
	}

	if isEOF || pr.current >= pr.total {
		fmt.Println()
		pr.finished = true
	}
}

// subStoreUpdater 封装了显式指定代理的 HTTP 客户端
type subStoreUpdater struct {
	proxyClient  *http.Client
	directClient *http.Client
	useSysProxy  bool

	ghProxyChecked bool
	useGhProxy     bool
}

func newSubStoreUpdater() *subStoreUpdater {
	directTransport := http.DefaultTransport.(*http.Transport).Clone()
	directTransport.Proxy = nil
	directTransport.DialContext = dialContext
	directTransport.ResponseHeaderTimeout = 20 * time.Second

	proxyTransport := directTransport.Clone()
	useSysProxy := utils.GetSysProxy()

	if useSysProxy {
		if proxyURL, err := url.Parse(config.GlobalConfig.SystemProxy); err == nil && proxyURL.String() != "" {
			proxyTransport.Proxy = http.ProxyURL(proxyURL)
		} else {
			slog.Warn("代理 URL 解析失败或为空，退化为直连", "url", config.GlobalConfig.SystemProxy)
			useSysProxy = false
			proxyTransport.Proxy = nil
		}
	}

	return &subStoreUpdater{
		proxyClient:  &http.Client{Transport: proxyTransport, Timeout: 3 * time.Minute},
		directClient: &http.Client{Transport: directTransport, Timeout: 3 * time.Minute},
		useSysProxy:  useSysProxy,
	}
}

func (u *subStoreUpdater) getGhProxy() bool {
	if !u.ghProxyChecked {
		u.useGhProxy = utils.GetGhProxy()
		u.ghProxyChecked = true
	}
	return u.useGhProxy
}

func (u *subStoreUpdater) doRequest(targetURL string) (*http.Response, error) {
	token := config.GlobalConfig.GithubToken
	hasValidToken := utils.IsValidGitHubToken(token)

	rawURL := targetURL
	warpedURL := targetURL
	if !strings.Contains(targetURL, "api.github.com") {
		warpedURL = utils.WarpURL(targetURL, u.getGhProxy())
	}

	type strategy struct {
		name   string
		client *http.Client
		url    string
	}
	var strategies []strategy

	if u.useSysProxy {
		if hasValidToken {
			strategies = append(strategies, strategy{"系统代理", u.proxyClient, rawURL})
			if warpedURL != rawURL {
				strategies = append(strategies, strategy{"直连ᴳ", u.directClient, warpedURL})
			}
			strategies = append(strategies, strategy{"直连", u.directClient, rawURL})
		} else {
			if warpedURL != rawURL {
				strategies = append(strategies, strategy{"直连ᴳ", u.directClient, warpedURL})
			} else {
				strategies = append(strategies, strategy{"直连ᶠ", u.directClient, rawURL})
			}
			strategies = append(strategies, strategy{"系统代理ᶠ", u.proxyClient, rawURL})
		}
	} else {
		if warpedURL != rawURL {
			strategies = append(strategies, strategy{"直连ᴳ", u.directClient, warpedURL})
		}
		strategies = append(strategies, strategy{"直连", u.directClient, rawURL})
	}

	var lastErr error
	var lastStatus int

	for i, st := range strategies {
		req, err := http.NewRequest("GET", st.url, nil)
		if err != nil {
			lastErr = fmt.Errorf("创建请求失败: %w", err)
			continue
		}

		if hasValidToken {
			utils.InjectGitHubToken(req, token)
		}

		resp, err := st.client.Do(req)

		if err == nil && resp.StatusCode == http.StatusOK {
			return resp, nil
		}

		if err != nil {
			lastErr = err
		} else {
			lastErr = fmt.Errorf("HTTP %d", resp.StatusCode)
			lastStatus = resp.StatusCode
			resp.Body.Close()
		}

		if i < len(strategies)-1 {
			slog.Warn("请求失败，触发重试",
				"当前", st.name,
				"切换至", strategies[i+1].name,
			)
			slog.Debug("Fallback 详情", "url", st.url, "error", lastErr)
		}
	}

	errMsg := fmt.Sprintf("请求失败 (url: %s, 最终错误: %v)", targetURL, lastErr)
	if lastStatus != 0 {
		errMsg += fmt.Sprintf(" (状态码: %d)", lastStatus)
	}

	return nil, errors.New(errMsg)
}

// UpdateSubStoreAssets 检查并自动更新 Sub-Store 前后端
func UpdateSubStoreAssets() (*SubStoreUpdateResult, error) {
	paths, err := getSubStorePaths()
	if err != nil {
		return nil, fmt.Errorf("获取路径失败: %w", err)
	}

	updater := newSubStoreUpdater()
	result := &SubStoreUpdateResult{}
	var errs []string

	// 定义后端版本号文件路径，和 JS 处于同一目录
	backendVerPath := filepath.Join(filepath.Dir(paths.jsPath), "backend.version")
	// 允许文件不存在，TrimSpace 用来容忍末尾隐藏换行符导致的版本解析错误
	localBVerBytes, _ := os.ReadFile(backendVerPath)

	updBackend, newBVer, errB := updater.updateComponent(
		"后端", "sub-store-org/Sub-Store", subStoreAssetName, strings.TrimSpace(string(localBVerBytes)),
		func(dlURL, version string) error {
			if err := updater.downloadFile(dlURL, paths.jsPath, "下载后端"); err != nil {
				return err
			}
			// 下载成功后，写入 backend.version
			return os.WriteFile(backendVerPath, []byte(version), 0644)
		},
	)
	if errB != nil {
		errs = append(errs, errB.Error())
	} else {
		result.UpdatedBackend = updBackend
		result.NewBackendVer = newBVer
	}

	// 更新完毕，触发后端热重载应用
	if result.UpdatedBackend {
		if err := ReloadSubStoreEngine(); err != nil {
			slog.Error("Sub-Store 后端热重载失败，需重启进程后才能生效", "error", err)
			errs = append(errs, fmt.Sprintf("后端热重载失败: %v", err))
		}
	}

	localFVerBytes, _ := os.ReadFile(filepath.Join(paths.frontDir, "frontend.version"))
	updFront, newFVer, errF := updater.updateComponent(
		"前端", "sub-store-org/Sub-Store-Front-End", "dist.zip", strings.TrimSpace(string(localFVerBytes)),
		func(dlURL, version string) error {
			if err := updater.extractRemoteZipToPath(dlURL, paths.frontDir, "下载前端"); err != nil {
				return err
			}
			return os.WriteFile(filepath.Join(paths.frontDir, "frontend.version"), []byte(version), 0644)
		},
	)
	if errF != nil {
		errs = append(errs, errF.Error())
	} else {
		result.UpdatedFrontend = updFront
		result.NewFrontendVer = newFVer
	}

	if len(errs) > 0 {
		return result, errors.New(strings.Join(errs, "；"))
	}

	return result, nil
}

func (u *subStoreUpdater) updateComponent(name, repo, assetName, localVerRaw string, downloadAction func(dlURL, tag string) error) (bool, string, error) {
	tag, dlURL, err := u.getLatestRelease(repo, assetName)
	if err != nil {
		err = fmt.Errorf("获取 Sub-Store %s 版本失败: %w", name, err)
		slog.Error(err.Error())
		return false, "", err
	}

	localVer, remoteVer := parseVersion(localVerRaw), parseVersion(tag)
	if remoteVer == nil || (localVer != nil && !remoteVer.GreaterThan(localVer)) {
		return false, "", nil
	}

	slog.Info(fmt.Sprintf("Sub-Store %s 有新版", name), "local", localVer, "remote", tag)

	if err := downloadAction(dlURL, tag); err != nil {
		err = fmt.Errorf("更新 Sub-Store %s 失败: %w", name, err)
		slog.Error(err.Error())
		return false, "", err
	}

	slog.Info(fmt.Sprintf("Sub-Store %s 已更新", name), "version", tag)
	return true, tag, nil
}

func (u *subStoreUpdater) getLatestRelease(repo string, assetName string) (string, string, error) {
	apiBase := "https://api.github.com"
	if config.GlobalConfig.GithubAPIMirror != "" {
		apiBase = strings.TrimRight(config.GlobalConfig.GithubAPIMirror, "/")
	}
	apiURL := fmt.Sprintf("%s/repos/%s/releases/latest", apiBase, repo)

	resp, err := u.doRequest(apiURL)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()

	var rel struct {
		TagName string `json:"tag_name"`
		Assets  []struct {
			Name string `json:"name"`
			URL  string `json:"browser_download_url"`
		} `json:"assets"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&rel); err != nil {
		return "", "", err
	}

	for _, asset := range rel.Assets {
		if asset.Name == assetName {
			return rel.TagName, asset.URL, nil
		}
	}
	return "", "", fmt.Errorf("未找到对应的资源文件: %s", assetName)
}

func (u *subStoreUpdater) downloadFile(rawURL, path, title string) error {
	resp, err := u.doRequest(rawURL)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// 使用 .tmp 后缀进行下载替换原子化
	// 避免断网/下载失败时提前清空了原后端文件导致 Sub-Store JS 运行环境受损崩溃
	tmpPath := path + ".tmp"
	outFile, err := os.Create(tmpPath)
	if err != nil {
		return err
	}

	_, err = io.Copy(outFile, &progressReader{Reader: resp.Body, total: resp.ContentLength, title: title})
	outFile.Close() // 必须先释放文件句柄

	if err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("下载进度中断: %w", err)
	}

	// 通过 QuickJS 预编译验证脚本未损坏
	scriptBytes, readErr := os.ReadFile(tmpPath)
	if readErr == nil {
		rt := quickjs.NewRuntime()
		ctx := rt.NewContext()
		// 尝试编译，仅做语法分析不执行，开销极低
		_, compileErr := ctx.Compile(string(scriptBytes))
		ctx.Close()
		rt.Close()

		if compileErr != nil {
			_ = os.Remove(tmpPath)
			return fmt.Errorf("下载的脚本存在语法错误或已损坏，拒绝替换: %w", compileErr)
		}
	}

	// 成功且语法无误后，进行原子化覆写
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("替换新版本失败: %w", err)
	}
	return nil
}

func (u *subStoreUpdater) extractRemoteZipToPath(rawURL string, targetDir string, title string) error {
	resp, err := u.doRequest(rawURL)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// Android 的 os.TempDir() 应用无写权限，临时文件放在应用自己的数据目录
	parentDir := filepath.Dir(targetDir)
	if err := os.MkdirAll(parentDir, 0o755); err != nil {
		return fmt.Errorf("创建前端上级目录失败: %w", err)
	}
	tmpFile, err := os.CreateTemp(parentDir, "substore-front-*.zip")
	if err != nil {
		return err
	}
	tmpName := tmpFile.Name()
	defer os.Remove(tmpName)

	_, err = io.Copy(tmpFile, &progressReader{Reader: resp.Body, total: resp.ContentLength, title: title})
	tmpFile.Close()
	if err != nil {
		return fmt.Errorf("下载 ZIP 失败: %w", err)
	}

	return installFrontendZip(tmpName, targetDir)
}

// installFrontendZip 把前端 zip（内含 dist/ 目录）安装到 targetDir。
// 拆成独立函数以便脱离网络做单元测试。
func installFrontendZip(zipPath, targetDir string) error {
	zipReader, err := zip.OpenReader(zipPath)
	if err != nil {
		return fmt.Errorf("解析 ZIP 失败: %w", err)
	}
	defer zipReader.Close()

	// 先解压到暂存目录，成功后再整体替换，失败不影响现有前端
	stageDir := targetDir + ".new"
	oldDir := targetDir + ".old"
	_ = os.RemoveAll(stageDir)
	_ = os.RemoveAll(oldDir)
	defer os.RemoveAll(stageDir) // 成功时 stageDir 已被改名，这里是 no-op；失败时负责清理

	cleanStageDir := filepath.Clean(stageDir) + string(os.PathSeparator)
	extracted := 0
	for _, f := range zipReader.File {
		if !strings.HasPrefix(f.Name, "dist/") || strings.TrimPrefix(f.Name, "dist/") == "" {
			continue
		}

		targetPath := filepath.Join(stageDir, filepath.FromSlash(strings.TrimPrefix(f.Name, "dist/")))
		if !strings.HasPrefix(targetPath, cleanStageDir) {
			return fmt.Errorf("非法的文件路径穿越: %s", targetPath)
		}

		if f.FileInfo().IsDir() {
			_ = os.MkdirAll(targetPath, 0o755)
			continue
		}

		_ = os.MkdirAll(filepath.Dir(targetPath), 0o755)
		if err := extractZipFile(f, targetPath); err != nil {
			return err
		}
		extracted++
	}
	if extracted == 0 {
		return fmt.Errorf("ZIP 中没有找到 dist/ 目录下的前端文件，已保留现有前端")
	}

	// scp/ 是本程序自带的图标资源，不在前端 zip 里，需带到新目录
	scpOld, scpNew := filepath.Join(targetDir, "scp"), filepath.Join(stageDir, "scp")
	scpMoved := false
	if _, err := os.Stat(scpOld); err == nil {
		if _, err := os.Stat(scpNew); os.IsNotExist(err) {
			scpMoved = os.Rename(scpOld, scpNew) == nil
		}
	}
	restoreScp := func() {
		if scpMoved {
			_ = os.Rename(scpNew, scpOld)
		}
	}

	if _, err := os.Stat(targetDir); err == nil {
		if err := os.Rename(targetDir, oldDir); err != nil {
			restoreScp()
			return fmt.Errorf("备份旧前端目录失败: %w", err)
		}
	}
	if err := os.Rename(stageDir, targetDir); err != nil {
		_ = os.Rename(oldDir, targetDir) // 回滚旧前端
		restoreScp()
		return fmt.Errorf("切换到新前端目录失败: %w", err)
	}
	_ = os.RemoveAll(oldDir)
	return nil
}

func extractZipFile(f *zip.File, targetPath string) error {
	rc, err := f.Open()
	if err != nil {
		return err
	}
	defer rc.Close()

	outFile, err := os.OpenFile(targetPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.Mode())
	if err != nil {
		return err
	}
	defer outFile.Close()

	_, err = io.Copy(outFile, rc)
	return err
}
