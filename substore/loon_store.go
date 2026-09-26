// sub-store\loon_store.go
package substore

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/goccy/go-json"
)

type LoonKVStore struct {
	mu        sync.RWMutex
	mainPath  string // 核心配置：sub-store.json
	cachePath string // 缓存文件：sub-store-cache.json
	cacheData map[string]string

	saveTimer *time.Timer
	saveMu    sync.Mutex
}

func NewLoonKVStore(mainPath string) (*LoonKVStore, error) {
	cachePath := filepath.Join(filepath.Dir(mainPath), "sub-store-cache.json")
	s := &LoonKVStore{
		mainPath:  mainPath,
		cachePath: cachePath,
		cacheData: make(map[string]string),
	}
	if err := os.MkdirAll(filepath.Dir(mainPath), 0o755); err != nil {
		return nil, fmt.Errorf("创建持久化存储目录失败: %w", err)
	}

	// 加载缓存
	if b, err := os.ReadFile(cachePath); err == nil {
		_ = json.Unmarshal(b, &s.cacheData)
	}
	return s, nil
}

func (s *LoonKVStore) Read(key string) any {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// 核心配置直接读取原版 JSON
	if key == "sub-store" {
		if b, err := os.ReadFile(s.mainPath); err == nil {
			return string(b)
		}
		return nil
	}

	// 缓存数据从内存秒读
	if v, ok := s.cacheData[key]; ok {
		return v
	}
	return nil
}

func (s *LoonKVStore) Write(value *string, key string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	// 1. 核心配置同步落盘，并做漂亮的美化
	if key == "sub-store" {
		if value == nil {
			os.Remove(s.mainPath)
			return true
		}
		var obj any
		if err := json.Unmarshal([]byte(*value), &obj); err == nil {
			if pretty, err := json.MarshalIndent(obj, "", "  "); err == nil {
				*value = string(pretty)
			}
		}
		tmp := s.mainPath + ".tmp"
		if err := os.WriteFile(tmp, []byte(*value), 0o644); err != nil {
			return false
		}
		return os.Rename(tmp, s.mainPath) == nil
	}

	// 2. 缓存数据仅操作内存，解决 Ubuntu IO 严重阻塞问题
	if value == nil {
		delete(s.cacheData, key)
	} else {
		s.cacheData[key] = *value
	}

	// 触发异步防抖落盘
	s.scheduleCacheSave()
	return true
}

// scheduleCacheSave 防抖机制：2秒内没有新的写入才会真正刷入磁盘
func (s *LoonKVStore) scheduleCacheSave() {
	s.saveMu.Lock()
	defer s.saveMu.Unlock()
	if s.saveTimer != nil {
		s.saveTimer.Stop()
	}
	s.saveTimer = time.AfterFunc(2*time.Second, func() {
		s.mu.RLock()
		b, err := json.Marshal(s.cacheData)
		s.mu.RUnlock()
		if err == nil {
			tmp := s.cachePath + ".tmp"
			if err := os.WriteFile(tmp, b, 0o644); err == nil {
				os.Rename(tmp, s.cachePath)
			}
		}
	})
}
