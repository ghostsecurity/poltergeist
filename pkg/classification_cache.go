package poltergeist

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

const classificationCacheLimit = 64 * 1024 * 1024

type classificationCache struct {
	dir string
	key []byte
	mu  sync.Mutex
}
type cacheEntry struct {
	Policy        string    `json:"policy"`
	Created       time.Time `json:"created"`
	Model         string    `json:"model"`
	Probabilities []float64 `json:"probabilities"`
}

// Initialization uses an atomic hard-link publication: another process can
// never observe a partly written key, or silently replace an existing key.
func openClassificationCache(dir string) *classificationCache {
	if os.MkdirAll(dir, 0700) != nil {
		return nil
	}
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return nil
	}
	keyPath := filepath.Join(dir, ".key")
	key, err := readPrivateCacheFile(keyPath, 32)
	if os.IsNotExist(err) {
		fresh := make([]byte, 32)
		if _, err = rand.Read(fresh); err != nil {
			return nil
		}
		temp, tempErr := os.CreateTemp(dir, ".key-*")
		if tempErr != nil {
			return nil
		}
		name := temp.Name()
		defer func() { _ = os.Remove(name) }()
		if _, err = temp.Write(fresh); err != nil {
			_ = temp.Close()
			return nil
		}
		if temp.Close() != nil {
			return nil
		}
		// Link fails safely when a concurrent initializer has already published.
		_ = os.Link(name, keyPath)
		key, err = readPrivateCacheFile(keyPath, 32)
	}
	if err != nil || len(key) != 32 {
		return nil
	}
	return &classificationCache{dir: dir, key: key}
}
func readPrivateCacheFile(path string, limit int) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > int64(limit) {
		return nil, os.ErrPermission
	}
	return os.ReadFile(path)
}
func (c *classificationCache) name(identity []byte) string {
	h := hmac.New(sha256.New, c.key)
	_, _ = h.Write(identity)
	return filepath.Join(c.dir, hex.EncodeToString(h.Sum(nil))+".json")
}
func (c *classificationCache) get(ctx context.Context, identity []byte, model string, count int) (ClassificationBatchResult, bool) {
	if ctx.Err() != nil {
		return ClassificationBatchResult{}, false
	}
	data, err := readPrivateCacheFile(c.name(identity), 16*1024)
	if err != nil {
		return ClassificationBatchResult{}, false
	}
	var entry cacheEntry
	if json.Unmarshal(data, &entry) != nil || entry.Policy != ClassificationPolicyVersion || entry.Model != model || len(entry.Probabilities) != count || time.Since(entry.Created) < 0 || time.Since(entry.Created) >= 24*time.Hour {
		return ClassificationBatchResult{}, false
	}
	for _, p := range entry.Probabilities {
		if !validProbability(p) {
			return ClassificationBatchResult{}, false
		}
	}
	return ClassificationBatchResult{Model: model, Probabilities: entry.Probabilities, Source: "cache"}, true
}
func (c *classificationCache) put(ctx context.Context, identity []byte, result ClassificationBatchResult) {
	if ctx.Err() != nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	data, err := json.Marshal(cacheEntry{ClassificationPolicyVersion, time.Now(), result.Model, result.Probabilities})
	if err != nil {
		return
	}
	lock := filepath.Join(c.dir, ".write-lock")
	lockFile, lockErr := os.OpenFile(lock, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if lockErr != nil {
		return
	}
	_ = lockFile.Close()
	defer func() { _ = os.Remove(lock) }()
	if !c.prune(ctx, int64(len(data))) {
		return
	}
	file, err := os.CreateTemp(c.dir, ".entry-*")
	if err != nil {
		return
	}
	name := file.Name()
	defer func() { _ = os.Remove(name) }()
	if _, err = file.Write(data); err != nil {
		_ = file.Close()
		return
	}
	if file.Close() != nil || ctx.Err() != nil {
		return
	}
	_ = os.Rename(name, c.name(identity))
}
func (c *classificationCache) prune(ctx context.Context, incoming int64) bool {
	// Cross-process writers serialize pruning/publication. Lock acquisition is
	// nonblocking: a busy or stale lock simply disables this cache write.
	entries, err := os.ReadDir(c.dir)
	if err != nil {
		return false
	}
	type item struct {
		path     string
		size     int64
		modified time.Time
	}
	var items []item
	var total int64
	for _, e := range entries {
		if ctx.Err() != nil {
			return false
		}
		if !strings.HasSuffix(e.Name(), ".json") || len(e.Name()) != 69 {
			continue
		}
		info, err := e.Info()
		if err != nil || !info.Mode().IsRegular() {
			continue
		}
		path := filepath.Join(c.dir, e.Name())
		if time.Since(info.ModTime()) >= 24*time.Hour {
			_ = os.Remove(path)
			continue
		}
		total += info.Size()
		items = append(items, item{path, info.Size(), info.ModTime()})
	}
	sort.Slice(items, func(i, j int) bool { return items[i].modified.Before(items[j].modified) })
	for _, it := range items {
		if total+incoming <= classificationCacheLimit {
			break
		}
		if ctx.Err() != nil {
			return false
		}
		if os.Remove(it.path) == nil {
			total -= it.size
		}
	}
	return total+incoming <= classificationCacheLimit
}
