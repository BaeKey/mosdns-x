package cache

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pmkol/mosdns-x/pkg/cache/mem_cache"
)

func TestCacheDumpSaveLoad(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "cache.dump")
	now := time.Now()

	src := mem_cache.NewMemCache(1024, -1)
	defer src.Close()
	src.Store("a", []byte{1, 2, 3}, now, now.Add(time.Minute))
	src.Store("expired", []byte{4, 5, 6}, now.Add(-time.Minute), now.Add(-time.Second))

	saved, err := saveCacheDump(file, src)
	if err != nil {
		t.Fatal(err)
	}
	if saved != 1 {
		t.Fatalf("unexpected saved count %d", saved)
	}

	dst := mem_cache.NewMemCache(1024, -1)
	defer dst.Close()
	loaded, err := loadCacheDump(file, dst)
	if err != nil {
		t.Fatal(err)
	}
	if loaded != 1 {
		t.Fatalf("unexpected loaded count %d", loaded)
	}

	v, storedTime, expirationTime := dst.Get("a")
	if string(v) != string([]byte{1, 2, 3}) {
		t.Fatalf("unexpected loaded value %v", v)
	}
	if !storedTime.Equal(now) || !expirationTime.Equal(now.Add(time.Minute)) {
		t.Fatalf("unexpected loaded times %s %s", storedTime, expirationTime)
	}
	if v, _, _ := dst.Get("expired"); v != nil {
		t.Fatal("expired item was loaded")
	}
}

func TestLoadCacheDumpMissingFile(t *testing.T) {
	c := mem_cache.NewMemCache(1024, -1)
	defer c.Close()

	loaded, err := loadCacheDump(filepath.Join(t.TempDir(), "missing.dump"), c)
	if err != nil {
		t.Fatal(err)
	}
	if loaded != 0 {
		t.Fatalf("unexpected loaded count %d", loaded)
	}
}

func TestLoadCacheDumpBrokenFile(t *testing.T) {
	file := filepath.Join(t.TempDir(), "broken.dump")
	if err := os.WriteFile(file, []byte("broken"), 0o644); err != nil {
		t.Fatal(err)
	}

	c := mem_cache.NewMemCache(1024, -1)
	defer c.Close()

	if _, err := loadCacheDump(file, c); err == nil {
		t.Fatal("expected error from broken dump")
	}
}
