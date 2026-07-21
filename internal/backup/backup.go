package backup

import (
	"bufio"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/JiangHe12/opskit-core/v2/apperrors"

	"github.com/JiangHe12/opskit-core/v2/lockfile"
)

const (
	StatusOK      = "ok"
	StatusMissing = "missing"
	storeIDFile   = ".store-id"
)

type Request struct {
	Context   string
	Namespace string
	Group     string
	DataID    string
	Content   []byte
	Operator  string
}

type Result struct {
	BackupID string `json:"backupId,omitempty"`
	StoreID  string `json:"storeId,omitempty"`
	Path     string `json:"path"`
	SHA256   string `json:"sha256"`
	Size     int    `json:"size"`
}

type Metadata struct {
	BackupID  string `json:"backupId"`
	StoreID   string `json:"storeId,omitempty"`
	Context   string `json:"context"`
	DataID    string `json:"dataId"`
	Namespace string `json:"namespace"`
	Group     string `json:"group"`
	Operator  string `json:"operator"`
	SHA256    string `json:"sha256"`
	Size      int    `json:"size"`
	CreatedAt string `json:"createdAt"`
	Path      string `json:"path"`
	Status    string `json:"status"`
}

type Filter struct {
	Context   string
	Namespace string
	DataID    string
}

type CleanOptions struct {
	Filter    Filter
	OlderThan time.Duration
	Before    *time.Time
	KeepLast  *int
	Now       time.Time
	Apply     bool
}

type CleanResult struct {
	Deleted []Metadata `json:"deleted"`
	Removed []Metadata `json:"removed"`
	DryRun  bool       `json:"dryRun"`
}

func Write(root string, req Request) (Result, error) {
	now := time.Now().UTC()
	storeID, err := getOrCreateStoreID(root)
	if err != nil {
		return Result{}, err
	}
	var backupID string
	var path string
	for attempt := 0; attempt < 3; attempt++ {
		backupID = generateBackupID(storeID)
		path = filepath.Join(
			root,
			safe(req.Context),
			safe(req.Namespace),
			safe(req.Group),
			safe(req.DataID),
			backupID+".bak",
		)
		if _, err := os.Stat(path); os.IsNotExist(err) {
			break
		}
		if attempt == 2 {
			return Result{}, apperrors.New(apperrors.CodeLocalIOError, "backup ID collision after 3 retries", nil)
		}
	}
	sum := sha256.Sum256(req.Content)
	hash := hex.EncodeToString(sum[:])
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return Result{}, err
	}
	if err := enforceStorePermissions(root); err != nil {
		return Result{}, err
	}
	bf, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600) //nolint:gosec // Path is generated inside the configured backup directory with a sanitized filename.
	if err != nil {
		return Result{}, err
	}
	if _, err := bf.Write(req.Content); err != nil {
		_ = bf.Close()
		return Result{}, err
	}
	if err := bf.Close(); err != nil {
		return Result{}, err
	}

	item := Metadata{
		BackupID:  backupID,
		StoreID:   storeID,
		Context:   req.Context,
		DataID:    req.DataID,
		Namespace: req.Namespace,
		Group:     req.Group,
		Operator:  req.Operator,
		SHA256:    hash,
		Size:      len(req.Content),
		CreatedAt: now.Format(time.RFC3339),
		Path:      path,
	}
	line, err := json.Marshal(item)
	if err != nil {
		return Result{}, err
	}

	indexLock := lockfile.New(filepath.Join(root, "index"))
	if err := indexLock.Acquire(); err != nil {
		return Result{}, apperrors.New(apperrors.CodeLocalIOError, "lock backup index", err)
	}
	defer func() { _ = indexLock.Release() }()

	var f *os.File
	if err := enforceIndexPermission(root); err != nil {
		return Result{}, err
	}
	f, err = os.OpenFile(filepath.Join(root, "index.jsonl"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600) //nolint:gosec // reason: path constructed from backup root directory
	if err != nil {
		return Result{}, err
	}
	defer func() { _ = f.Close() }()
	if _, err := f.Write(append(line, '\n')); err != nil {
		return Result{}, err
	}

	return Result{BackupID: backupID, StoreID: storeID, Path: path, SHA256: hash, Size: len(req.Content)}, nil
}

func enforceStorePermissions(root string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	info, err := os.Stat(root)
	if err != nil {
		return err
	}
	if info.Mode().Perm() != 0o700 {
		return apperrors.New(apperrors.CodeLocalIOError,
			fmt.Sprintf("backup directory %s has insecure mode %#o; expected 0700", root, info.Mode().Perm()), nil)
	}
	return nil
}

func enforceIndexPermission(root string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	path := filepath.Join(root, "index.jsonl")
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if info.Mode().Perm() != 0o600 {
		return apperrors.New(apperrors.CodeLocalIOError,
			fmt.Sprintf("backup index %s has insecure mode %#o; expected 0600", path, info.Mode().Perm()), nil)
	}
	return nil
}

func List(root string, filter Filter) ([]Metadata, error) {
	items, err := readIndex(root)
	if err != nil {
		return nil, err
	}
	filtered := make([]Metadata, 0, len(items))
	for _, item := range items {
		item = reconcile(item)
		if item.BackupID == "" {
			if createdAt, err := time.Parse(time.RFC3339, item.CreatedAt); err == nil {
				item.BackupID = legacyBackupID(createdAt)
			}
		}
		if filter.Context != "" && item.Context != filter.Context {
			continue
		}
		if filter.Namespace != "" && item.Namespace != filter.Namespace {
			continue
		}
		if filter.DataID != "" && item.DataID != filter.DataID {
			continue
		}
		filtered = append(filtered, item)
	}
	return filtered, nil
}

func Clean(root string, opts CleanOptions) (CleanResult, error) { //nolint:gocyclo // reason: backup clean logic requires multiple filter/age/status branches
	if opts.Now.IsZero() {
		opts.Now = time.Now()
	}
	if opts.Apply {
		indexLock := lockfile.New(filepath.Join(root, "index"))
		if err := indexLock.Acquire(); err != nil {
			return CleanResult{}, apperrors.New(apperrors.CodeLocalIOError, "lock backup index", err)
		}
		defer func() { _ = indexLock.Release() }()
		return cleanLocked(root, opts)
	}
	return cleanLocked(root, opts)
}

func cleanLocked(root string, opts CleanOptions) (CleanResult, error) { //nolint:gocyclo // reason: shared clean implementation
	return cleanLockedWithOperations(root, opts, os.Remove, writeIndex)
}

func cleanLockedWithOperations(
	root string,
	opts CleanOptions,
	remove func(string) error,
	write func(string, []Metadata) error,
) (CleanResult, error) { //nolint:gocyclo // reason: shared clean implementation
	items, err := readIndex(root)
	if err != nil {
		return CleanResult{}, err
	}
	result := CleanResult{DryRun: !opts.Apply}
	kept := make([]Metadata, 0, len(items))
	removed := make([]Metadata, 0, len(items))
	deleteSet := cleanDeleteSet(items, opts)
	for _, item := range items {
		item = reconcile(item)
		if item.BackupID == "" {
			if createdAt, err := time.Parse(time.RFC3339, item.CreatedAt); err == nil {
				item.BackupID = legacyBackupID(createdAt)
			}
		}
		if !matches(item, opts.Filter) {
			kept = append(kept, item)
			continue
		}
		if item.Status == StatusMissing {
			if opts.Apply {
				removed = append(removed, item)
			} else {
				result.Removed = append(result.Removed, item)
				kept = append(kept, item)
			}
			continue
		}
		if !deleteSet[item.BackupID] && !cleanByTime(item, opts) {
			kept = append(kept, item)
			continue
		}
		if opts.Apply {
			if err := remove(item.Path); err != nil && !os.IsNotExist(err) {
				return result, err
			}
			result.Deleted = append(result.Deleted, item)
			continue
		}
		result.Deleted = append(result.Deleted, item)
		kept = append(kept, item)
	}
	if opts.Apply {
		if err := write(root, kept); err != nil {
			return result, err
		}
		result.Removed = append(result.Removed, removed...)
	}
	return result, nil
}

func cleanDeleteSet(items []Metadata, opts CleanOptions) map[string]bool {
	out := map[string]bool{}
	if opts.KeepLast == nil {
		return out
	}
	matched := make([]Metadata, 0, len(items))
	for _, item := range items {
		item = reconcile(item)
		if item.Status == StatusMissing || !matches(item, opts.Filter) {
			continue
		}
		matched = append(matched, item)
	}
	sortMetadata(matched)
	keep := *opts.KeepLast
	if keep >= len(matched) {
		return out
	}
	for _, item := range matched[:len(matched)-keep] {
		out[item.BackupID] = true
	}
	return out
}

func cleanByTime(item Metadata, opts CleanOptions) bool {
	if opts.KeepLast != nil {
		return false
	}
	if opts.Before != nil {
		createdAt, err := time.Parse(time.RFC3339, item.CreatedAt)
		return err == nil && createdAt.Before(*opts.Before)
	}
	return opts.OlderThan <= 0 || olderThan(item, opts.Now, opts.OlderThan)
}

func ParseRetentionDuration(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, fmt.Errorf("duration is required")
	}
	re := regexp.MustCompile(`(\d+)([dhms])`)
	matches := re.FindAllStringSubmatch(s, -1)
	if len(matches) == 0 {
		return 0, fmt.Errorf("invalid duration %q", s)
	}
	var consumed int
	var d time.Duration
	for _, match := range matches {
		consumed += len(match[0])
		n, err := strconv.Atoi(match[1])
		if err != nil {
			return 0, err
		}
		switch match[2] {
		case "d":
			d += time.Duration(n) * 24 * time.Hour
		case "h":
			d += time.Duration(n) * time.Hour
		case "m":
			d += time.Duration(n) * time.Minute
		case "s":
			d += time.Duration(n) * time.Second
		}
	}
	if consumed != len(s) {
		return 0, fmt.Errorf("invalid duration %q", s)
	}
	return d, nil
}

func readIndex(root string) ([]Metadata, error) {
	f, err := os.Open(filepath.Join(root, "index.jsonl")) //nolint:gosec // reason: path constructed from backup root directory
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer func() { _ = f.Close() }()
	var items []Metadata
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var item Metadata
		if err := json.Unmarshal([]byte(line), &item); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, scanner.Err()
}

func writeIndex(root string, items []Metadata) error {
	if err := os.MkdirAll(root, 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(filepath.Join(root, "index.jsonl"), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600) //nolint:gosec // reason: path constructed from backup root directory
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	for _, item := range items {
		item.Status = ""
		line, err := json.Marshal(item)
		if err != nil {
			return err
		}
		if _, err := f.Write(append(line, '\n')); err != nil {
			return err
		}
	}
	return nil
}

func reconcile(item Metadata) Metadata {
	if _, err := os.Stat(item.Path); err != nil {
		if os.IsNotExist(err) {
			item.Status = StatusMissing
		}
	} else {
		item.Status = StatusOK
	}
	return item
}

func matches(item Metadata, filter Filter) bool {
	if filter.Context != "" && item.Context != filter.Context {
		return false
	}
	if filter.Namespace != "" && item.Namespace != filter.Namespace {
		return false
	}
	if filter.DataID != "" && item.DataID != filter.DataID {
		return false
	}
	return true
}

func olderThan(item Metadata, now time.Time, age time.Duration) bool {
	if info, err := os.Stat(item.Path); err == nil {
		return now.Sub(info.ModTime()) > age
	}
	createdAt, err := time.Parse(time.RFC3339, item.CreatedAt)
	if err != nil {
		return false
	}
	return now.Sub(createdAt) > age
}

func sortMetadata(items []Metadata) {
	sort.SliceStable(items, func(i, j int) bool {
		ti, iok := metadataTime(items[i])
		tj, jok := metadataTime(items[j])
		switch {
		case iok && jok && !ti.Equal(tj):
			return ti.Before(tj)
		case iok != jok:
			return iok
		default:
			return items[i].BackupID < items[j].BackupID
		}
	})
}

func metadataTime(item Metadata) (time.Time, bool) {
	if t, err := time.Parse(time.RFC3339, item.CreatedAt); err == nil {
		return t, true
	}
	return time.Time{}, false
}

func getOrCreateStoreID(storeDir string) (string, error) {
	path := filepath.Join(storeDir, storeIDFile)
	data, err := os.ReadFile(path) //nolint:gosec // reason: path constructed from backup store directory
	if err == nil {
		return strings.TrimSpace(string(data)), nil
	}
	if !os.IsNotExist(err) {
		return "", err
	}
	buf := make([]byte, 8)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	id := hex.EncodeToString(buf)
	if err := os.MkdirAll(storeDir, 0o700); err != nil {
		return "", err
	}
	if err := os.WriteFile(path, []byte(id+"\n"), 0o600); err != nil {
		return "", err
	}
	return id, nil
}

func generateBackupID(storeID string) string {
	ts := time.Now().UTC().Format("20060102T150405Z")
	buf := make([]byte, 3)
	_, _ = rand.Read(buf)
	shortStoreID := storeID
	if len(shortStoreID) > 8 {
		shortStoreID = shortStoreID[:8]
	}
	return fmt.Sprintf("bk-%s-%s-%s", ts, shortStoreID, hex.EncodeToString(buf))
}

func legacyBackupID(t time.Time) string {
	sum := sha256.Sum256([]byte(t.Format(time.RFC3339Nano)))
	return fmt.Sprintf("bk-%s-%s-%s", t.Format("20060102"), t.Format("150405"), hex.EncodeToString(sum[:])[:4])
}

func safe(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return "_"
	}
	replacer := strings.NewReplacer("/", "_", "\\", "_", ":", "_", "*", "_", "?", "_", `"`, "_", "<", "_", ">", "_", "|", "_")
	s = replacer.Replace(s)
	switch s {
	case ".":
		return "%2e"
	case "..":
		return "%2e%2e"
	default:
		return s
	}
}
