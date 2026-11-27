// Package collection 负责授权日志源、不可变批次与自动分析。
package collection

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path"
	"regexp"
	"strings"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

const (
	maxRead = 4 << 20
	maxLine = 64 << 10
)

var generationPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

// CatalogEntry 只能由部署者写入受控配置文件；Web 只引用 ID。
type CatalogEntry struct {
	ID             string `json:"id"`
	Name           string `json:"name"`
	Address        string `json:"address"`
	Username       string `json:"username"`
	KeyFile        string `json:"key_file"`
	HostPublicKey  string `json:"host_public_key"`
	LogPath        string `json:"log_path"`
	GenerationPath string `json:"generation_path"`
	Format         string `json:"format"`
	SourceHost     string `json:"source_host"`
}

type Catalog struct{ entries map[string]CatalogEntry }

func LoadCatalog(catalogPath string) (Catalog, error) {
	result := Catalog{entries: map[string]CatalogEntry{}}
	if catalogPath == "" {
		return result, nil
	}
	raw, err := os.ReadFile(catalogPath)
	if err != nil {
		return result, err
	}
	var entries []CatalogEntry
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&entries); err != nil {
		return result, fmt.Errorf("授权源目录格式无效: %w", err)
	}
	if decoder.Decode(new(any)) != io.EOF {
		return result, errors.New("授权源目录含多余内容")
	}
	for _, entry := range entries {
		if entry.ID == "" || entry.Name == "" || entry.Username == "" || entry.KeyFile == "" || entry.SourceHost == "" ||
			entry.HostPublicKey == "" || entry.LogPath == entry.GenerationPath ||
			!strings.HasPrefix(entry.LogPath, "/") || !strings.HasPrefix(entry.GenerationPath, "/") ||
			path.Clean(entry.LogPath) != entry.LogPath || path.Clean(entry.GenerationPath) != entry.GenerationPath ||
			(entry.Format != "ssh-rfc3339" && entry.Format != "ssh-rfc3164" && entry.Format != "nginx-combined") {
			return result, fmt.Errorf("授权源条目 %q 无效", entry.ID)
		}
		if _, _, err := net.SplitHostPort(entry.Address); err != nil {
			return result, fmt.Errorf("授权源地址无效: %w", err)
		}
		if _, _, _, _, err := ssh.ParseAuthorizedKey([]byte(entry.HostPublicKey)); err != nil {
			return result, fmt.Errorf("授权源主机公钥无效: %w", err)
		}
		if result.entries[entry.ID].ID != "" {
			return result, fmt.Errorf("授权源 ID 重复")
		}
		result.entries[entry.ID] = entry
	}
	return result, nil
}

func (c Catalog) Get(id string) (CatalogEntry, bool) { entry, ok := c.entries[id]; return entry, ok }

func entryDigest(entry CatalogEntry) string { raw, _ := json.Marshal(entry); return hash(raw) }

type Cursor struct {
	Generation string
	Offset     int64
	LineNo     int64
	AnchorHash string
}

type Chunk struct {
	Generation string
	Bytes      []byte
	AnchorHash string
	Backlog    bool
}

type Reader interface {
	Read(context.Context, CatalogEntry, Cursor) (Chunk, error)
}

type SFTPReader struct{}

func (SFTPReader) Read(ctx context.Context, entry CatalogEntry, cursor Cursor) (Chunk, error) {
	key, err := os.ReadFile(entry.KeyFile)
	if err != nil {
		return Chunk{}, errors.New("只读凭据不可用")
	}
	signer, err := ssh.ParsePrivateKey(key)
	if err != nil {
		return Chunk{}, errors.New("只读凭据格式无效")
	}
	trusted, _, _, _, _ := ssh.ParseAuthorizedKey([]byte(entry.HostPublicKey))
	config := &ssh.ClientConfig{
		User: entry.Username, Auth: []ssh.AuthMethod{ssh.PublicKeys(signer)}, Timeout: 5 * time.Second,
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			if string(key.Marshal()) != string(trusted.Marshal()) {
				return errors.New("主机身份不匹配")
			}
			return nil
		},
	}
	dialer := net.Dialer{Timeout: 5 * time.Second}
	conn, err := dialer.DialContext(ctx, "tcp", entry.Address)
	if err != nil {
		return Chunk{}, errors.New("连接授权源失败")
	}
	defer conn.Close()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	sshConn, channels, requests, err := ssh.NewClientConn(conn, entry.Address, config)
	if err != nil {
		return Chunk{}, errors.New("授权源握手或身份验证失败")
	}
	client := ssh.NewClient(sshConn, channels, requests)
	defer client.Close()
	remote, err := sftp.NewClient(client)
	if err != nil {
		return Chunk{}, errors.New("授权源 SFTP 不可用")
	}
	defer remote.Close()
	readGeneration := func() (string, error) {
		file, err := remote.Open(entry.GenerationPath)
		if err != nil {
			return "", err
		}
		defer file.Close()
		raw, err := io.ReadAll(io.LimitReader(file, 66))
		if err != nil {
			return "", err
		}
		value := strings.TrimSuffix(string(raw), "\n")
		if !generationPattern.MatchString(value) {
			return "", errors.New("文件代次无效")
		}
		return value, nil
	}
	generation, err := readGeneration()
	if err != nil {
		return Chunk{}, errors.New("无法验证文件代次")
	}
	if cursor.Generation != "" && cursor.Generation != generation {
		return Chunk{}, errors.New("文件代次已改变，请停用旧源并登记新源")
	}
	info, err := remote.Lstat(entry.LogPath)
	if err != nil || !info.Mode().IsRegular() {
		return Chunk{}, errors.New("授权日志文件不可用或不是普通文件")
	}
	if info.Size() < cursor.Offset {
		return Chunk{}, errors.New("日志文件短于已提交断点")
	}
	file, err := remote.Open(entry.LogPath)
	if err != nil {
		return Chunk{}, errors.New("无法读取授权日志")
	}
	defer file.Close()
	if cursor.Offset > 0 {
		start := max(int64(0), cursor.Offset-4096)
		anchor := make([]byte, cursor.Offset-start)
		if _, err := file.ReadAt(anchor, start); err != nil {
			return Chunk{}, errors.New("无法核对已消费前缀")
		}
		if hash(anchor) != cursor.AnchorHash {
			return Chunk{}, errors.New("已消费前缀不匹配")
		}
	}
	buf := make([]byte, maxRead+1)
	n, err := file.ReadAt(buf, cursor.Offset)
	if err != nil && err != io.EOF {
		return Chunk{}, errors.New("授权日志读取失败")
	}
	buf = buf[:n]
	limit := min(len(buf), maxRead)
	end := strings.LastIndexByte(string(buf[:limit]), '\n') + 1
	if end == 0 && len(buf) > maxLine {
		return Chunk{}, errors.New("日志行超过 64 KiB")
	}
	consumed := buf[:end]
	for _, line := range strings.Split(string(consumed), "\n") {
		if len(line) >= maxLine {
			return Chunk{}, errors.New("日志行超过 64 KiB")
		}
	}
	again, err := readGeneration()
	if err != nil || again != generation {
		return Chunk{}, errors.New("读取时文件代次变化")
	}
	anchorStart := max(int64(0), cursor.Offset+int64(end)-4096)
	anchor := make([]byte, cursor.Offset+int64(end)-anchorStart)
	if len(anchor) > 0 {
		if _, err := file.ReadAt(anchor, anchorStart); err != nil {
			return Chunk{}, errors.New("无法核对新断点")
		}
	}
	return Chunk{Generation: generation, Bytes: append([]byte(nil), consumed...), AnchorHash: hash(anchor), Backlog: len(buf) > end}, nil
}

func hash(raw []byte) string { sum := sha256.Sum256(raw); return hex.EncodeToString(sum[:]) }
