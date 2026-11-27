package collection

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/Double-Cloth/NetSentinel/backend/internal/repository"
	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

func TestSFTPReaderWithPinnedHostAndCursor(t *testing.T) {
	_, hostPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	hostSigner, err := ssh.NewSignerFromKey(hostPrivate)
	if err != nil {
		t.Fatal(err)
	}
	clientPublic, clientPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	clientKey, err := ssh.NewPublicKey(clientPublic)
	if err != nil {
		t.Fatal(err)
	}
	config := &ssh.ServerConfig{PublicKeyCallback: func(_ ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
		if !bytes.Equal(key.Marshal(), clientKey.Marshal()) {
			return nil, errors.New("client key mismatch")
		}
		return nil, nil
	}}
	config.AddHostKey(hostSigner)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	go func() {
		for {
			connection, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer connection.Close()
				_, channels, requests, err := ssh.NewServerConn(connection, config)
				if err != nil {
					return
				}
				go ssh.DiscardRequests(requests)
				for channelRequest := range channels {
					if channelRequest.ChannelType() != "session" {
						channelRequest.Reject(ssh.UnknownChannelType, "session only")
						continue
					}
					channel, reqs, err := channelRequest.Accept()
					if err != nil {
						return
					}
					go func() {
						defer channel.Close()
						for request := range reqs {
							if request.Type == "subsystem" && len(request.Payload) >= 8 && string(request.Payload[4:]) == "sftp" {
								request.Reply(true, nil)
								server, err := sftp.NewServer(channel)
								if err == nil {
									_ = server.Serve()
									_ = server.Close()
								}
								return
							}
							request.Reply(false, nil)
						}
					}()
				}
			}()
		}
	}()
	keyDER, err := x509.MarshalPKCS8PrivateKey(clientPrivate)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "reader.key")
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0600); err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(dir, "auth.log")
	generationPath := filepath.Join(dir, "generation")
	if err := os.WriteFile(generationPath, []byte("generation-1\n"), 0600); err != nil {
		t.Fatal(err)
	}
	first := []byte(sshLine(0))
	if err := os.WriteFile(logPath, first, 0600); err != nil {
		t.Fatal(err)
	}
	entry := CatalogEntry{Address: listener.Addr().String(), Username: "reader", KeyFile: keyPath, HostPublicKey: string(ssh.MarshalAuthorizedKey(hostSigner.PublicKey())),
		LogPath: filepath.ToSlash(logPath), GenerationPath: filepath.ToSlash(generationPath)}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	chunk, err := (SFTPReader{}).Read(ctx, entry, Cursor{})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(chunk.Bytes, first) || chunk.Generation != "generation-1" {
		t.Fatalf("首次读取错误: %+v", chunk)
	}
	second := []byte(sshLine(1))
	file, err := os.OpenFile(logPath, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.Write(second); err != nil {
		t.Fatal(err)
	}
	file.Close()
	chunk, err = (SFTPReader{}).Read(ctx, entry, Cursor{Generation: chunk.Generation, Offset: int64(len(first)), LineNo: 1, AnchorHash: chunk.AnchorHash})
	if err != nil || !bytes.Equal(chunk.Bytes, second) {
		t.Fatalf("增量读取错误: %+v %v", chunk, err)
	}
	_, otherPrivate, _ := ed25519.GenerateKey(rand.Reader)
	otherSigner, _ := ssh.NewSignerFromKey(otherPrivate)
	entry.HostPublicKey = string(ssh.MarshalAuthorizedKey(otherSigner.PublicKey()))
	if _, err := (SFTPReader{}).Read(ctx, entry, Cursor{}); err == nil {
		t.Fatal("错误主机公钥应拒绝")
	}
	if runtime.GOOS == "windows" {
		// Windows 临时路径不是目录契约要求的 POSIX 绝对远端路径；Linux 容器执行完整链路。
		return
	}
	entry.ID = "fixture"
	entry.Name = "合成 SFTP"
	entry.Format = "ssh-rfc3339"
	entry.SourceHost = "node-1"
	entry.HostPublicKey = string(ssh.MarshalAuthorizedKey(hostSigner.PublicKey()))
	file, err = os.OpenFile(logPath, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	for _, minute := range []int{2, 3} {
		if _, err := file.WriteString(sshLine(minute)); err != nil {
			file.Close()
			t.Fatal(err)
		}
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	catalogPath := filepath.Join(dir, "catalog.json")
	raw, _ := json.Marshal([]CatalogEntry{entry})
	if err := os.WriteFile(catalogPath, raw, 0600); err != nil {
		t.Fatal(err)
	}
	catalog, err := LoadCatalog(catalogPath)
	if err != nil {
		t.Fatal(err)
	}
	store, err := repository.Open(context.Background(), filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	svc, err := NewService(store.DB, catalog, nil, filepath.Join(dir, "data"))
	if err != nil {
		t.Fatal(err)
	}
	source, err := svc.CreateSource(context.Background(), SourceInput{CatalogID: "fixture", IntervalSeconds: 30, Enabled: true}, "", "test")
	if err != nil {
		t.Fatal(err)
	}
	chainCtx, chainCancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer chainCancel()
	if err := svc.RunOnce(chainCtx); err != nil {
		t.Fatal(err)
	}
	file, err = os.OpenFile(logPath, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.WriteString(sshLine(5)); err != nil {
		file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := store.DB.ExecContext(chainCtx, `UPDATE log_sources SET next_at=0 WHERE id=?`, source.ID); err != nil {
		t.Fatal(err)
	}
	if err := svc.RunOnce(chainCtx); err != nil {
		t.Fatal(err)
	}
	alerts, err := svc.Alerts(chainCtx)
	if err != nil || len(alerts) != 1 || alerts[0].Finding.ActualCount != 5 {
		t.Fatalf("SFTP 自动链路告警错误: %+v %v", alerts, err)
	}
	evidence, err := svc.Evidence(chainCtx, alerts[0].ID)
	if err != nil || len(evidence) != 5 {
		t.Fatalf("SFTP 自动链路证据错误: %+v %v", evidence, err)
	}
}
