package mtls_test

import (
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/lstoll/ingress/internal/mtls"
)

func TestReloaderReloadOnceAfterRotateClient(t *testing.T) {
	fix := mtls.NewTestFixture(t)
	reloader, err := mtls.NewClientReloader(testLogger(), fix.ClientCert, fix.ClientKey, fix.CAFile, time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	fix.RotateClientCert(t)
	if err := reloader.ReloadOnce(); err != nil {
		t.Fatalf("reload after rotation: %v", err)
	}
}

func TestReloaderReloadOnceAfterRotateServer(t *testing.T) {
	fix := mtls.NewTestFixture(t)
	reloader, err := mtls.NewServerReloader(testLogger(), fix.ServerCert, fix.ServerKey, fix.CAFile, fix.IngressSVID, time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	fix.RotateServerCert(t)
	if err := reloader.ReloadOnce(); err != nil {
		t.Fatalf("reload after rotation: %v", err)
	}
}

func TestReloaderKeepsPreviousMaterialOnBadReload(t *testing.T) {
	fix := mtls.NewTestFixture(t)
	reloader, err := mtls.NewClientReloader(testLogger(), fix.ClientCert, fix.ClientKey, fix.CAFile, time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	before := reloader.ClientTLSConfig("backend-sidecar")

	if err := os.WriteFile(fix.ClientKey, []byte("not a key"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := reloader.ReloadOnce(); err == nil {
		t.Fatal("expected reload error for corrupt key")
	}

	after := reloader.ClientTLSConfig("backend-sidecar")
	if len(before.Certificates) != 1 || len(after.Certificates) != 1 {
		t.Fatal("expected one certificate before and after failed reload")
	}
	if string(before.Certificates[0].Certificate[0]) != string(after.Certificates[0].Certificate[0]) {
		t.Fatal("expected in-memory client certificate to be unchanged after failed reload")
	}
}

func TestReloaderReloadOnceNoOpWhenUnchanged(t *testing.T) {
	fix := mtls.NewTestFixture(t)
	reloader, err := mtls.NewClientReloader(testLogger(), fix.ClientCert, fix.ClientKey, fix.CAFile, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := reloader.ReloadOnce(); err != nil {
		t.Fatalf("unchanged reload: %v", err)
	}
}

func testLogger() *slog.Logger {
	return slog.New(slog.DiscardHandler)
}
