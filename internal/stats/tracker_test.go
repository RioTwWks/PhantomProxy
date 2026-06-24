package stats

import "testing"

func TestTrackerConnectionsAndTraffic(t *testing.T) {
	t.Parallel()

	tr := New()
	tr.OnConnect("alice")
	tr.OnConnect("alice")
	tr.AddTraffic("alice", 100, 200)

	snap := tr.Snapshot()
	if snap.ActiveConnections != 2 {
		t.Fatalf("active = %d", snap.ActiveConnections)
	}
	if snap.UploadBytes != 100 || snap.DownloadBytes != 200 {
		t.Fatalf("traffic = %+v", snap)
	}

	tr.OnDisconnect("alice")
	snap = tr.Snapshot()
	if snap.ActiveConnections != 1 {
		t.Fatalf("active after disconnect = %d", snap.ActiveConnections)
	}
}
