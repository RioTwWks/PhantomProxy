package stats

import (
	"sync"
	"sync/atomic"
)

// UserStats — метрики одного пользователя.
type UserStats struct {
	Name              string `json:"name"`
	ActiveConnections int64  `json:"active_connections"`
	TotalConnections  int64  `json:"total_connections"`
	UploadBytes       int64  `json:"upload_bytes"`
	DownloadBytes     int64  `json:"download_bytes"`
}

// Snapshot — снимок статистики сервера.
type Snapshot struct {
	ActiveConnections int64       `json:"active_connections"`
	TotalConnections  int64       `json:"total_connections"`
	UploadBytes       int64       `json:"upload_bytes"`
	DownloadBytes     int64       `json:"download_bytes"`
	Users             []UserStats `json:"users"`
}

type userCounters struct {
	active  atomic.Int64
	total   atomic.Int64
	upload  atomic.Int64
	download atomic.Int64
}

// Tracker собирает статистику подключений и трафика.
type Tracker struct {
	mu    sync.RWMutex
	users map[string]*userCounters
}

// New создаёт трекер статистики.
func New() *Tracker {
	return &Tracker{users: make(map[string]*userCounters)}
}

func (t *Tracker) counters(name string) *userCounters {
	t.mu.RLock()
	c, ok := t.users[name]
	t.mu.RUnlock()
	if ok {
		return c
	}

	t.mu.Lock()
	defer t.mu.Unlock()
	if c, ok = t.users[name]; ok {
		return c
	}
	c = &userCounters{}
	t.users[name] = c
	return c
}

// OnConnect вызывается при новом подключении пользователя.
func (t *Tracker) OnConnect(name string) {
	c := t.counters(name)
	c.active.Add(1)
	c.total.Add(1)
}

// OnDisconnect вызывается при отключении пользователя.
func (t *Tracker) OnDisconnect(name string) {
	c := t.counters(name)
	c.active.Add(-1)
}

// AddTraffic добавляет переданный трафик пользователю.
func (t *Tracker) AddTraffic(name string, upload, download int64) {
	c := t.counters(name)
	if upload > 0 {
		c.upload.Add(upload)
	}
	if download > 0 {
		c.download.Add(download)
	}
}

// Snapshot возвращает текущую статистику.
func (t *Tracker) Snapshot() Snapshot {
	t.mu.RLock()
	defer t.mu.RUnlock()

	var snap Snapshot
	names := make([]string, 0, len(t.users))
	for name := range t.users {
		names = append(names, name)
	}

	for _, name := range names {
		c := t.users[name]
		us := UserStats{
			Name:              name,
			ActiveConnections: c.active.Load(),
			TotalConnections:  c.total.Load(),
			UploadBytes:       c.upload.Load(),
			DownloadBytes:     c.download.Load(),
		}
		snap.Users = append(snap.Users, us)
		snap.ActiveConnections += us.ActiveConnections
		snap.TotalConnections += us.TotalConnections
		snap.UploadBytes += us.UploadBytes
		snap.DownloadBytes += us.DownloadBytes
	}
	return snap
}

// User возвращает статистику пользователя.
func (t *Tracker) User(name string) (UserStats, bool) {
	t.mu.RLock()
	c, ok := t.users[name]
	t.mu.RUnlock()
	if !ok {
		return UserStats{}, false
	}
	return UserStats{
		Name:              name,
		ActiveConnections: c.active.Load(),
		TotalConnections:  c.total.Load(),
		UploadBytes:       c.upload.Load(),
		DownloadBytes:     c.download.Load(),
	}, true
}
