package user

import (
	"crypto/rand"
	"fmt"
	"sync"

	"github.com/RioTwWks/PhantomProxy/internal/faketls"
	"github.com/RioTwWks/PhantomProxy/internal/mtproto"
)

// User — зарегистрированный MTProto-пользователь прокси.
type User struct {
	Name    string         `json:"name"`
	Secret  mtproto.Secret `json:"-"`
	Enabled bool           `json:"enabled"`
}

// UserView — пользователь для API (без сырого ключа).
type UserView struct {
	Name     string `json:"name"`
	Secret   string `json:"secret"`
	Host     string `json:"host"`
	Enabled  bool   `json:"enabled"`
	TGLink   string `json:"tg_link,omitempty"`
}

// Manager хранит список пользователей и сопоставляет ClientHello с секретом.
type Manager struct {
	mu           sync.RWMutex
	users        []User
	maskHost     string
	fingerprints map[string]struct{}
}

// NewManager создаёт менеджер пользователей.
func NewManager(users []User, allowedJA3 []string) (*Manager, error) {
	if len(users) == 0 {
		return nil, fmt.Errorf("нужен хотя бы один пользователь")
	}

	m := &Manager{fingerprints: make(map[string]struct{}, len(allowedJA3))}
	for _, fp := range allowedJA3 {
		if fp != "" {
			m.fingerprints[fp] = struct{}{}
		}
	}
	if err := m.replaceUsers(users); err != nil {
		return nil, err
	}
	return m, nil
}

func (m *Manager) replaceUsers(users []User) error {
	active := 0
	for _, u := range users {
		if u.Enabled {
			active++
		}
	}
	if active == 0 {
		return fmt.Errorf("нет активных пользователей")
	}

	m.users = append([]User(nil), users...)
	for _, u := range m.users {
		if u.Enabled {
			m.maskHost = u.Secret.Host
			break
		}
	}
	return nil
}

// MaskHost возвращает домен маскировки для fallback-редиректа.
func (m *Manager) MaskHost() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.maskHost
}

// Users возвращает копию всех пользователей.
func (m *Manager) Users() []User {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]User, len(m.users))
	copy(out, m.users)
	return out
}

// ListViews возвращает пользователей для API.
func (m *Manager) ListViews(server string, port int) []UserView {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]UserView, len(m.users))
	for i, u := range m.users {
		out[i] = toView(u, server, port)
	}
	return out
}

// GetView возвращает одного пользователя для API.
func (m *Manager) GetView(name, server string, port int) (UserView, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, u := range m.users {
		if u.Name == name {
			return toView(u, server, port), true
		}
	}
	return UserView{}, false
}

// MatchClientHello находит пользователя по валидному ClientHello.
func (m *Manager) MatchClientHello(ch *faketls.ClientHello) (*User, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if len(m.fingerprints) > 0 {
		ja3 := faketls.JA3(ch.Raw)
		if _, ok := m.fingerprints[ja3]; !ok {
			return nil, fmt.Errorf("JA3 %s не в белом списке", ja3)
		}
	}

	for i := range m.users {
		u := &m.users[i]
		if !u.Enabled {
			continue
		}
		if err := faketls.ValidateClientHello(ch, u.Secret.Key[:], u.Secret.Host); err != nil {
			continue
		}
		copy := m.users[i]
		return &copy, nil
	}
	return nil, fmt.Errorf("секрет не найден среди активных пользователей")
}

// AddUser добавляет нового пользователя.
func (m *Manager) AddUser(u User) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, existing := range m.users {
		if existing.Name == u.Name {
			return fmt.Errorf("пользователь %q уже существует", u.Name)
		}
	}
	m.users = append(m.users, u)
	if u.Enabled {
		m.maskHost = u.Secret.Host
	}
	return nil
}

// UpdateUser обновляет пользователя.
func (m *Manager) UpdateUser(name string, secret *mtproto.Secret, enabled *bool) (User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	for i, u := range m.users {
		if u.Name != name {
			continue
		}
		if secret != nil {
			m.users[i].Secret = *secret
		}
		if enabled != nil {
			m.users[i].Enabled = *enabled
		}
		m.refreshMaskHost()
		return m.users[i], nil
	}
	return User{}, fmt.Errorf("пользователь %q не найден", name)
}

// RemoveUser удаляет пользователя.
func (m *Manager) RemoveUser(name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if len(m.users) <= 1 {
		return fmt.Errorf("нельзя удалить последнего пользователя")
	}

	idx := -1
	for i, u := range m.users {
		if u.Name == name {
			idx = i
			break
		}
	}
	if idx < 0 {
		return fmt.Errorf("пользователь %q не найден", name)
	}
	m.users = append(m.users[:idx], m.users[idx+1:]...)
	return m.refreshMaskHost()
}

// Reload заменяет список пользователей из конфигурации.
func (m *Manager) Reload(users []User) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.replaceUsers(users)
}

func (m *Manager) refreshMaskHost() error {
	active := 0
	for _, u := range m.users {
		if u.Enabled {
			active++
			m.maskHost = u.Secret.Host
		}
	}
	if active == 0 {
		return fmt.Errorf("нет активных пользователей")
	}
	return nil
}

// GenerateSecret создаёт новый ee-секрет с заданным доменом.
func GenerateSecret(host string) (mtproto.Secret, string, error) {
	if host == "" {
		host = "storage.googleapis.com"
	}
	var key [mtproto.KeyLength]byte
	if _, err := rand.Read(key[:]); err != nil {
		return mtproto.Secret{}, "", err
	}
	secret := mtproto.Secret{Key: key, Host: host}
	return secret, mtproto.EncodeHex(secret), nil
}

func toView(u User, server string, port int) UserView {
	view := UserView{
		Name:    u.Name,
		Secret:  mtproto.EncodeHex(u.Secret),
		Host:    u.Secret.Host,
		Enabled: u.Enabled,
	}
	if server != "" && port > 0 {
		view.TGLink = fmt.Sprintf("tg://proxy?server=%s&port=%d&secret=%s", server, port, view.Secret)
	}
	return view
}
