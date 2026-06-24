package user

import (
	"fmt"

	"github.com/RioTwWks/PhantomProxy/internal/faketls"
	"github.com/RioTwWks/PhantomProxy/internal/mtproto"
)

// User — зарегистрированный MTProto-пользователь прокси.
type User struct {
	Name    string
	Secret  mtproto.Secret
	Enabled bool
}

// Manager хранит список пользователей и сопоставляет ClientHello с секретом.
type Manager struct {
	users       []User
	maskHost    string
	fingerprints map[string]struct{}
}

// NewManager создаёт менеджер пользователей.
func NewManager(users []User, allowedJA3 []string) (*Manager, error) {
	if len(users) == 0 {
		return nil, fmt.Errorf("нужен хотя бы один пользователь")
	}

	active := make([]User, 0, len(users))
	for _, u := range users {
		if u.Enabled {
			active = append(active, u)
		}
	}
	if len(active) == 0 {
		return nil, fmt.Errorf("нет активных пользователей")
	}

	allowed := make(map[string]struct{}, len(allowedJA3))
	for _, fp := range allowedJA3 {
		if fp != "" {
			allowed[fp] = struct{}{}
		}
	}

	return &Manager{
		users:        active,
		maskHost:     active[0].Secret.Host,
		fingerprints: allowed,
	}, nil
}

// MaskHost возвращает домен маскировки для fallback-редиректа.
func (m *Manager) MaskHost() string {
	return m.maskHost
}

// Users возвращает активных пользователей.
func (m *Manager) Users() []User {
	out := make([]User, len(m.users))
	copy(out, m.users)
	return out
}

// MatchClientHello находит пользователя по валидному ClientHello.
func (m *Manager) MatchClientHello(ch *faketls.ClientHello) (*User, error) {
	if len(m.fingerprints) > 0 {
		ja3 := faketls.JA3(ch.Raw)
		if _, ok := m.fingerprints[ja3]; !ok {
			return nil, fmt.Errorf("JA3 %s не в белом списке", ja3)
		}
	}

	for i := range m.users {
		u := &m.users[i]
		if err := faketls.ValidateClientHello(ch, u.Secret.Key[:], u.Secret.Host); err != nil {
			continue
		}
		return u, nil
	}
	return nil, fmt.Errorf("секрет не найден среди %d пользователей", len(m.users))
}
