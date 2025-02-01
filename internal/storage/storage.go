package storage

// Storage defines the storage interface
type Storage interface {
	Save(data []byte) error
	Load(key string) ([]byte, error)
}
