package handshake

type selfAuthInfo struct {
	Entropy   []byte
	SessionId []byte
	EphPub    [32]byte
	EphPri    [32]byte
	SharedKey []byte
}

type otherAuthInfo struct {
	Entropy   []byte
	SessionId []byte
	EphPub    [32]byte
}

type AuthInfo struct {
	PrivateKey []byte
	PublicKey  []byte
	SessionId  []byte
}
