package key

// Model 是签名密钥最小元数据投影，用于在内存里标识 kid、算法和用途。
type Model struct {
	KID string
	Alg string
	Use string
}
