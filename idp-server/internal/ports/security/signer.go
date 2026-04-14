package security

// Signer 是“能把 claim 集合铸造成 token”的最小能力抽象。
// 上层不关心底层是 JWT、JWS 还是其他格式，只关心能否拿到一个可分发的字符串。
type Signer interface {
	Mint(claims map[string]any) (string, error)
}
