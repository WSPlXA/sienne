package cache

import "errors"

var (
	// ErrStateVersionConflict 表示并发写入导致的状态版本冲突（CAS 失败）。
	ErrStateVersionConflict = errors.New("state version conflict")
	// ErrInvalidStateTransition 表示状态位组合或跃迁不满足约束。
	ErrInvalidStateTransition = errors.New("invalid state transition")
)
