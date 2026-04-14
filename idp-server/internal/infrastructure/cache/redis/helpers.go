package redis

import (
	"strconv"
	"time"
)

func durationSeconds(ttl time.Duration) int64 {
	// Redis 脚本大多按秒接收 TTL；小于 1 秒但大于 0 的值向上取成 1 秒，
	// 避免短 TTL 在脚本层被截断成 0 导致意外“不过期”或“立即过期”。
	seconds := int64(ttl / time.Second)
	if ttl > 0 && seconds == 0 {
		return 1
	}
	return seconds
}

func formatTime(value time.Time) string {
	// 统一用 UTC + RFC3339，方便跨进程、跨语言和 Lua 脚本稳定处理。
	return value.UTC().Format(time.RFC3339)
}

func parseTime(value string) time.Time {
	// 解析失败时返回零值时间；上层通常会把零值视为“无效/不存在”。
	parsed, _ := time.Parse(time.RFC3339, value)
	return parsed
}

func boolString(value bool) string {
	// Redis hash 字段统一使用 "1"/"0" 表示布尔值，便于脚本判断。
	if value {
		return "1"
	}
	return "0"
}

func parseBoolString(value string) bool {
	// 同时兼容旧数据里可能出现的 true/false 字面量。
	return value == "1" || value == "true"
}

func parseInt64(value string) int64 {
	// 辅助解析函数默认吞掉错误，调用方按 0 处理缺失/非法值。
	parsed, _ := strconv.ParseInt(value, 10, 64)
	return parsed
}
