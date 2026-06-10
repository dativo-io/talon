package cache

import "time"

// TierLabel converts a numeric classifier tier (0-2) to the string label used
// by the cache policy vocabulary and the ttl_by_tier config keys.
func TierLabel(tier int) string {
	switch tier {
	case 1:
		return "internal"
	case 2:
		return "confidential"
	default:
		return "public"
	}
}

// TTLForTier resolves the cache TTL for a tier label: ttl_by_tier[label] when
// set and positive, otherwise defaultTTL, otherwise one hour. Both config
// values are seconds.
func TTLForTier(label string, byTier map[string]int, defaultTTL int) time.Duration {
	if secs, ok := byTier[label]; ok && secs > 0 {
		return time.Duration(secs) * time.Second
	}
	if defaultTTL > 0 {
		return time.Duration(defaultTTL) * time.Second
	}
	return time.Hour
}
