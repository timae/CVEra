package repository

import (
	"database/sql"
	"fmt"
	"strings"
	"time"
)

func isPostgres(db *sql.DB) bool {
	return strings.Contains(fmt.Sprintf("%T", db.Driver()), "pgx")
}

func rebindPlaceholders(db *sql.DB, query string) string {
	if !isPostgres(db) {
		return query
	}
	var b strings.Builder
	index := 1
	for _, r := range query {
		if r == '?' {
			fmt.Fprintf(&b, "$%d", index)
			index++
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

func formatDBTime(t time.Time) any {
	return t.UTC()
}

func parseDBTime(raw any) (time.Time, error) {
	switch v := raw.(type) {
	case time.Time:
		return v.UTC(), nil
	case string:
		return parseDBTimeString(v)
	case []byte:
		return parseDBTimeString(string(v))
	default:
		return time.Time{}, fmt.Errorf("unsupported time type %T", raw)
	}
}

func parseDBTimeString(value string) (time.Time, error) {
	layouts := []string{
		time.RFC3339Nano,
		time.RFC3339,
		"2006-01-02 15:04:05.999999999 -0700 MST",
		"2006-01-02 15:04:05 -0700 MST",
		"2006-01-02 15:04:05",
	}
	var lastErr error
	for _, layout := range layouts {
		ts, err := time.Parse(layout, value)
		if err == nil {
			return ts.UTC(), nil
		}
		lastErr = err
	}
	return time.Time{}, lastErr
}

func nullableString(s string) any {
	if s == "" {
		return nil
	}
	return s
}
