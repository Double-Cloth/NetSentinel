// Package migrations 嵌入按编号排列的数据库迁移。
package migrations

import "embed"

//go:embed *.sql
var Files embed.FS
