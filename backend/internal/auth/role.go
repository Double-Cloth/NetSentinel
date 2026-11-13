// Package auth 定义三角色契约，认证与会话在后续增量接入。
package auth

type Role string

const (
	Admin   Role = "admin"
	Analyst Role = "analyst"
	Auditor Role = "auditor"
)

func (r Role) Valid() bool { return r == Admin || r == Analyst || r == Auditor }
