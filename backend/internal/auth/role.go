// Package auth 负责身份、登录校验及会话生命周期。
package auth

type Role string

const (
	Admin   Role = "admin"
	Analyst Role = "analyst"
	Auditor Role = "auditor"
)

func (r Role) Valid() bool { return r == Admin || r == Analyst || r == Auditor }
