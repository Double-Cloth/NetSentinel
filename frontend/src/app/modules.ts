export const modules = [
  { path: '/', label: '工作台', current: '', next: '' },
  { path: '/datasets', label: '数据集', current: '统一事件模型与原始证据引用已建立。', next: '接入 SSH、Nginx 预览、导入与事件查询。' },
  { path: '/rules', label: '规则库', current: 'Count 编译校验与 R-001 固定样例可运行。', next: '接入规则草稿、发布、版本历史与沙箱。' },
  { path: '/tasks', label: '分析任务', current: '独立引擎迭代器、接收器与运行指标已建立。', next: '接入后台队列、任务快照与原子结果发布。' },
  { path: '/alerts', label: '告警', current: 'Count 命中解释、完整证据与稳定指纹已建立。', next: '接入告警持久化、认领、处置与历史。' },
  { path: '/audit', label: '审计', current: '审计基础表与请求标识已建立。', next: '接入关键业务操作审计和查询。' },
  { path: '/settings', label: '系统设置', current: '三角色契约与身份基础表已建立。', next: '接入登录、RBAC、CSRF、用户管理与飞书通知。' },
] as const

export const progress = [
  ['独立引擎', 'Count 与证据快照', 'Distinct、Sequence'],
  ['日志解析', '事件契约已建立', 'SSH、Nginx 导入'],
  ['规则管理', 'R-001 固定样例', '草稿、发布、版本'],
  ['身份与权限', '角色契约已建立', '登录、RBAC、CSRF'],
  ['分析与告警', '引擎入口可运行', '异步任务、告警处置'],
]
