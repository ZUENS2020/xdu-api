# XDU 课表 API

基于 XDYou (traintime_pda) 逆向分析的 ehall 课表数据接口。

## 使用方法

### 1. 注入 Cookie

在浏览器登录 ehall 后，从开发者工具提取 Cookie：

```bash
curl -X POST http://localhost:8500/api/cookies \
  -H "Content-Type: application/json" \
  -d '{"cookies": {"JSESSIONID": "xxx", "iPlanetDirectoryPro": "xxx"}}'
```

### 2. 查课表

```bash
# 明天课表
curl http://localhost:8500/api/tomorrow

# 今天课表
curl http://localhost:8500/api/today

# 本周全部
curl http://localhost:8500/api/schedule

# 指定周
curl http://localhost:8500/api/week?week=1
```

### 3. 检查登录状态

```bash
curl http://localhost:8500/api/status
```

## API 端点

| 端点 | 说明 |
|------|------|
| GET /api/health | 健康检查 |
| GET /api/status | 登录状态 |
| POST /api/cookies | 注入 Cookie |
| GET /api/schedule | 完整课表 |
| GET /api/today | 今天课程 |
| GET /api/tomorrow | 明天课程 |
| GET /api/week?week=X | 第X周课程 |

## 技术细节

- 基于 XDYou 项目的 ehall 接口分析
- 使用 ehall app ID: 4770397878132218 (本科课表)
- 默认学期: 2025-2026-2，学号: 25009290006
- 数据存储: Docker volume xdu-data
