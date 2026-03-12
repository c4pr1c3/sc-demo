# Agent Teams 分工方案

## 项目背景
开发一款自动化 Web 应用漏洞扫描器，支持 SPA 爬取、SQL注入/XSS 检测、任务持久化恢复等功能。

---

## Team 结构总览

```
┌─────────────────────────────────────────────────────────────────┐
│                      Orchestrator Agent                         │
│                    (项目协调与整体调度)                          │
└─────────────────────────────────────────────────────────────────┘
                            │
        ┌───────────────────┼───────────────────┐
        │                   │                   │
        ▼                   ▼                   ▼
┌───────────────┐  ┌───────────────┐  ┌───────────────┐
│  Crawler Team │  │  Scanner Team │  │  Infra Team   │
│   (爬虫组)    │  │   (扫描组)    │  │  (基础设施)   │
└───────────────┘  └───────────────┘  └───────────────┘
        │                   │                   │
        ├───────────────────┤                   │
        ▼                   ▼                   ▼
┌───────────────┐  ┌───────────────┐  ┌───────────────┐
│ Playwright    │  │  SQLi Agent   │  │  DB Agent     │
│ Specialist    │  │  XSS Agent    │  │  Docker Agent │
│               │  │  Sensitive    │  │  Reporter     │
│               │  │  Agent        │  │  Agent        │
└───────────────┘  └───────────────┘  └───────────────┘
```

---

## 详细角色定义

### 1. Orchestrator Agent (协调者)
**角色定位**: 项目整体调度与协调

**职责范围**:
- 任务分发与进度跟踪
- 团队间协作协调
- 决策冲突解决
- 里程碑验收

**关键交互**:
- ← 接收用户需求
- → 分发任务给各 Team
- ← 收集各 Team 进度报告
- → 输出整体状态

---

### 2. Crawler Team (爬虫组)

#### 2.1 Playwright Specialist
**角色定位**: SPA 爬虫专家

**职责范围**:
- Playwright 爬虫引擎实现
- 动态页面渲染处理
- 表单提取与解析
- 资源过滤逻辑

**技术要点**:
- Playwright for Python API
- 异步爬虫架构 (asyncio)
- JavaScript 执行与等待策略
- URL 去重与队列管理

**交付物**:
- `src/crawler/engine.py`
- `src/crawler/parser.py`
- `src/crawler/filter.py`

---

### 3. Scanner Team (扫描组)

#### 3.1 SQLi Agent
**角色定位**: SQL 注入检测专家

**职责范围**:
- SQL 注入 Payload 设计
- 报错/布尔/时间盲注检测
- SQLMap 集成与调用
- 漏洞验证逻辑

**技术要点**:
- SQLMap API/子进程调用
- 盲注延迟检测算法
- Payload 编码与转义

**交付物**:
- `src/scanner/sqli/detector.py`
- `src/scanner/sqli/sqlmap_wrapper.py`

#### 3.2 XSS Agent
**角色定位**: XSS 检测专家

**职责范围**:
- 反射型 XSS Payload 设计
- Headless 浏览器回显匹配
- DOM 型 XSS 检测

**技术要点**:
- XSS Payload 变种库
- 浏览器响应分析
- 上下文感知注入

**交付物**:
- `src/scanner/xss/detector.py`
- `src/scanner/xss/payloads.py`

#### 3.3 Sensitive Agent
**角色定位**: 敏感信息泄露检测专家

**职责范围**:
- 常见敏感路径扫描 (.git, .env)
- 备份文件检测 (.bak, .swp)
- 配置文件泄露检测

**技术要点**:
- 字典生成与路径组合
- 状态码与内容匹配

**交付物**:
- `src/scanner/sensitive/detector.py`
- `src/scanner/sensitive/paths.py`

---

### 4. Infra Team (基础设施组)

#### 4.1 DB Agent
**角色定位**: 数据持久化专家

**职责范围**:
- SQLite 数据库设计
- 任务状态持久化
- 断点续传机制
- 数据查询与恢复接口

**技术要点**:
- SQLite Schema 设计
- 事务处理与并发控制
- 数据迁移策略

**交付物**:
- `src/storage/db.py`
- `src/storage/models.py`
- `src/storage/task_manager.py`

#### 4.2 Docker Agent
**角色定位**: 测试环境专家

**职责范围**:
- Docker 靶场搭建 (DVWA, sqli-labs)
- Docker Compose 编排
- 环境隔离与配置

**技术要点**:
- Docker Compose 语法
- 容器网络配置

**交付物**:
- `docker-compose.yml`
- `tests/targets/Dockerfile`

#### 4.3 Reporter Agent
**角色定位**: 报告生成专家

**职责范围**:
- HTML 报告模板设计
- JSON 格式输出
- 漏洞详情渲染
- HTTP 请求/响应包展示

**技术要点**:
- Jinja2 模板引擎
- JSON 序列化

**交付物**:
- `src/reporter/html_gen.py`
- `src/reporter/json_gen.py`
- `src/reporter/templates/report.html`

---

## 协作流程

### 阶段 1: 项目初始化
```
Orchestrator → Infra/DB Agent
  任务: 设计数据库 Schema，搭建基础项目结构
```

### 阶段 2: 爬虫开发
```
Orchestrator → Crawler/Playwright Specialist
  任务: 实现 URL 抓取，存入 DB
```

### 阶段 3: 扫描器集成
```
Orchestrator → Scanner Team
  任务: 从 DB 获取 URL，执行检测，结果回写 DB
```

### 阶段 4: 报告与验证
```
Orchestrator → Reporter Agent
  任务: 读取 DB 结果，生成报告
Orchestrator → Docker Agent
  任务: 启动靶场，验证扫描效果
```
