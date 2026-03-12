# 测试策略与环境规划 (Test Strategy & Environment)

## 1. 测试策略概述 (Overview)
本项目采用 **测试驱动开发 (TDD)** 的思想，在编码前先规划测试环境和用例。测试分为三个层级：
1.  **单元测试 (Unit Tests)**: 针对独立函数和类（如 URL 过滤逻辑、SQL 注入 Payload 生成）。
2.  **集成测试 (Integration Tests)**: 针对模块间交互（如 爬虫 -> 数据库 -> 扫描器）。
3.  **端到端测试 (E2E Tests)**: 针对真实靶场的完整扫描流程。

## 2. 技术栈 (Tech Stack)
- **测试框架**: `pytest` (功能强大，插件丰富)
- **异步测试**: `pytest-asyncio` (配合 Playwright 和 httpx)
- **E2E 浏览器引擎**: `Playwright`
- **本地靶场**: `Docker Compose` (编排 ctf-games 中的靶场)

## 3. 本地靶场环境 (Local Targets)
为了确保扫描器的准确性，我们引入了 [ctf-games](https://github.com/c4pr1c3/ctf-games) 作为子模块，利用其中丰富的靶场资源作为“被测系统 (SUT)”。

### 3.1 推荐靶场 (Selected Targets)
我们主要使用 `tests/ctf-games` 目录下的以下靶场：

| 靶场路径 (相对于 tests/ctf-games) | 用途 | 端口 (需配置) |
| :--- | :--- | :--- |
| `dvwa` | DVWA (Damn Vulnerable Web App) 经典漏洞练习环境 | 8086 |
| `owasp/juice-shop` | OWASP Juice Shop 现代化 Web 应用漏洞靶场 | 3000 |
| `owasp/webgoat` | OWASP WebGoat 综合漏洞教学靶场 (包含 v7/v8/Latest) | 8081 (Latest), 8088 (v8), 8087 (v7) |

*(注：具体端口配置需参考对应目录下的 docker-compose.yml)*

### 3.2 启动方式
```bash
# 初始化子模块
git submodule update --init --recursive

# 启动某个具体靶场 (例如 dvwa)
cd tests/ctf-games/dvwa
docker-compose up -d
```

### 3.3 目录结构
```
tests/
├── ctf-games/            # [Submodule] 外部靶场集合
├── targets/              # 自定义靶场配置 (如有需要)
├── unit/                 # 单元测试
│   ├── test_url_filter.py
│   └── test_payloads.py
├── integration/          # 集成测试
│   └── test_crawler_db.py
└── e2e/                  # 端到端测试
    ├── test_scan_wordpress.py
    └── test_scan_sqli.py
```

## 4. 测试数据准备 (Test Data)
- **Payload 字典**: 准备一份标准的 SQLi 和 XSS 测试向量集合 (`tests/data/payloads.json`)。
- **预期结果**: 针对每个靶场 URL，记录预期的漏洞类型和数量，用于断言测试结果。

## 5. 持续集成 (CI)
- 在 GitHub Actions 中集成测试流程：
    1.  Checkout 代码 (含 submodules)
    2.  启动指定 Docker Compose 靶场
    3.  等待靶场就绪 (Health Check)
    4.  运行 `pytest`
