# CLAUDE.md — 项目开发约定

## 技术栈决策

| 决策 | 选择 | 理由 |
|------|------|------|
| HTTP 客户端 | httpx | 同步 API 简洁，超时/重定向控制好，替代 requests |
| HTML 解析 | BeautifulSoup4 | 容错性强，适合扫描不可控的 HTML |
| 报告模板 | Jinja2 | HTML 报告模板引擎，Python 标配 |
| CLI 框架 | argparse | 标准库零依赖，功能够用 |
| 数据格式 | JSON 文件 | 轻量可读，无需数据库 |
| 并发模型 | 同步 | MVP 阶段足够，避免 asyncio 复杂度 |
| Payload 存储 | YAML 外置 | 独立于代码维护，方便扩展 |
| 测试靶场 | DVWA | 社区标准靶场，Docker 一键启动 |

## 架构约束

- **不使用 Playwright/Selenium** — 纯 HTTP 层面检测，MVP 不需要浏览器渲染
- **不使用外部漏洞数据库** — 手写 Payload，针对课程项目足够
- **不使用数据库** — JSON 文件持久化结果，保持简单

## Payload 管理规范

- Payload 数据存放于 `src/vulnscan/payloads/*.yaml`
- 每个 YAML 文件包含 `version` 和 `description` 元信息
- 通过 `vulnscan.payloads.load_payloads(name)` 加载
- 检测器模块在导入时加载 YAML（模块级变量），不延迟加载

## 检测器插件规范

- 所有检测器继承 `vulnscan.detectors.base.BaseDetector`
- 实现 `name` 属性和 `scan()` 方法
- 在模块末尾调用 `register(YourDetector())` 自注册
- 在 `detectors/__init__.py` 中 import 模块以触发注册
- CLI 通过 `get_detectors()` 遍历所有注册检测器

## 测试策略

- DVWA 为唯一集成测试靶场
- `tests/conftest.py` 提供 DVWA 等待和认证 fixture
- `tests/test_payloads.py` 不依赖外部服务，验证 YAML 结构
- GitHub Actions CI 使用 `services: dvwa` 容器
- 测试断言：SQLi 检出 > 0、XSS 检出 > 0、CSRF 零误报、总漏洞 >= 3
