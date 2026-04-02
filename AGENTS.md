# AGENTS.md — 系统架构与模块说明

## 系统架构

```
URL → Crawler → Pages → Detectors → Vulnerabilities → Reporter → Reports
                  ↑                      ↑
                  └── login/auth         └── payloads/*.yaml
```

## 数据流

1. **Crawler** 登录目标站点，BFS 爬取页面，提取表单和链接
2. **Detector Registry** 遍历所有注册检测器，逐个调用 `scan()`
3. 每个 **Detector** 从 `payloads/*.yaml` 加载 Payload，执行检测逻辑
4. 检测结果汇总为 `list[Vulnerability]`，交由 **Reporter** 生成报告

## 模块职责

### 核心模块 (`src/vulnscan/`)

| 模块 | 职责 |
|------|------|
| `cli.py` | CLI 入口，扫描管线编排 |
| `crawler.py` | HTTP 爬虫：登录、CSRF 处理、BFS 爬取、表单提取 |
| `scanner.py` | SQLi 检测引擎：报错注入 + 布尔盲注 |
| `xss.py` | 反射型 XSS 检测：Payload 注入 + 响应反射匹配 |
| `sensitive.py` | 敏感路径扫描：路径枚举 + 关键词验证 |
| `reporter.py` | 报告生成：JSON + HTML (Jinja2) |
| `models.py` | 数据模型：VulnType, Severity, Vulnerability 等 |

### Payload 模块 (`src/vulnscan/payloads/`)

| 文件 | 内容 |
|------|------|
| `__init__.py` | Payload 加载器：`load_payloads(name)`, `list_payloads()` |
| `sqli.yaml` | SQL 注入 Payload：error_based, boolean_blind |
| `xss.yaml` | XSS Payload：reflected payloads + reflection_markers |
| `sensitive.yaml` | 敏感路径字典：分类路径 + 关键词 + 严重级别 |

### 检测器模块 (`src/vulnscan/detectors/`)

| 文件 | 职责 |
|------|------|
| `base.py` | BaseDetector ABC + 注册表 (`register`, `get_detectors`) |
| `sqli.py` | SQLi 检测器适配器 |
| `xss.py` | XSS 检测器适配器 |
| `sensitive.py` | 敏感路径检测器适配器 |

## 扩展新漏洞类型

三步完成，无需修改调度器、CLI 或报告生成器：

1. **创建 Payload 文件**: `src/vulnscan/payloads/<name>.yaml`
2. **创建检测器**: `src/vulnscan/detectors/<name>.py`，继承 `BaseDetector`，实现 `name` + `scan()`
3. **注册**: 在 `detectors/__init__.py` 中添加 `import vulnscan.detectors.<name>`
4. **可选**: 在 `models.py` 的 `VulnType` 枚举中添加新类型

## Payload YAML 格式规范

```yaml
version: "1.0"
description: "简短描述"

# 检测相关数据（结构由检测器自定义）
category:
  payloads: [...]
  detection_patterns: [...]
```

- `version`: 语义化版本，用于未来迁移
- `description`: 人类可读描述
- 具体结构由对应检测器定义和消费

## 检测器接口规范

```python
class BaseDetector(ABC):
    @property
    @abstractmethod
    def name(self) -> str: ...

    @abstractmethod
    def scan(self, pages: list[PageResult], base_url: str,
             username: str, password: str) -> list[Vulnerability]: ...
```

## CI/CD

- GitHub Actions: `.github/workflows/ci.yml`
- 触发: push/PR 到 main 分支
- 测试环境: `vulnerables/web-dvwa` Docker 容器 (port 8086)
- 流程: checkout → setup Python → install → wait DVWA → pytest
