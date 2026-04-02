# Web 应用漏洞扫描器

自动化 Web 安全漏洞扫描工具，支持 SQL 注入检测、反射型 XSS 检测、敏感信息泄露扫描，并自动生成 HTML/JSON 格式的扫描报告。

## 功能特性

- **智能爬虫**: 基于 httpx + BeautifulSoup，自动处理登录（含 CSRF Token）、BFS 站点爬取、表单提取
- **SQL 注入检测**: 报错注入 + 布尔盲注双模式检测，手写 Payload 无需外部工具
- **反射型 XSS 检测**: 多种 Payload 变体，响应内容反射匹配
- **敏感信息泄露**: 扫描 .git、.env、phpinfo 等常见敏感路径
- **报告生成**: 同时输出 HTML（可视化）和 JSON（可集成）两种格式
- **CLI 工具**: 一条命令完成 爬取→检测→报告 全流程

## 快速开始

### 安装

```bash
pip install -e .
```

### 启动测试靶场

```bash
cd tests/ctf-games/dvwa && docker-compose up -d
# DVWA 运行在 http://localhost:8086
```

### 运行扫描

```bash
# 基本用法
python -m vulnscan scan http://localhost:8086

# 指定凭据和输出目录
python -m vulnscan scan http://localhost:8086 -u admin -p password -o ./reports

# 详细输出
python -m vulnscan scan http://localhost:8086 -v
```

### 扫描结果示例

```
============================================================
  VULNERABILITIES FOUND: 7
============================================================
  sqli_blind: 2
  sqli_error: 1
  xss_reflected: 1
  sensitive_info: 3

  [sqli_error] http://localhost:8086/vulnerabilities/sqli/
    param=id  payload='
  [xss_reflected] http://localhost:8086/vulnerabilities/xss_r/
    param=name  payload=<script>alert(1)</script>

Reports saved:
    JSON: ./scan_results.json
    HTML: ./scan_report.html
```

## 项目结构

```
src/vulnscan/
├── cli.py         # CLI 入口 + 扫描管线
├── crawler.py     # httpx+BS4 爬虫, 登录/CSRF处理
├── scanner.py     # SQL 注入检测引擎
├── xss.py         # 反射型 XSS 检测
├── sensitive.py   # 敏感路径扫描
├── reporter.py    # JSON + HTML 报告生成
├── models.py      # 数据模型定义
├── __init__.py
└── __main__.py
```

## 技术栈

- Python 3.10+
- httpx (HTTP 客户端)
- BeautifulSoup4 (HTML 解析)
- Jinja2 (HTML 报告模板)
- argparse (CLI)

## 测试靶场

项目内置 Docker 靶场环境：

| 靶场 | 端口 | 说明 |
|------|------|------|
| DVWA | 8086 | 主要测试目标 |
| OWASP Juice Shop | 3000 | V2 支持 |
| OWASP WebGoat | 8081/8087/8088 | V2 支持 |
