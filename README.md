# 家具产业集群协作资料服务

维护园区、企业、应急联系人和可共享资源目录，为跨企业协作提供隔离的主体与审计基础。

系统采用 Python 标准库和 SQLite，可在单个 Linux 进程中运行。现有能力包括操作者与角色登记、场所台账、领域资料记录、请求幂等校验、哈希串联审计以及轻量 HTTP/JSON 接口。领域资料类别为：cluster_profile、member_enterprise、emergency_contact、resource_catalog。所有写操作都在事务中完成，同一请求编号携带相同内容时返回原结果，内容发生变化时返回业务冲突。

## 目录

- `src/cluster_response_core/`：领域模型、SQLite 存储、权限服务、审计链、HTTP 路由和离线验收；
- `tests/`：核心规则、事务边界、接口路由和端到端验收测试。

## 测试

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

## 构建检查

```bash
python3 -m compileall -q src tests
```

## 离线验收

```bash
PYTHONPATH=src python3 -m cluster_response_core.acceptance
```

命令会在临时 SQLite 数据库中登记操作者、场所和领域资料，核对幂等回执与审计链，成功时输出一行 `status` 为 `ok` 的 JSON 并以退出码 `0` 结束。

## HTTP 服务

```bash
PYTHONPATH=src python3 -m cluster_response_core.api --database cluster_response_core.sqlite3 --host 127.0.0.1 --port 8080
```

健康检查使用 `GET /health`。业务写入接口通过 `X-Actor-Id` 标识操作者，支持操作者、场所和领域资料的登记，以及审计事件查询。服务重启后，SQLite 中的业务状态和审计链继续保留。
