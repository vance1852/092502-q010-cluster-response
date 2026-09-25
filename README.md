# 家具产业集群协作资料服务

维护园区、企业、应急联系人、可共享资源目录，并提供**集群联防协同**能力：把各家具企业上报的脱敏废气风险信号归入事件，按版本化预案判定升级级别、牵头人与响应时限，协调跨企业备用设备与技术人员，同时保证企业敏感生产数据互不可见、资源账本始终平衡、指挥链唯一且审计可追溯。

系统采用 Python 标准库和 SQLite，可在单个 Linux 进程中运行。所有写操作都在事务中完成，同一请求编号携带相同内容时返回原结果，内容发生变化时返回业务冲突。全部状态落 SQLite，服务重启后继续有效。

## 能力概览

基础资料：操作者与角色登记、场所台账、领域资料记录（cluster_profile、member_enterprise、emergency_contact、resource_catalog）、请求幂等校验、哈希串联审计。

集群联防：

- **脱敏信号归并**：企业只上报标量脱敏字段（severity、supply_code、fingerprint 与受限键值对）。同园区、同告警类型的信号归入同一在处事件；同一场所同一指纹的重复信号合并来源（reports 追加、repeat_count 增加），不产生重复事件。
- **事件判定与升级**：纯函数规则区分 `single_fault`（单厂故障）、`shared_supply`（多家企业命中同一共用供应代码）、`regional`（覆盖三家及以上企业，或两家且含高严重度）。事件绑定创建时的预案版本，新信号到达即重算分类、级别、牵头人与响应时限；重复信号若严重度升高也会触发重评。
- **版本化预案**：预案按 `plan_id` 逐版本追加，内容与最新版本一致时拒绝重复发布；事件可由指挥人员显式采用更新预案版本。手动指定的牵头人不会被自动规则覆盖。
- **共享能力与带版本预占/确认**：企业声明可共享的备用设备/技术人员；指挥人员必须携带能力当前版本才能预占（乐观并发），确认携带预占版本。预占、确认、释放、撤回都在**单事务**内同时更新能力账本与调拨记录，任何中途失败整体回滚，绝不留下不平衡扣减。
- **撤回语义**：企业撤回共享量只影响**尚未确认**的部分；空闲量不足时按预占时间顺序撤销未确认预占，已确认调用一律保留。事件关闭时未确认预占自动释放。
- **终态与附录**：事件关闭后到达的信号进入**附录**（`in_appendix` / `late_count`），不重开终态、不改变级别；新一轮联防由指挥人员显式开启。
- **按角色裁剪的查询**：参与企业看到自身责任（本企业完整信号、本企业能力明细）与去身份化聚合态势（peer-N、资源总量/确认量）；街道指挥侧与监管角色可追溯完整来源（组织、场所、指纹、每次上报 payload 哈希）；无关企业无权查看。审计员只读。
- **唯一指挥链与完整审计**：每个事件只有一个牵头人；所有动作写入哈希串联审计链，可离线校验。

## 目录

- `src/cluster_response_core/`：领域模型、SQLite 存储、权限服务、审计链、HTTP 路由和离线验收。
  - `incidents.py`：事件分级、关联与分类的纯领域规则；
  - `service.py`：预案、信号/事件、能力/调拨、裁剪视图等用例；
  - `storage.py`：建表、事务边界与多线程串行化；
- `tests/`：核心规则、事务边界、并发超卖、失败回滚、字段裁剪、接口路由和端到端验收测试。

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

命令在临时 SQLite 数据库中登记主体、场所、资料，并完整走一遍集群联防（单厂→共用供应→区域升级、预占/确认/撤回、关闭后迟到信号进附录、跨企业字段裁剪），核对幂等回执与审计链，成功时输出一行 `status` 为 `ok` 的 JSON 并以退出码 `0` 结束。

## HTTP 服务

```bash
PYTHONPATH=src python3 -m cluster_response_core.api --database cluster_response_core.sqlite3 --host 127.0.0.1 --port 8080
```

健康检查使用 `GET /health`。业务接口通过 `X-Actor-Id` 标识操作者，所有写接口要求 `request_id` 以保证幂等。

基础接口：`POST /organizations`、`POST /actors`、`POST /sites`（支持 `cluster_id`、组织支持 `is_regulator`）、`POST /domain-records`、`GET /domain-records`、`GET /audit-events`。

集群联防接口：

| 接口 | 角色 | 说明 |
| --- | --- | --- |
| `POST /plans` | admin | 发布新版本预案 |
| `POST /signals` | 企业/监管 | 上报脱敏风险信号，自动建事件、合并或进附录 |
| `POST /incidents/open` | 指挥侧 | 关闭后开启新一轮事件 |
| `POST /incidents/close` | 指挥侧 | 关闭事件并自动释放未确认预占 |
| `POST /incidents/reassign-lead` | 指挥侧 | 指定唯一牵头人（之后不被自动覆盖） |
| `POST /incidents/adopt-plan` | 指挥侧 | 采用指定/最新预案版本并重算 |
| `GET /incidents` | 相关方 | 事件摘要列表（按角色过滤） |
| `GET /incidents/{id}` | 相关方 | 事件详情（按角色裁剪字段） |
| `POST /capabilities` | 企业 | 声明可共享能力 |
| `GET /capabilities` | 已登录 | 本企业明细 + 去身份化集群聚合 |
| `POST /allocations/reserve` | 指挥 | 带能力版本预占 |
| `POST /allocations/confirm` | 指挥 | 带预占版本确认 |
| `POST /allocations/release` | 指挥 | 释放未确认预占 |
| `POST /capabilities/withdraw` | 能力所属企业 | 撤回未确认共享量 |
