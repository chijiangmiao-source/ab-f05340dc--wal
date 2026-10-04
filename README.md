# 星载姿控参数 · 崩溃恢复审计服务

断电恢复后,审计员需要确认:**未提交事务不会残留在参数页中,已提交但尚未落盘的
更新也不会丢失**。本服务对星载姿控参数页执行 ARIES 风格的三阶段恢复裁决
(分析 → 重做 → 撤销),并冻结可复核的裁决证据。

## 快速开始(Docker Compose)

```bash
cp .env.example .env        # 可选:修改 HOST_PORT(默认 8080)
docker compose up -d --build app   # 启动审计服务
# 浏览器访问 http://localhost:${HOST_PORT}  健康响应 http://localhost:${HOST_PORT}/health

# verify 容器:规则测试 + 构建检查 + API/HTTP 冒烟,完成后以退出码结束
docker compose run --rm verify; echo "verify exit=$?"
# 或:docker compose up --exit-code-from verify --abort-on-container-exit verify
```

无 Docker 的本地环境:

```bash
PORT=8000 python3 app/server.py &                       # 启动服务
BASE_URL=http://127.0.0.1:8000 python3 verify/run_tests.py
```

## 输入契约(POST /api/recover)

```json
{
  "audit_id": "SAT-ATT-2026-001",
  "pages": [{"page_id": 7, "page_lsn": 110, "data": "11110000..."}],
  "wal": [
    {"lsn": 100, "type": "begin", "txn": "T1"},
    {"lsn": 110, "type": "update", "txn": "T1", "prev_lsn": 100,
     "page_id": 7, "offset": 0, "length": 2, "before": "0000", "after": "1111"},
    {"lsn": 140, "type": "checkpoint",
     "txns": [{"txn": "T1", "last_lsn": 110, "status": "running"}],
     "dpt": [{"page_id": 7, "rec_lsn": 110}]},
    {"lsn": 160, "type": "commit", "txn": "T1", "prev_lsn": 150}
  ]
}
```

- 至多 **48** 个初始页像(含崩溃时 `page_lsn`)、至多 **128** 条按 LSN **严格递增**
  排列的受限 WAL 记录;记录类型:`begin / update / commit / abort / end / checkpoint`
- `update` 必须携带事务前驱 `prev_lsn`、页号、页内**半开区间**
  `[offset, offset+length)`,以及等长的前后字节(`before`/`after` 十六进制)

## 恢复语义

1. **分析**:自最后一个检查点播种事务表(TT)与脏页表(DPT),扫描至 WAL 末尾;
   结束时 TT 中 `running/aborting` 的事务为失败事务(loser),`committed` 为获胜事务
2. **重做**:自 DPT 最小 recLSN 起扫描;仅当更新属于脏页、`LSN ≥ recLSN` 且
   `pageLSN < LSN`(确有缺失)时,校验前像后改写页像并推进 pageLSN
3. **撤销**:按最大 LSN 优先沿失败事务前驱链逆序回退;仅当
   `pageLSN ≥ 更新 LSN`(更新确在页上)时校验后像、恢复前像,并写入 CLR
   (自最大输入 LSN 起分配新 LSN)

## 冻结裁决与证据清除

- 成功:`200` + 冻结裁决(逐条分析归属/重做判据/撤销判据、恢复前后 pageLSN、
  最终页像 SHA-256、`verdict_sha256` 指纹);裁决不含时钟字段,同一输入恒定
- 拒绝:`422` + 稳定错误码;**该审计标识的旧成功证据同时被清除**
- `GET /api/verdict/<audit_id>` 读取已冻结裁决;无则 `404`

## 稳定拒绝码

| 代码 | 含义 |
| --- | --- |
| `LIMIT_EXCEEDED` | 页像 > 48 或 WAL > 128 |
| `DUPLICATE_LSN` / `LSN_OUT_OF_ORDER` | LSN 重复 / 未严格递增 |
| `BROKEN_CHAIN` | 前驱链损坏(前驱缺失、错位或指向其他事务) |
| `TXN_ENDED` | 已 `end` 的事务仍被后续记录引用 |
| `INTERVAL_OUT_OF_BOUNDS` | 半开区间越出页界 |
| `BAD_IMAGE_LENGTH` / `BAD_HEX` | 前后像长度不符 / 非法十六进制 |
| `BEFORE_IMAGE_MISMATCH` / `UNDO_IMAGE_MISMATCH` | 重做前像 / 撤销后像与页像不符 |
| `UNKNOWN_PAGE` / `DUPLICATE_PAGE` | 页像缺失 / 页号重复 |
| `BAD_CHECKPOINT` / `BAD_RECORD` / `BAD_AUDIT_ID` | 检查点或记录结构非法 |

## 目录结构

```
app/recovery.py    ARIES 恢复引擎(纯函数,可独立测试)
app/server.py      标准库 HTTP 服务(页面 / API / 健康)
app/static/index.html  审计页面
verify/run_tests.py    verify 容器入口(规则 + 构建 + 冒烟,退出码收尾)
Dockerfile / docker-compose.yml / .env.example
```
