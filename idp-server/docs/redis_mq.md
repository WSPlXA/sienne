# Redis Stream + MySQL 金融日志旁路入库 Demo


## 1. 背景

### Situation

在高并发交易、支付、审计、风控留痕这类场景里，主交易链路往往要求低延迟，但日志、流水、审计数据又不能轻易丢失。

如果把金融日志直接同步写 MySQL，常见问题会很快出现：

- 主交易接口 RT 被日志写库拖慢
- MySQL 在突发高峰时被大量小事务打满
- 一旦数据库抖动，主业务和日志链路一起受影响
- 业务代码里会充满“失败重试、补偿、兜底写库”的复杂逻辑

这就是这个 demo 想解决的起点：日志不能成为主交易链路的阻塞点，但日志本身又必须做到最终可达、可恢复、可对账。

### 为什么不直接用 Kafka

这个场景里并不是 Kafka 不好，而是这里刻意选择了更轻量的方案。

不直接上 Kafka 的主要原因是：

- 目标是做一个小而完整的 demo，强调高可靠最终一致性，不是演示大规模 MQ 集群治理
- 对很多中小团队来说，Kafka 的部署、分区、Broker 运维、消费位点治理和容量规划成本更高
- 这里的问题核心首先是“旁路削峰 + 异步落库 + 故障补偿”，这些能力 Redis Stream 已经能提供最小闭环
- 在单机到中等规模场景里，Redis Stream 的接入成本更低，更适合快速验证架构思路

所以这里不是说 Kafka 不适合，而是这个 demo 的目标是：先用更低复杂度的基础设施，把金融日志高可靠最终一致性的核心机制讲清楚。

## 2. 目标

### Task

这个 demo 要解决的问题可以归纳成四点：

1. 主交易链路不能被金融日志写库阻塞。
2. 高并发下日志要能先削峰、排队，再异步落库。
3. 日志链路在 Redis、消费者、MySQL 出现短时故障时，不能静默丢失。
4. 最终结果要能落到 MySQL 审计表里，并具备 replay 和后续对账的基础。

这套方案追求的不是强一致，而是：

- `eventual consistency`
- `at-least-once`
- 幂等落库
- 故障可恢复
- 审计结果最终可达

换句话说，它的目标不是“主业务成功时日志已经同步写进 MySQL”，而是“主业务成功后，日志最终会被可靠补齐进审计库”。

## 3. 先解释几个核心术语

为了让后面的方案描述更容易理解，这里先把文中反复出现的几个词说明白。

### ACK

`ACK` 是 `acknowledgement`，意思是“消费者确认这条消息已经处理完成”。

在 Redis Stream Consumer Group 里，一条消息被消费者读到以后，并不会自动消失。只有消费者显式执行 `XACK`，Redis 才会认为这条消息已经处理完，可以从待确认集合里移除。

这个 demo 里，`ACK` 的含义非常具体：

- 写入 MySQL 成功，才 ACK
- 或者写入 DLQ 成功，才 ACK

为什么这么严格：

- 如果先 ACK、后写库，消费者一旦崩溃，消息就真的丢了
- 对金融日志来说，重复可以靠幂等处理，但丢失很难补

### PEL

`PEL` 是 `Pending Entries List`，也就是“待确认消息列表”。

你可以把它理解成：

- Redis 已经把消息交给某个消费者了
- 但这个消费者还没有 ACK
- 所以 Redis 暂时把它记在 pending 里

PEL 的存在很关键，因为它让系统知道：

- 哪些消息已经发出去但还没真正处理完
- 哪些消息可能因为消费者挂掉而需要后续接管

### reclaim

`reclaim` 可以理解成“消息接管”或“超时回收”。

当一条消息长时间停留在 PEL 里，说明原来的消费者可能已经：

- 崩溃了
- 卡住了
- 写库失败后一直没处理完

这时另一个消费者可以把这条超时 pending 消息重新认领过来，再处理一次。这个过程在 README 里就叫 reclaim。

### DLQ

`DLQ` 是 `Dead Letter Queue`，也就是“死信队列”。

它用来存放那些短时间内无法正常落库、或者已经超过重试上限的消息。

为什么要有 DLQ：

- 不能让坏消息一直堵住主消费链路
- 也不能因为处理失败就直接丢弃

所以更合理的办法是：

- 先把失败消息隔离出来
- 后面修复问题后再 replay

### replay

`replay` 就是“重放”或“回灌”。

它的意思是：

- 从 DLQ 里把之前失败的消息重新拿出来
- 再次写回主 Stream
- 让消费者重新处理

这样做的目的不是重复制造消息，而是把之前因为临时故障、脏数据、程序 bug 导致失败的日志，在问题修复后重新补齐。

### at-least-once

`at-least-once` 的意思是：系统保证消息至少会被投递一次，但在故障恢复、超时接管、重复消费时，可能会被投递多次。

这不是缺点，而是一种常见的可靠性取舍：

- 优先保证“不丢”
- 重复由下游幂等去吸收

对于金融日志这种场景，这通常比“可能少投一次但绝不重复”更安全。

## 4. 我们做了什么

### Action

围绕上面的目标，这个 demo 做了 5 件核心事情。

### 3.1 生产端把“去重标记 + 入流”做成一个原子动作

关键代码：

- [scripts.go](/Users/gaosong/source_code/mq_redis/redis_mq/internal/redisx/scripts.go)
- [main.go](/Users/gaosong/source_code/mq_redis/redis_mq/cmd/producer/main.go)

关键片段在 [scripts.go](/Users/gaosong/source_code/mq_redis/redis_mq/internal/redisx/scripts.go)：

```lua
local inserted = redis.call('SET', KEYS[1], ARGV[1], 'NX', 'EX', ARGV[2])
if not inserted then
	return ''
end

local msg_id = redis.call(
	'XADD',
	KEYS[2],
	'*',
	'event_id', ARGV[1],
	'session_id', ARGV[3],
	'payload', ARGV[4],
	'produced_at', ARGV[5]
)
return msg_id
```

为什么这么做：

- 避免“去重标记写成功了，但消息没入流”
- 避免“消息入流了，但去重状态没写成功”
- 让生产端至少先把事件稳定推进到 Redis Stream

好处：

- 生产端逻辑简单
- 高并发下不会把状态一致性问题甩给业务层
- 为后续 `at-least-once + 幂等落库` 提供稳定入口

### 3.2 消费端只在两种情况下 ACK

关键代码：

- [service.go](/Users/gaosong/source_code/mq_redis/redis_mq/internal/consumer/service.go)

关键片段在 [service.go](/Users/gaosong/source_code/mq_redis/redis_mq/internal/consumer/service.go) 的 `persistBatch`、`handleSingle`、`moveEventToDLQ` 一组逻辑。

这套 ACK 规则是：

- 成功写入 MySQL 后，才 `XACK`
- 成功写入 DLQ 后，才 `XACK`

为什么这么做：

- 如果在持久化前 ACK，消费者进程崩溃、网络闪断、数据库超时都会导致消息直接丢失
- 旁路金融日志最怕的不是重复，而是静默丢失

好处：

- 失败时消息继续留在 PEL
- 即使发生重复投递，也可以交给下游幂等吸收
- 不会因为错误的 ACK 时机造成不可恢复的数据缺口

### 3.3 MySQL 端用主键幂等收敛重复投递

关键代码：

- [mysql.go](/Users/gaosong/source_code/mq_redis/redis_mq/internal/dbx/mysql.go)

关键片段在 [mysql.go](/Users/gaosong/source_code/mq_redis/redis_mq/internal/dbx/mysql.go) 的 `UpsertAuditLogs`：

```sql
INSERT INTO audit_logs (event_id, stream_id, session_id, payload, produced_at) VALUES ...
ON DUPLICATE KEY UPDATE
  stream_id = VALUES(stream_id),
  session_id = VALUES(session_id),
  payload = VALUES(payload),
  produced_at = VALUES(produced_at),
  updated_at = CURRENT_TIMESTAMP
```

为什么这么做：

- Redis Stream 消费语义天然更接近 `at-least-once`
- 一旦有 reclaim、重试、重复投递，数据库必须能吸收重复事件

好处：

- 消费端可以把重点放在“不丢消息”
- 不需要为了避免重复而冒险提前 ACK
- replay 时也可以复用同一个 `event_id`，不会写出重复账

### 3.4 消费失败时分层处理：重试、降级、DLQ

关键代码：

- [service.go](/Users/gaosong/source_code/mq_redis/redis_mq/internal/consumer/service.go)

关键片段：

- `flushBuffer`
- `handleSingle`
- `reclaimPending`

为什么这么做：

- 批量写库是为了吞吐
- 但批量失败时，不能把整批都当成永久失败
- 需要区分“数据库暂时不可用”和“单条消息本身有问题”

当前策略是：

- 批量成功：批量 `XACK`
- 批量可重试错误：留在 pending，等待后续 reclaim
- 批量不可重试错误：降级为单条处理
- 单条永久失败：进入 DLQ

好处：

- 既保留了微批吞吐
- 又避免一条坏消息拖死整批正常消息
- 失败消息能被明确隔离，方便后续修复和人工介入

### 3.5 给 DLQ 增加 replay 闭环

关键代码：

- [main.go](/Users/gaosong/source_code/mq_redis/redis_mq/cmd/replaydlq/main.go)
- [dlq.go](/Users/gaosong/source_code/mq_redis/redis_mq/internal/model/dlq.go)

为什么这么做：

- 金融日志链路不能只做到“失败隔离”
- 真正有价值的是“修复后可以补回来”

replay 工具会：

- 从 DLQ 读取失败事件
- 重建原始 `event_id/session_id/payload/produced_at`
- 重新写回主 Stream
- 让消费者再次按原有路径幂等落库

好处：

- 最终一致性真正形成闭环
- 失败不再只是“堆在 DLQ 等人工看”
- 后续可以继续扩展成审批式 replay、批次 replay、操作审计

## 5. 结果

### Result

这套 demo 最终达成的是：

- 主交易链路和日志落库链路完成了解耦
- Redis Stream 承担了高峰期削峰和排队的角色
- 消费侧通过 `at-least-once + 幂等落库` 把重点放在“不丢”
- 故障时可以通过 reclaim 接管 pending 消息
- 永久失败消息会进入 DLQ
- 修复后可以通过 replay 重新补齐

也就是说，这个 demo 已经不是一个简单的“异步写库示例”，而是一条具备最小可靠性闭环的金融日志旁路入库链路。

## 6. 优点和不足

### 优点

1. 架构足够轻。
不依赖 Kafka，就能把削峰、异步消费、幂等落库、失败隔离、回放闭环这套最关键的能力先跑起来。

2. 可靠性语义比较清楚。
它不是假装“强一致”，而是明确站在最终一致性的立场上，把重点放在最终可达和尽量不丢。

3. 对金融日志场景更贴切。
对于审计、流水、风控留痕这类旁路数据，真正重要的是不丢、可恢复、可对账，而不是让日志同步阻塞主交易。

4. 工程扩展路径明确。
现在已经有生产、消费、reclaim、DLQ、replay、监控，再往上加对账、背压、审批式 replay 都是顺着现有结构演进。

### 不足

1. Redis 仍然是当前阶段的核心瓶颈。
在高并发下，单 Redis 单线程很容易先到上限。

怎么克服：

- 做 producer 背压
- 做 Stream 分片
- 做 Redis 多实例路由
- 在更高量级再演进到 Kafka 或更强的消息中枢

2. 这不是强一致事务日志。
如果你的定义是“业务提交成功时，日志必须已经和主事务一起提交成功”，那这套不是那个语义。

怎么克服：

- 把日志事件先写入更强的持久层
- 引入业务本地 WAL / Outbox
- 在更高要求场景采用事务消息或更强的一致性方案

3. 还缺正式的对账能力。
现在有幂等、reclaim、replay，但还没有把“业务流水数、Redis 事件数、MySQL 落库数、DLQ 数”自动对平。

怎么克服：

- 增加定时对账任务
- 引入批次号和账务核对维度
- 做异常差异报警

4. replay 还不够审计化。
现在 replay 已经能用，但还没有操作审批、批次记录、操作者留痕。

怎么克服：

- 给 replay 增加 batch_id
- 记录 replay_operator / replay_reason
- 把 replay 本身也纳入审计表

5. 还没有主动背压。
当前更多是 Redis 在被动承压，还不是系统主动调速。

怎么克服：

- 根据 Redis CPU、stream lag、consumer buffer、DB latency 动态调整 producer 速率
- 在入口做限流与降级

## 7. 关键文件索引

- 生产端原子入流：[scripts.go](/Users/gaosong/source_code/mq_redis/redis_mq/internal/redisx/scripts.go)
- Producer 入口：[main.go](/Users/gaosong/source_code/mq_redis/redis_mq/cmd/producer/main.go)
- Consumer 核心状态机：[service.go](/Users/gaosong/source_code/mq_redis/redis_mq/internal/consumer/service.go)
- MySQL 幂等落库：[mysql.go](/Users/gaosong/source_code/mq_redis/redis_mq/internal/dbx/mysql.go)
- 事件模型：[event.go](/Users/gaosong/source_code/mq_redis/redis_mq/internal/model/event.go)
- DLQ 模型：[dlq.go](/Users/gaosong/source_code/mq_redis/redis_mq/internal/model/dlq.go)
- DLQ replay 工具：[main.go](/Users/gaosong/source_code/mq_redis/redis_mq/cmd/replaydlq/main.go)
- 部署入口：[docker-compose.yml](/Users/gaosong/source_code/mq_redis/redis_mq/docker-compose.yml)

## 8. 一句话总结

这不是一个“用 Redis 代替 Kafka”的 demo，而是一个围绕金融日志旁路入库场景，演示如何用较低基础设施复杂度做出一条高可靠、最终一致、可恢复、可 replay 的异步持久化链路。
