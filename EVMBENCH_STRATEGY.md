# EVMbench 最优策略

## 实验数据总结

| 方法 | 检出率 | 时间/审计 | 特点 |
|------|--------|----------|------|
| 单次 LLM scan | 10-16% | 1-2min | 每文件独立分析，高召回 |
| Solidity prompt | +4% | 同上 | 专用漏洞模式 |
| RLM deep (修复后) | 未测 | 3-5min | 跨合约分析，找单文件看不到的 bug |
| Agent V1 (transcript) | 16.7% | 2-3min | 多轮但粗糙 |
| Agent V2 (tool-use) | 13.3% | 3-5min | 读更多文件但报告更少(过度保守) |
| Two-pass verification | -4% | ×2 | 杀召回，已废弃 |
| 多次运行取并集 | +3-5% | ×N | 利用 LLM 随机性，免费提升 |
| Codex CLI (xhigh) | ~35-40% | 10-30min | 官方最强，但太慢 |

## 最优流水线设计

```
┌─────────────────────────────────────────────────┐
│              secaudit scan --max                 │
│                                                  │
│  Stage 1: LLM Per-File Scan (并行5文件)         │
│  ├── Solidity专用prompt                         │
│  ├── 每文件独立分析 → 高召回                     │
│  └── 输出: findings_llm[]                       │
│                                                  │
│  Stage 2: RLM Deep Cross-File (4阶段)           │
│  ├── Phase 1: Recon (识别关键模块)               │
│  ├── Phase 2: Focused (模块深入分析)             │
│  ├── Phase 3: Cross-Module (跨合约数据流)        │
│  ├── Phase 4: Aggregation (汇总去重)            │
│  └── 输出: findings_rlm[]                       │
│                                                  │
│  Stage 3: Agent V2 Targeted (tool-use)          │
│  ├── 只分析 Stage 1+2 没覆盖的大文件             │
│  ├── 用 rg 追踪 cross-ref                       │
│  ├── 强制最低文件读取量                          │
│  └── 输出: findings_agent[]                     │
│                                                  │
│  Stage 4: Merge + Dedup                         │
│  ├── 合并 findings_llm + findings_rlm + agent   │
│  ├── 近邻去重 (±3 lines)                        │
│  └── 按 severity 排序                           │
│                                                  │
│  Optional: 跑3次 Stage 1 取并集                  │
│  └── 利用 LLM 随机性额外 +3-5%                  │
└─────────────────────────────────────────────────┘
```

## 预期效果
- Stage 1 alone: ~16% (baseline)
- + Stage 2 (RLM): ~20-22% (cross-contract bugs)
- + Stage 3 (Agent): ~22-25% (补漏)
- + 3x union: ~25-28%
- 目标: 超过 Gemini 3 Pro (20.8%)
