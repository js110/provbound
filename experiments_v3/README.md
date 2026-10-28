# v3 real-agent experiments

All providers run through `experiments_v3.agents.UnifiedToolAgent`. The model
provider changes; the system prompt, tool schemas, step limit, sandbox and
pre-execution hook do not.

Required environment variables (use newly rotated credentials; never commit
them or paste them into result files):

```sh
export DEEPSEEK_API_KEY='...'
export MIMO_API_KEY='...'
export SENSENOVA_API_KEY='...'
```

Before any benchmark run, verify native multi-turn tool calling and record the
model identifier returned by each service:

```sh
python3 -m experiments_v3.provider_smoke \
  --providers deepseek mimo sensenova \
  --output results_v3/provider_smoke_v1/results.json
```

An `unavailable` or `protocol_failure` result is an experimental failure. It
must never be counted as a blocked attack or a safety success. `sensenova` is
fixed to `sensenova-6.7-flash-lite` at `https://token.sensenova.cn/v1`.
