# Implementation of [BLS signatures](https://crypto.stanford.edu/~dabo/pubs/papers/BLSmultisig.html) using the BLS12-381 curve.

This implementation currently only supports rogue-key attack resistant batching, and does not support distinct message verification.

## Benchmarks

### Machine specs

The benchmarks were ran on a 2020 13.3" MacBook Pro.

CPU:
```
$ lscpu
Intel(R) Core(TM) i7-1068NG7 CPU @ 2.30GHz
```

RAM:
```
16 GB 3733 MHz LPDDR4X
```

### Results

```
test benches::bench_aggregate_pk    ... bench:   1,654,552 ns/iter (+/- 107,025)
test benches::bench_aggregate_sig   ... bench:      36,893 ns/iter (+/- 3,399)
test benches::bench_sign            ... bench:   1,480,169 ns/iter (+/- 106,151)
test benches::bench_sign_vulnerable ... bench:   1,024,052 ns/iter (+/- 111,395)
test benches::bench_verify          ... bench:   4,740,114 ns/iter (+/- 336,036)
```
