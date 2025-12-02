# `{target_name}` fuzzing summary

## Benchmark configuration


| Target name | name   |
|-------------|--------|
| Duration    | 12h    |
| Trials      | 10     |
| Corpus size | 1      |
| Dict        | yes/no |
| Jobs per Trial | 2 |

Fuzzers to be tested:
- AFL++
- AFL
- HonggFuzz
- LibFuzzer
- SymCC
- KLEE

## Coverage analysis

```
Place here: raw statistics in form of table
per fuzzer: mean, std, min, median, max 
```

```
Place here: pictures of coverage growth in time
```

```
Place here: pictures of median coverage
```

```
Place here: pictures of violin plot
```


```
TBD: Statistical tests
```

```
TBD: Pairwise coverage
```

## Bug analysis

|                  | AFL++ | AFL | Honggfuzz | LibFuzzer | SymCC | KLEE |
|------------------|-------|-----|-----------|-----------|-------|------|
| BugSig:BugType_1 |   X   |     |           |     X     |       |   X  |
| BugSig:BugType_2 |       |  X  |     X     |           |       |      |

```
Place histogram of unique bugs
```

```
Place pie chart of all found bugs
```

```
Place pie chart of found bugs by particular fuzzer
```

### `{BugSig:BugType_1}`

```
Summary: {bug_type} in {function} at line {line}
Stack trace:
    - func1
    - func2
    - func3
    - ...
```

```
Place table as below - only for fuzzers that found bug with particulat signature
```

|              | AFL++ | Honggfuzz | LibFuzzer |
|--------------|-------|-----------|-----------|
| Effectivness |  0.6  |    0.2    |    0.5    |
| Min TTE      | 15000 |   20000   |    5000   |
| Mean TTE     | 17500 | 22500     | 7000      |
| Max TTE      | 30000 | 27000     | 9000      |

#### Stderr output

```
Place ASAN stack trace or other stderr output
```




