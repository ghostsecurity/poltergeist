# Benchmarks

While performance is not the top priority for Poltergeist, it is still important to be reasonably fast. We aim to be performant enought that scanning large codebases does not slow down CI pipelines.

On a typical development machine scanning a medium-sized codebase, we should expect performance to be roughly:

- **~1,000 files**: 50-100ms
- **~10,000 files**: 200-500ms
- **~100,000 files**: 2-5 seconds

The Go engine is included primarily for benchmark reference purposes, even though it is not typically used as the primary matching engine.

### Results

Running against some real-world [content](https://github.com/torvalds/linux) with a few seeded secrets.

| Engine    | Rules | Compile(ms) | Scan  | Total | Matches | Throughput (MB/s) |
| --------- | ----- | ----------- | ----- | ----- | ------- | ----------------- |
| go        | 16    | 0.3         | 13.4s | 13.4s | 20      | 108.27            |
| hyperscan | 16    | 79.1        | 8.2s  | 8.2s  | 20      | 177.44            |
| go        | 26    | 0.4         | 19.7s | 19.7s | 20      | 73.73             |
| hyperscan | 26    | 109.1       | 8.1s  | 8.2s  | 20      | 178.92            |
| go        | 66    | 0.6         | 45.4s | 45.4s | 20      | 32.04             |
| hyperscan | 66    | 222.1       | 8.2s  | 8.4s  | 20      | 177.49            |
| go        | 116   | 1.1         | 1m17s | 1m17s | 20      | 18.82             |
| hyperscan | 116   | 356.3       | 8.0s  | 8.4s  | 20      | 180.15            |
| go        | 216   | 1.8         | 2m24s | 2m24s | 20      | 10.09             |
| hyperscan | 216   | 639.6       | 8.1s  | 8.7s  | 20      | 179.54            |
| go        | 516   | 4.6         | 5m45s | 5m45s | 20      | 4.21              |
| hyperscan | 516   | 1546.4      | 8.1s  | 8.5s  | 20      | 177.53            |
| go        | 1016  | 8.5         | 11m9s | 11m9s | 20      | 2.17              |
| hyperscan | 1016  | 2942.7      | 8.6s  | 11.2s | 20      | 176.02            |

| Rules | Go Total(ms) | HS Total(ms) | Speedup |
| ----- | ------------ | ------------ | ------- |
| 16    | 13443.3      | 8281.4       | 1.62x   |
| 26    | 19739.9      | 8243.5       | 2.39x   |
| 66    | 45419.3      | 8422.4       | 5.39x   |
| 116   | 77335.4      | 8435.3       | 9.17x   |
| 216   | 144174.3     | 8745.9       | 16.48x  |
| 516   | 345988.1     | 9744.4       | 35.51x  |
| 1016  | 669583.4     | 11211.1      | 59.72x  |

| Tool (all hs/vs based)                                       | Rules | ~Time (1.4GB content) |
| ------------------------------------------------------------ | ----- | --------------------- |
| poltergeist                                                  | 16    | 8s                    |
| poltergeist                                                  | 26    | 8s                    |
| poltergeist                                                  | 66    | 8s                    |
| poltergeist                                                  | 116   | 8s                    |
| [noseyparker](https://github.com/praetorian-inc/noseyparker) | 162   | 5s                    |
| poltergeist                                                  | 216   | 8s                    |
| [kingfisher](https://github.com/mongodb/kingfisher)          | 256   | 6s                    |
| poltergeist                                                  | 516   | 8s                    |
| poltergeist                                                  | 1016  | 9s                    |
