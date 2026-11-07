# AES-128 in CTR mode, sequential vs OpenMP

**AES-128 implemented by hand in C (S-box, ShiftRows, MixColumns, key expansion), then parallelised with OpenMP.**

Counter (CTR) mode turns AES into a stream cipher where every 16-byte block is encrypted independently
(`block_i XOR AES(key, nonce || i)`). Since no block depends on another, the blocks can be spread across threads
with a single `#pragma omp parallel for`, which is what this project measures.

## Files

| File | What it is |
|---|---|
| `AES-CTR_Projet/sequential.c` | reference implementation, one thread |
| `AES-CTR_Projet/openMP.c` | same algorithm, blocks encrypted in parallel; prints the elapsed time (`omp_get_wtime`) |
| `AES-CTR_Projet/file_to_encrypt.txt` | input used for the timings |

## Run

```bash
cd AES-CTR_Projet
gcc -O2 sequential.c -o sequential && ./sequential
gcc -O2 -fopenmp openMP.c -o openmp && OMP_NUM_THREADS=8 ./openmp
```

Change `OMP_NUM_THREADS` to see how the time scales with the number of cores.

*Educational implementation: use a vetted library (OpenSSL, libsodium) for real encryption.*
