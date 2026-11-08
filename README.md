# AES-128 in CTR mode, sequential and with OpenMP

In this project I implemented AES-128 by hand in C (the S-box, ShiftRows, MixColumns and the key
expansion), then made it faster with OpenMP.

I used counter mode (CTR) because it encrypts every 16-byte block on its own: each block is combined with
`AES(key, nonce || i)`. Since no block depends on another one, the blocks can be shared between threads
with a single `#pragma omp parallel for`. That's what this project measures.

## Files

| File | What it is |
|---|---|
| `AES-CTR_Projet/sequential.c` | the reference version, on one thread |
| `AES-CTR_Projet/openMP.c` | the same algorithm with the blocks encrypted in parallel; it prints the time taken (`omp_get_wtime`) |
| `AES-CTR_Projet/file_to_encrypt.txt` | the input file used for the timings |

## Running it

```bash
cd AES-CTR_Projet
gcc -O2 sequential.c -o sequential && ./sequential
gcc -O2 -fopenmp openMP.c -o openmp && OMP_NUM_THREADS=8 ./openmp
```

You can change `OMP_NUM_THREADS` to see how the time changes with the number of cores.

This is a learning project about how AES and parallelism work. For real encryption, use a tested library
like OpenSSL or libsodium.
