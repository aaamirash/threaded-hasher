# threaded-hasher

thread_crypt is a multithreaded file hashing tool written in C. It securely computes cryptographic hashes (e.g., SHA-512) for files using POSIX threads to parallelize the workload. The goal is to efficiently hash large numbers of files by distributing work across multiple threads.

Build Instructions
```
make
```

Usage
```
./thread_crypt [file1 file2 ...]
```

Design Overview:
Files are added to a thread-safe queue.

A fixed number of worker threads pull from the queue and compute hashes.

Each thread reads file contents and hashes them using the crypt() function.

Results are printed in the format:
```
[thread_id] filename -> hash
```
