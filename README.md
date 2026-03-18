# tgz-recover

Recover files from corrupted `.tgz` (gzip-compressed tar) archives.

When a gzip stream has no sync/flush markers, standard tools like `tar` and `gzip` give up at the first corrupted byte — even if 99% of the data after that point is intact. This script finds stored deflate block chains past each corruption point to resume decompression and extract as many files as possible.

## How it works

1. Decompress the gzip stream from the start until corruption is hit
2. Scan forward through the raw bytes for stored deflate blocks (identified by their self-describing LEN/NLEN headers)
3. Resume decompression from the first valid block chain found
4. Repeat for each subsequent corruption point until the end of the file
5. Extract tar entries (including GNU `@LongLink` long filenames) from every recovered segment

## Requirements

Python 3.6+ — no external dependencies. The only libraries used are `zlib`, `os`, and `sys`, all part of the Python standard library.

## Usage

```
python3 tgz-recover.py <archive.tgz> [output_directory]
```

`output_directory` defaults to `recovered`.

Example:

```
$ python3 tgz-recover.py backup.tgz restored/

Reading backup.tgz ...
Archive size: 29182936 bytes

=== Stream 1: gzip decompression from offset 0 ===
Decompressed 803188 bytes before corruption at input ~270336
Extracted 143 complete, 0 partial

Searching for deflate resumption after offset 270336 ...

=== Stream 2: raw deflate from offset 313900 ===
Decompressed 6708266 bytes
Extracted 506 complete, 1 partial

Searching for deflate resumption after offset 4180524 ...

=== Stream 3: raw deflate from offset 4487904 ===
Decompressed 97620985 bytes
Extracted 1036 complete, 0 partial

============================================================
Recovery complete: 1685 files extracted, 1 partial
Output: restored/
Total: 1589 files, 96.9 MB
```

## Limitations

- The archive must contain stored deflate blocks after each corruption point. These are common in larger archives and those produced by parallel compressors like `pigz`, but a small archive compressed entirely with dynamic Huffman blocks won't have resumption points.
- File data that spans a corruption gap will be lost or truncated. The script saves truncated files with a `PARTIAL` note in the output.
- The gap between the corruption point and the next stored block chain is unrecoverable — any tar entries fully contained in that gap are lost.
