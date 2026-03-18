#!/usr/bin/env python3
"""
Recover files from a corrupted gzip/tar archive by finding and following
stored deflate block chains past corruption points.

When a gzip stream has no sync/flush markers, corruption makes standard
decompression fail at the first bad byte. However, stored deflate blocks
(type 00) have a self-describing LEN/NLEN header that can be found by
scanning raw bytes. By locating these block chains after each corruption
point, we can resume decompression and recover the remaining tar data.
"""

import argparse
import zlib
import os
import sys


def decompress_gzip_stream(data):
    """Decompress the initial gzip stream until corruption."""
    d = zlib.decompressobj(zlib.MAX_WBITS | 16)
    tar_data = bytearray()
    offset = 0
    chunk_size = 4096
    try:
        while offset < len(data):
            tar_data.extend(d.decompress(data[offset:offset + chunk_size]))
            offset += chunk_size
    except zlib.error:
        pass
    return tar_data, offset


def find_deflate_resumption(data, search_start):
    """
    Find the next valid raw deflate stream after a corruption point
    by scanning for stored block headers (LEN/NLEN pairs where NLEN == LEN ^ 0xFFFF),
    then verifying that raw deflate decompression succeeds from just before them.
    """
    for i in range(search_start, len(data) - 4):
        len_val = data[i] | (data[i + 1] << 8)
        nlen_val = data[i + 2] | (data[i + 3] << 8)
        if len_val > 100 and nlen_val == (len_val ^ 0xFFFF):
            for start in range(max(search_start, i - 3), i + 1):
                try:
                    d = zlib.decompressobj(-zlib.MAX_WBITS)
                    out = d.decompress(data[start:start + 131072])
                    if len(out) > 50000:
                        return start
                except zlib.error:
                    pass
    return None


def decompress_raw_deflate(data, start):
    """Decompress a raw deflate stream from the given offset."""
    d = zlib.decompressobj(-zlib.MAX_WBITS)
    tar_data = bytearray()
    offset = start
    chunk_size = 65536
    try:
        while offset < len(data):
            tar_data.extend(d.decompress(data[offset:offset + chunk_size]))
            offset += chunk_size
        tar_data.extend(d.flush())
    except zlib.error:
        pass
    return tar_data, offset


def find_tar_headers(stream):
    """
    Locate tar entry headers by searching for the 'ustar' magic at byte 257
    within each 512-byte-aligned candidate block.
    """
    headers = []
    for i in range(len(stream) - 5):
        if stream[i:i + 5] == b'ustar':
            header_start = i - 257
            if header_start < 0:
                continue
            block = stream[header_start:header_start + 512]
            if len(block) < 512:
                continue

            name = block[:100].split(b'\0')[0].decode('utf-8', errors='replace')
            prefix = block[345:500].split(b'\0')[0].decode('utf-8', errors='replace')
            try:
                size = int(block[124:136].split(b'\0')[0].strip(), 8)
            except (ValueError, IndexError):
                size = 0
            typeflag = chr(block[156]) if block[156] else '0'
            full_name = (prefix + '/' + name) if prefix else name

            headers.append({
                'offset': header_start,
                'name': full_name,
                'size': size,
                'type': typeflag,
                'data_start': header_start + 512,
            })
    return headers


def resolve_longlinks(stream, headers):
    """Resolve GNU tar ././@LongLink entries to get full filenames."""
    resolved = []
    longlink_name = None
    for h in headers:
        if h['name'] == '././@LongLink':
            longlink_name = (
                stream[h['data_start']:h['data_start'] + h['size']]
                .rstrip(b'\0')
                .decode('utf-8', errors='replace')
            )
        else:
            if longlink_name:
                h['name'] = longlink_name
                longlink_name = None
            # Skip entries with empty or root-only names
            if h['name'] and h['name'] not in ('', '.', './', '/'):
                resolved.append(h)
    return resolved


def extract_files(stream, entries, output_dir):
    """Extract tar entries from a decompressed stream into output_dir."""
    extracted = 0
    partial = 0
    for h in entries:
        full_path = os.path.join(output_dir, h['name'])
        data_end = h['data_start'] + h['size']

        if h['type'] in ('5', '') or h['name'].endswith('/'):
            os.makedirs(full_path, exist_ok=True)
        elif data_end <= len(stream):
            os.makedirs(os.path.dirname(full_path), exist_ok=True)
            with open(full_path, 'wb') as f:
                f.write(stream[h['data_start']:data_end])
            extracted += 1
        else:
            avail = max(0, len(stream) - h['data_start'])
            if avail > 0:
                os.makedirs(os.path.dirname(full_path), exist_ok=True)
                with open(full_path, 'wb') as f:
                    f.write(stream[h['data_start']:len(stream)])
                partial += 1
                print(f"  PARTIAL: {h['name']} ({avail}/{h['size']} bytes)")

    return extracted, partial


def recover(archive_path, output_dir):
    print(f"Reading {archive_path} ...")
    data = open(archive_path, 'rb').read()
    print(f"Archive size: {len(data)} bytes")

    os.makedirs(output_dir, exist_ok=True)
    total_extracted = 0
    total_partial = 0
    stream_num = 0

    # --- Stream 1: standard gzip decompression from the start ---
    stream_num += 1
    print(f"\n=== Stream {stream_num}: gzip decompression from offset 0 ===")
    tar_data, corrupt_offset = decompress_gzip_stream(data)
    print(f"Decompressed {len(tar_data)} bytes before corruption at input ~{corrupt_offset}")

    entries = resolve_longlinks(tar_data, find_tar_headers(tar_data))
    extracted, partial = extract_files(tar_data, entries, output_dir)
    total_extracted += extracted
    total_partial += partial
    print(f"Extracted {extracted} complete, {partial} partial")

    # --- Subsequent streams: find stored deflate block chains past each corruption ---
    search_from = corrupt_offset
    while search_from < len(data):
        print(f"\nSearching for deflate resumption after offset {search_from} ...")
        resume_offset = find_deflate_resumption(data, search_from)
        if resume_offset is None:
            print("No further resumption points found.")
            break

        stream_num += 1
        print(f"\n=== Stream {stream_num}: raw deflate from offset {resume_offset} ===")
        tar_data, next_corrupt = decompress_raw_deflate(data, resume_offset)
        print(f"Decompressed {len(tar_data)} bytes")

        entries = resolve_longlinks(tar_data, find_tar_headers(tar_data))
        extracted, partial = extract_files(tar_data, entries, output_dir)
        total_extracted += extracted
        total_partial += partial
        print(f"Extracted {extracted} complete, {partial} partial")

        if next_corrupt >= len(data):
            break
        search_from = next_corrupt

    print(f"\n{'='*60}")
    print(f"Recovery complete: {total_extracted} files extracted, {total_partial} partial")
    print(f"Output: {output_dir}")

    file_count = sum(len(f) for _, _, f in os.walk(output_dir))
    total_size = sum(
        os.path.getsize(os.path.join(r, f))
        for r, _, files in os.walk(output_dir)
        for f in files
    )
    print(f"Total: {file_count} files, {total_size / 1024 / 1024:.1f} MB")


def gzip_archive(path):
    """argparse type: validates the file exists and starts with gzip magic."""
    if not os.path.isfile(path):
        raise argparse.ArgumentTypeError(f"'{path}' does not exist")
    try:
        with open(path, 'rb') as f:
            if f.read(2) != b'\x1f\x8b':
                raise argparse.ArgumentTypeError(
                    f"'{path}' is not a gzip archive"
                )
    except OSError as e:
        raise argparse.ArgumentTypeError(f"cannot read '{path}': {e}")
    return path


def existing_directory(path):
    """argparse type: validates the directory exists."""
    if not os.path.isdir(path):
        raise argparse.ArgumentTypeError(f"'{path}' does not exist")
    return path


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description="Recover files from corrupted .tgz archives."
    )
    parser.add_argument(
        'archive', type=gzip_archive,
        help="corrupted .tgz or .tar.gz file to recover",
    )
    parser.add_argument(
        'output', type=existing_directory, nargs='?', default='recovered',
        help="directory to extract into (default: recovered)",
    )
    args = parser.parse_args()
    recover(args.archive, args.output)
