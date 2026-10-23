#!/usr/bin/env python3
"""Mutation fuzzer for the apkinfo core (run against the ASan build)."""
import os, random, subprocess, sys
binary, n = sys.argv[1], int(sys.argv[2])
seeds = sys.argv[3:]
random.seed(1234)
os.makedirs('/tmp/fuzz', exist_ok=True)
fails = 0
for i in range(n):
    src = random.choice(seeds)
    data = bytearray(open(src, 'rb').read())
    mode = random.random()
    if mode < 0.15:
        data = data[:random.randrange(len(data))]
    else:
        # focus mutations on the tail (central directory / signing block) half the time
        for _ in range(random.randint(1, 40)):
            if random.random() < 0.5:
                pos = random.randrange(max(1, len(data) - 70000), len(data))
            else:
                pos = random.randrange(len(data))
            r = random.random()
            if r < 0.6: data[pos] = random.randrange(256)
            elif r < 0.8: data[pos] = random.choice([0, 0xff, 0x7f, 0x80])
            else:
                k = random.randint(1, 8); data[pos:pos+k] = bytes([0xff]*k)
    ext = os.path.splitext(src)[1]
    path = f'/tmp/fuzz/case{ext}'
    open(path, 'wb').write(data)
    try:
        p = subprocess.run([binary, '-a', '--lang', random.choice(['ru','en']), path], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=20)
        if p.returncode not in (0, 1):
            fails += 1
            keep = f'/tmp/fuzz/crash{fails}{ext}'
            os.rename(path, keep)
            print('CRASH', p.returncode, keep, p.stderr.decode(errors='replace')[:600])
    except subprocess.TimeoutExpired:
        fails += 1
        keep = f'/tmp/fuzz/hang{fails}{ext}'; os.rename(path, keep); print('HANG', keep)
print('done', n, 'cases,', fails, 'failures')
