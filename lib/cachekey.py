"""cachekey.py -- tie a cache directory to the binary it was built from.

WHY THIS EXISTS.  `cache/` holds funcs.json, indirect.json and meta.json, and
every one of them is a map keyed by ADDRESS in a particular binary.  Point the
generator at a different ELF with an old cache still on disk and nothing
complains: the addresses are all plausible, so the run produces a tree built
from one binary's function list and another binary's bytes.  What comes out is
not a translation of either.  meta.json did record a `binary` path, but a path
is not an identity -- the cache shipped with this package records
`D:\\glslc-port\\subsdk0.elf`, which exists on no machine here and would have
matched nothing even if it were checked.

So the cache carries the SHA-256 of the bytes it was built from, and the two
readers ask different questions of it:

  * analyze.py OWNS the cache: on a mismatch it discards the stale files and
    rebuilds, because that is the whole job it was asked to do.
  * gen.py (elf2c.py) only READS it, and cannot rebuild in reasonable time, so
    a mismatch is a hard error naming analyze.py.

A cache from before this existed has no hash.  It is not rejected -- that
would throw away half an hour of work over a missing field -- but it is
checked against what CAN be compared (the load base and the text span) and it
says out loud that it is unverified.
"""

import hashlib
import json
import os

FILES = ('funcs.json', 'indirect.json', 'meta.json')


def digest(path, _chunk=1 << 20):
    """SHA-256 of a file, read in chunks: the inputs are 10-18 MB."""
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for block in iter(lambda: f.read(_chunk), b''):
            h.update(block)
    return h.hexdigest()


def stamp(meta, binary):
    """Record the binary's identity in a meta dict about to be written."""
    meta['sha256'] = digest(binary)
    meta['size'] = os.path.getsize(binary)
    return meta


def load_meta(cachedir):
    try:
        with open(os.path.join(cachedir, 'meta.json')) as f:
            return json.load(f)
    except Exception:
        return None


def check(cachedir, binary, base=None, text_lo=None, text_hi=None):
    """Why this cache does not match this binary, or None if it does.

    `base`/`text_lo`/`text_hi` are optional and only used for an UNSTAMPED
    cache, where they are the only evidence available.  Returns a pair
    (reason, verified): reason is None when the cache is usable, and verified
    is False when it was accepted without a hash to check.
    """
    meta = load_meta(cachedir)
    if meta is None:
        return ('no readable meta.json in %s' % cachedir, False)

    want = meta.get('sha256')
    if want:
        size = meta.get('size')
        if size is not None and size != os.path.getsize(binary):
            return ('cache was built from a %d-byte binary, this one is %d'
                    % (size, os.path.getsize(binary)), False)
        got = digest(binary)
        if got != want:
            return ('cache was built from sha256 %s..., this binary is %s...'
                    % (want[:16], got[:16]), False)
        return (None, True)

    # Unstamped: compare what there is.  Neither of these proves the binary is
    # the same one -- two builds of the same library can share both -- but a
    # DIFFERENT library almost never lands on the same text span.
    for name, have in (('base', base), ('text_lo', text_lo), ('text_hi', text_hi)):
        if have is None or meta.get(name) is None:
            continue
        if meta[name] != have:
            return ('cache %s is %#x, this binary has %#x'
                    % (name, meta[name], have), False)
    return (None, False)


def discard(cachedir):
    """Delete the files THIS TOOL wrote, and only those.

    Not the directory: `cache` is a path the caller chose, and a tool that
    removes a directory it was merely pointed at is one bad argument away from
    deleting something that matters.  Every file analyze.py writes is named in
    FILES, so removing exactly those leaves the cache empty in the only sense
    that counts.
    """
    gone = []
    for name in FILES:
        p = os.path.join(cachedir, name)
        if os.path.exists(p):
            os.remove(p)
            gone.append(name)
    return gone
