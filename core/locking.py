"""OS-released scheduler lock prevents duplicate processes sharing a queue."""

import sys
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator


@contextmanager
def scheduler_lock(path: Path) -> Iterator[None]:
    """Hold an exclusive nonblocking file lock until exit or process death."""
    with path.open("a+b") as stream:
        stream.seek(0)
        if sys.platform != "win32":
            import fcntl

            fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
        else:
            import msvcrt

            if path.stat().st_size == 0:
                stream.write(b"0")
                stream.flush()
            stream.seek(0)
            msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
        yield
