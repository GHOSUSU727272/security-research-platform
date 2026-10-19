"""Memory-bounded forensic extraction; inputs never execute."""
from __future__ import annotations

import io
import struct
import wave


def packbits(values, plane=0, reverse=False):
    result = bytearray()
    value = count = 0
    for number in values:
        bit = (number >> plane) & 1
        value = value | (bit << count) if reverse else (value << 1) | bit
        count += 1
        if count == 8:
            result.append(value)
            count = value = 0
        if len(result) >= 128*1024:
            break
    return bytes(result)


def recover(data: bytes):
    if data.startswith(b"RIFF") and data[8:12] == b"WAVE":
        with wave.open(io.BytesIO(data)) as audio:
            width, channels = audio.getsampwidth(), audio.getnchannels()
            if width in (1, 2, 3, 4) and 1 <= channels <= 8:
                frames = audio.readframes(min(audio.getnframes(), 1_000_000))
                samples = frames[::width]
                for channel in range(channels):
                    for reverse in (False, True):
                        yield f"wav-lsb:channel={channel},order={'lsb' if reverse else 'msb'}", packbits(samples[channel::channels], reverse=reverse)
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        offset = 8
        for _ in range(1000):
            if offset+12 > len(data):
                break
            size = struct.unpack_from(">I", data, offset)[0]
            kind = data[offset+4:offset+8]
            end = offset+12+size
            if end > len(data):
                break
            if kind in (b"tEXt", b"iTXt", b"zTXt"):
                payload = data[offset+8:offset+8+size]
                if kind == b"zTXt" and b"\0" in payload:
                    import zlib
                    compressed = payload.split(b"\0", 1)[1]
                    if compressed[:1] == b"\0":
                        try:
                            payload = zlib.decompressobj().decompress(compressed[1:], 512*1024)
                        except zlib.error:
                            pass
                yield "png-chunk:"+kind.decode(), payload
            offset = end
            if kind == b"IEND":
                if offset < len(data):
                    yield "png-appended-data", data[offset:]
                break
    if data.startswith(b"\xff\xd8"):
        end = data.rfind(b"\xff\xd9")
        if end >= 0 and end+2 < len(data):
            yield "jpeg-appended-data", data[end+2:]
    if data.startswith((b"\x89PNG", b"GIF8", b"BM")):
        from PIL import Image
        Image.MAX_IMAGE_PIXELS = 2_000_000
        with Image.open(io.BytesIO(data)) as picture:
            if picture.width*picture.height > 2_000_000:
                return
            pixels = picture.convert("RGBA").tobytes()
            channels = [("rgba", pixels), ("rgb", picture.convert("RGB").tobytes())]
            channels += [(name, pixels[i::4]) for i, name in enumerate("rgba")]
            for name, samples in channels:
                for plane in (0, 1):
                    for reverse in (False, True):
                        yield f"image-bitplane:channels={name},plane={plane},order={'lsb' if reverse else 'msb'}", packbits(samples, plane, reverse)
