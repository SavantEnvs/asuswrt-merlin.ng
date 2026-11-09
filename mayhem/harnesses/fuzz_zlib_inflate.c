#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <zlib.h>

/* byte 0 picks the stream format; the rest is the compressed stream. */
static const int kWindowBits[4] = {15, 31, 47, -15};
static const unsigned char kDict[] = "hello, hello! the quick brown fox jumps over the lazy dog";

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 2) return -1;
  int wbits = kWindowBits[data[0] & 3];
  data++; size--;

  z_stream strm;
  memset(&strm, 0, sizeof(strm));
  if (inflateInit2(&strm, wbits) != Z_OK) return -1;

  unsigned char extra[64], name[64], comment[64];
  gz_header head;
  memset(&head, 0, sizeof(head));
  head.extra = extra;     head.extra_max = sizeof(extra);
  head.name = name;       head.name_max = sizeof(name);
  head.comment = comment; head.comm_max = sizeof(comment);
  if (wbits > 15) inflateGetHeader(&strm, &head);

  unsigned char out[4096];
  strm.next_in = (Bytef *)data;
  strm.avail_in = (uInt)size;
  size_t total = 0;
  int ret;
  do {
    strm.next_out = out;
    strm.avail_out = sizeof(out);
    ret = inflate(&strm, Z_NO_FLUSH);
    if (ret == Z_NEED_DICT) {
      if (inflateSetDictionary(&strm, kDict, sizeof(kDict) - 1) != Z_OK) break;
      continue;
    }
    total += sizeof(out) - strm.avail_out;
    /* output cap an embedder would set against decompression bombs (not a time limit) */
  } while (ret == Z_OK && total < (1u << 24));
  inflateEnd(&strm);
  return 0;
}
