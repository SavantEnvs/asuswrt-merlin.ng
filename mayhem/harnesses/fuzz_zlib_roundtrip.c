#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <zlib.h>

/* Bytes 0-3 choose deflate parameters; the rest is compressed, inflated again and compared. */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 4) return -1;
  int level = (data[0] % 11) - 1;                 /* -1 .. 9 */
  int wbits = 9 + data[1] % 7;                    /* 9 .. 15 */
  int mem_level = 1 + data[2] % 9;                /* 1 .. 9  */
  int strategy = data[3] % 5;                     /* Z_DEFAULT_STRATEGY .. Z_FIXED */
  data += 4; size -= 4;

  z_stream c;
  memset(&c, 0, sizeof(c));
  if (deflateInit2(&c, level, Z_DEFLATED, wbits, mem_level, strategy) != Z_OK) return -1;
  uLong bound = deflateBound(&c, (uLong)size);
  unsigned char *comp = malloc(bound ? bound : 1);
  c.next_in = (Bytef *)data;
  c.avail_in = (uInt)size;
  c.next_out = comp;
  c.avail_out = (uInt)bound;
  if (deflate(&c, Z_FINISH) != Z_STREAM_END) abort();
  uLong clen = c.total_out;
  deflateEnd(&c);

  unsigned char *back = malloc(size ? size : 1);
  z_stream d;
  memset(&d, 0, sizeof(d));
  if (inflateInit2(&d, wbits) != Z_OK) abort();
  d.next_in = comp;
  d.avail_in = (uInt)clen;
  d.next_out = back;
  d.avail_out = (uInt)size;
  int ret = inflate(&d, Z_FINISH);
  if (size == 0 ? ret != Z_STREAM_END && ret != Z_BUF_ERROR : ret != Z_STREAM_END) abort();
  if (d.total_out != size || memcmp(back, data, size) != 0) abort();
  inflateEnd(&d);
  free(comp);
  free(back);
  return 0;
}
