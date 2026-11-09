#include <stdio.h>
#include <string.h>
#include <zlib.h>

int main(void) {
  const char *w = "Wikipedia";
  const char *n = "123456789";
  printf("adler32(Wikipedia)=%08lx\n", adler32(adler32(0L, Z_NULL, 0), (const Bytef *)w, (uInt)strlen(w)));
  printf("crc32(123456789)=%08lx\n", crc32(crc32(0L, Z_NULL, 0), (const Bytef *)n, (uInt)strlen(n)));

  unsigned char comp[256], back[256];
  uLongf clen = sizeof(comp), blen = sizeof(back);
  const char *msg = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaabbbbbbbbbbbbbbbbbbbbbbbbbbbb";
  if (compress2(comp, &clen, (const Bytef *)msg, (uLong)strlen(msg), 9) != Z_OK) return 1;
  printf("compressed_smaller=%d\n", clen < strlen(msg));
  if (uncompress(back, &blen, comp, clen) != Z_OK) return 1;
  printf("roundtrip_len=%lu equal=%d\n", (unsigned long)blen, blen == strlen(msg) && memcmp(back, msg, blen) == 0);

  /* a known zlib stream: "hello" */
  static const unsigned char hello[] = {0x78, 0x9c, 0xcb, 0x48, 0xcd, 0xc9, 0xc9, 0x07, 0x00, 0x06, 0x2c, 0x02, 0x15};
  blen = sizeof(back);
  if (uncompress(back, &blen, hello, sizeof(hello)) != Z_OK) return 1;
  back[blen] = 0;
  printf("known_stream=%s\n", back);
  return 0;
}
