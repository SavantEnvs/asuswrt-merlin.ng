#include "../harnesses/dnsmasq_common.h"
#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>

static unsigned char *put_name(unsigned char *p, const char *labels) {
  /* "kat.example" -> 3kat7example0 */
  while (*labels) {
    const char *dot = strchr(labels, '.');
    size_t n = dot ? (size_t)(dot - labels) : strlen(labels);
    *p++ = (unsigned char)n;
    memcpy(p, labels, n);
    p += n;
    labels += n + (dot ? 1 : 0);
  }
  *p++ = 0;
  return p;
}

int main(void) {
  dnsmasq_setup();
  unsigned char pkt[512];
  memset(pkt, 0, sizeof(pkt));
  struct dns_header *h = (struct dns_header *)pkt;
  h->id = htons(0x1234);
  h->hb3 = HB3_QR | HB3_RD;
  h->hb4 = HB4_RA;
  h->qdcount = htons(1);
  h->ancount = htons(1);
  unsigned char *p = (unsigned char *)(h + 1);
  p = put_name(p, "kat.example");
  *p++ = 0; *p++ = 1; *p++ = 0; *p++ = 1;            /* A IN */
  *p++ = 0xc0; *p++ = sizeof(struct dns_header);     /* pointer to the question name */
  *p++ = 0; *p++ = 1; *p++ = 0; *p++ = 1;            /* A IN */
  *p++ = 0; *p++ = 0; *p++ = 1; *p++ = 0x2c;         /* ttl 300 */
  *p++ = 0; *p++ = 4;
  *p++ = 203; *p++ = 0; *p++ = 113; *p++ = 7;
  size_t len = (size_t)(p - pkt);

  time_t now = 1000000;
  int rc = extract_addresses(h, len, daemon->namebuff, now, NULL, NULL, 0, 0, 0);
  printf("extract_addresses=%d\n", rc);
  struct crec *c = cache_find_by_name(NULL, "kat.example", now, F_IPV4);
  char buf[INET_ADDRSTRLEN] = "none";
  if (c) inet_ntop(AF_INET, &c->addr.addr4, buf, sizeof(buf));
  printf("cached kat.example A=%s\n", buf);

  /* a query answered from --host-record=host.example.com,192.0.2.5,... */
  memset(daemon->packet, 0, daemon->packet_buff_sz);
  h = (struct dns_header *)daemon->packet;
  h->id = htons(0x4321);
  h->hb3 = HB3_RD;
  h->qdcount = htons(1);
  p = (unsigned char *)(h + 1);
  p = put_name(p, "host.example.com");
  *p++ = 0; *p++ = 1; *p++ = 0; *p++ = 1;
  struct in_addr local = {.s_addr = htonl(0x7f000001)}, mask = {.s_addr = htonl(0xff000000)};
  int stale = 0, filtered = 0;
  size_t alen = answer_request(h, (char *)daemon->packet + daemon->packet_buff_sz, (size_t)(p - (unsigned char *)daemon->packet),
                               local, mask, now, 0, 0, 0, &stale, &filtered);
  printf("answer len=%zu ancount=%u rcode=%u hb3=%x\n", alen, ntohs(h->ancount), h->hb4 & 0x0f, h->hb3);
  if (alen >= 4) {
    struct in_addr a;
    memcpy(&a, daemon->packet + alen - 4, 4);
    inet_ntop(AF_INET, &a, buf, sizeof(buf));
    printf("answer last A=%s\n", buf);
  }
  return 0;
}
