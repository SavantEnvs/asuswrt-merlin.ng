#include "dnsmasq_common.h"

/* A client query answered from local data (--address, --txt-record, --mx-host, ...) by answer_request(). */
int LLVMFuzzerInitialize(int *argc, char ***argv) {
  (void)argc; (void)argv;
  dnsmasq_setup();
  return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < sizeof(struct dns_header) + 1 || size > daemon->edns_pktsz) return -1;
  struct dns_header *header = (struct dns_header *)daemon->packet;
  memcpy(header, data, size);
  struct in_addr local = {.s_addr = htonl(0x7f000001)}, mask = {.s_addr = htonl(0xff000000)};
  int stale = 0, filtered = 0;
  unsigned short type, class;
  char name[MAXDNAMESTR + 1];
  extract_request(header, size, name, &type, &class);
  answer_request(header, (char *)daemon->packet + daemon->packet_buff_sz, size, local, mask,
                 1000000, data[sizeof(struct dns_header) - 1] & 1, 0, 0, &stale, &filtered);
  return 0;
}
