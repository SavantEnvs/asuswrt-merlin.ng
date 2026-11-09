#include "dnsmasq_common.h"

/* Upstream DNS reply as dnsmasq's forwarder sees it: extract_addresses() parses the answer,
   authority and additional sections and fills the cache. */
int LLVMFuzzerInitialize(int *argc, char ***argv) {
  (void)argc; (void)argv;
  dnsmasq_setup();
  return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < sizeof(struct dns_header) + 1) return -1;
  uint8_t flags = data[sizeof(struct dns_header) - 1];
  struct dns_header *header = malloc(size);
  memcpy(header, data, size);
  time_t now = 1000000;
  extract_addresses(header, size, daemon->namebuff, now, NULL, NULL, flags & 1, 0, 0);
  check_for_bogus_wildcard(header, size, daemon->namebuff, now);
  check_for_ignored_address(header, size);
  free(header);
  cache_reload();   /* drop what this input cached: each input stands alone */
  return 0;
}
