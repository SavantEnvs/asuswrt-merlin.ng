#include <stdlib.h>
#include <string.h>
#include "dnsmasq.h"

/* Configure the real daemon the way a router does: through read_opts() on a command line. */
static void dnsmasq_setup(void) {
  static char *args[] = {
      "dnsmasq", "--conf-file=/dev/null", "--no-hosts", "--no-resolv", "--cache-size=150",
      "--address=/addr.example.com/192.0.2.1", "--address=/addr.example.com/2001:db8::1",
      "--host-record=host.example.com,192.0.2.5,2001:db8::5",
      "--cname=alias.example.com,host.example.com",
      "--txt-record=txt.example.com,hello,world",
      "--mx-host=example.com,mail.example.com,10",
      "--srv-host=_sip._tcp.example.com,sip.example.com,5060,1,2",
      "--naptr-record=example.com,10,20,u,E2U+sip,!^.*$!sip:info@example.com!,.",
      "--ptr-record=_svc._tcp.example.com,svc.example.com",
      "--bogus-nxdomain=192.0.2.99", "--ignore-address=192.0.2.98",
      NULL};
  int argc = 0;
  while (args[argc]) argc++;
  read_opts(argc, args, "");
  if (daemon->edns_pktsz < PACKETSZ) daemon->edns_pktsz = PACKETSZ;
  daemon->packet_buff_sz = daemon->edns_pktsz + MAXDNAME + RRFIXEDSZ;
  daemon->packet = safe_malloc(daemon->packet_buff_sz);
  daemon->pipe_to_parent = -1;
  rand_init();
  cache_init();
  cache_reload();
}
