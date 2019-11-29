#include <pcap.h>


int x_start_pcap_loop(char *filter_exp, pcap_handler callback) {

  char *dev = NULL;
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t *handle;

  struct bpf_program fp;
  bpf_u_int32 mask;
  bpf_u_int32 net;

  dev = pcap_lookupdev(errbuf);
  if (dev == NULL) {
    return 1;
  }

  if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
    net = 0;
    mask = 0;
  }

  handle = pcap_open_live(dev, 65536, 1, 1000, errbuf);
  if (handle == NULL) {
    return 2;
  }

  if (pcap_datalink(handle) != DLT_EN10MB) {
    return 3;
  }

  if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
    return 4;
  }

  if (pcap_setfilter(handle, &fp) == -1) {
    return 5;
  }

  pcap_loop(handle, -1, callback, NULL);

  pcap_freecode(&fp);
  pcap_close(handle);

  return 0;
}
