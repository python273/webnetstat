#include <pcap.h>
#include <stdio.h>

int x_start_pcap_loop(char *filter_exp, char *dev, pcap_handler callback) {
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t *handle;

  struct bpf_program fp;
  bpf_u_int32 mask;
  bpf_u_int32 net;

  // pcap_if_t *alldevsp;       /* list of interfaces */

  // if (pcap_findalldevs (&alldevsp, errbuf) < 0)   
  //   {
  //     fprintf (stderr, "%s", errbuf);
  //     exit (1);
  //   }
  // while (alldevsp != NULL)
  //   {
  //     printf ("%s\n", alldevsp->name);
  //     if (strcmp(alldevsp->name, "en7") == 0) {
  //       printf("USING %s\n", alldevsp->name);

  //       dev = alldevsp->name;
  //     }
  //     alldevsp = alldevsp->next;
  //   }

  // TODO: fallback only if empty?
  // dev = pcap_lookupdev(errbuf);
  // if (dev == NULL) {
  //   return 1;
  // }

  if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
    net = 0;
    mask = 0;
  }

  handle = pcap_open_live(dev, 65536, 1, 1000, errbuf);
  if (handle == NULL) {
    printf(&errbuf);  // TODO: return properly
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
