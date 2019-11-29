{.passL: "-lpcap".}
{.compile: "sniffpcap.c".}

include nimcompt
import strformat
import threadchannel

type
  pcap_pkthdr {.bycopy.} = object
    ts*: Timeval
    caplen*: uint32
    len*: uint32

type
  pcap_handler = proc (a1: ptr uint8; a2: ptr pcap_pkthdr; a3: ptr uint8)


proc x_start_pcap_loop(filter_exp: cstring; dev: cstring; callback: pcap_handler): cint {.importc.}

const
  SNAP_LEN* = 1518
  SIZE_ETHERNET* = 14
  ETHER_ADDR_LEN* = 6

type
  sniff_ethernet* {.bycopy.} = object
    ether_dhost*: array[ETHER_ADDR_LEN, uint8] ##  destination host address
    ether_shost*: array[ETHER_ADDR_LEN, uint8] ##  source host address
    ether_type*: uint16                        ##  IP? ARP? RARP? etc

  sniff_ip* {.bycopy.} = object
    ip_vhl*: uint8  ##  version << 4 | header length >> 2
    ip_tos*: uint8  ##  type of service
    ip_len*: uint16 ##  total length
    ip_id*: uint16  ##  identification
    ip_off*: uint16 ##  fragment offset field
    ip_ttl*: uint8  ##  time to live
    ip_p*: uint8    ##  protocol
    ip_sum*: uint16 ##  checksum
    ip_src*: InAddr
    ip_dst*: InAddr ##  source and dest address

const
  IP_RF* = 0x00008000
  IP_DF* = 0x00004000
  IP_MF* = 0x00002000
  IP_OFFMASK* = 0x00001FFF


template IP_HL(ip: untyped): untyped =
  cast[cint](ip.ip_vhl and cast[uint8](0x0000000F))

type
  sniff_ipv6* {.bycopy.} = object
    header*: array[4, uint8]
    ip_len*: uint16
    ip_p*: uint8
    ip_ttl*: uint8
    ip_src*: In6Addr
    ip_dst*: In6Addr


const
  IPV6_PACKET_LEN* = 40

##  TCP header

const
  TH_FIN* = 0x00000001
  TH_SYN* = 0x00000002
  TH_RST* = 0x00000004
  TH_PUSH* = 0x00000008
  TH_ACK* = 0x00000010
  TH_URG* = 0x00000020
  TH_ECE* = 0x00000040
  TH_CWR* = 0x00000080
  TH_FLAGS* = (TH_FIN or TH_SYN or TH_RST or TH_ACK or TH_URG or TH_ECE or TH_CWR)

type
  tcp_seq* = uint32
  sniff_tcp* {.bycopy.} = object
    th_sport*: uint16 ##  source port
    th_dport*: uint16 ##  destination port
    th_seq*: tcp_seq  ##  sequence number
    th_ack*: tcp_seq  ##  acknowledgement number
    th_offx2*: uint8  ##  data offset, rsvd
    th_flags*: uint8
    th_win*: uint16   ##  window
    th_sum*: uint16   ##  checksum
    th_urp*: uint16   ##  urgent pointer

template TH_OFF(th: untyped): untyped =
  cast[cint](((th).th_offx2 and cast[uint8](0x000000F0)) shr 4)

proc get_ethernet_packet_from_bytes(packet: ptr uint8): ptr sniff_ethernet =
  return cast[ptr sniff_ethernet](packet)

proc handlePacket(args: ptr uint8; header: ptr pcap_pkthdr; packet: ptr uint8) =
  var parsedData: ParsedData
  defer: channel.send(parsedData)

  # TODO: probably not totaly safe parsing via casting pointers

  parsedData.tsSec = cast[uint64](header.ts.tv_sec)
  parsedData.tsUsec = cast[uint64](header.ts.tv_usec)

  var ethernet = get_ethernet_packet_from_bytes(packet)

  var payload: cstring
  ##  Packet payload
  var protocol: cint = 0
  var ip_payload_len: cint = 0
  var size_ip: cint
  var size_tcp: cint
  var size_payload: cint

  parsedData.len = header.len
  parsedData.capLen = header.capLen

  var ether_type: uint16 = ntohs(ethernet.ether_type)

  case ether_type
  of uint16(EtherType.IPv6):
    parsedData.etherType = EtherType.IPv6

    var ipv6 = cast[ptr sniff_ipv6](cast[int](packet) + SIZE_ETHERNET)
    size_ip = IPV6_PACKET_LEN # TODO: ext headers?
    protocol = cast[cint](ipv6.ip_p)
    ip_payload_len = cast[cint](ntohs(ipv6.ip_len) + IPV6_PACKET_LEN)

    var ip_src = nim_inet_ntop(AF_INET6, addr(ipv6.ip_src))
    var ip_dst = nim_inet_ntop(AF_INET6, addr(ipv6.ip_dst))

    parsedData.ipSrc = ip_src
    parsedData.ipDst = ip_dst
  of uint16(EtherType.IPv4):
    parsedData.etherType = EtherType.IPv4

    var ip = cast[ptr sniff_ip](cast[int](packet) + SIZE_ETHERNET)
    size_ip = IP_HL(ip) * 4

    if size_ip < 20:
      parsedData.parseError = true
      parsedData.parseErrorMsg = &"Invalid IP header length: {size_ip} bytes"
      return

    var ip_src = nim_inet_ntop(AF_INET, addr(ip.ip_src))
    var ip_dst = nim_inet_ntop(AF_INET, addr(ip.ip_dst))

    parsedData.ipSrc = ip_src
    parsedData.ipDst = ip_dst

    ip_payload_len = cast[cint](ntohs(ip.ip_len))
    protocol = cast[cint](ip.ip_p)
  of uint16(EtherType.ARP):
    parsedData.etherType = EtherType.ARP
    return
  else:
    parsedData.etherType = EtherType.Unknown
    parsedData.etherTypeUnknown = ether_type
    return

  case protocol
  of IPPROTO_TCP:
    parsedData.ipProto = IpProto.TCP

    var tcp = cast[ptr sniff_tcp](cast[int](packet) + SIZE_ETHERNET + size_ip)

    size_tcp = TH_OFF(tcp) * 4
    if size_tcp < 20:
      parsedData.parseError = true
      parsedData.parseErrorMsg = &"Invalid TCP header length: {size_tcp} bytes"
      return

    var port_src = ntohs(tcp.th_sport)
    var port_dst = ntohs(tcp.th_dport)

    parsedData.portSrc = port_src
    parsedData.portDst = port_dst

    # payload = cast[ptr uint8]((cast[int](packet) + SIZE_ETHERNET + size_ip + size_tcp))
    size_payload = ip_payload_len - (size_ip + size_tcp)

    parsedData.payloadSize = size_payload
    return
  of IPPROTO_UDP:
    parsedData.ipProto = IpProto.UDP
    return
  of IPPROTO_ICMP:
    parsedData.ipProto = IpProto.ICMP
    return
  of IPPROTO_ICMPV6:
    parsedData.ipProto = IpProto.ICMPv6
    return
  of IPPROTO_IP:
    parsedData.ipProto = IpProto.IP
    return
  else:
    parsedData.ipProto = IpProto.Unknown
    parsedData.ipProtoUnknown = protocol
    return
  return


proc startPcapLoop*(filter_exp: string, device: string): cint =
  return x_start_pcap_loop(filter_exp, device, handlePacket)
