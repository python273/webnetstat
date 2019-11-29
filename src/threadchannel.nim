
include nimcompt

type
  EtherType* {.pure.} = enum
    Unknown = uint16(0),
    IPv4 = 0x00000800,
    ARP = 0x00000806,
    IPv6 = 0x000086DD,
  
  IpProto* {.pure.} = enum
    Unknown = cint(-1)
    IP = IPPROTO_IP
    ICMP = IPPROTO_ICMP
    TCP = IPPROTO_TCP
    UDP = IPPROTO_UDP
    ICMPv6 = IPPROTO_ICMPV6

  ParsedData* = object
    len*: uint32
    caplen*: uint32

    tsSec*: uint64
    tsUsec*: uint64

    parseError*: bool
    parseErrorMsg*: string

    etherType*: EtherType
    etherTypeUnknown*: uint16

    ipProto*: IpProto
    ipProtoUnknown*: cint

    ipSrc*: string
    ipSrcLatitude*: BiggestFloat
    ipSrcLongitude*: BiggestFloat

    ipDst*: string
    ipDstLatitude*: BiggestFloat
    ipDstLongitude*: BiggestFloat

    portSrc*: uint16
    portDst*: uint16

    payloadSize*: cint

var channel*: Channel[ParsedData]
