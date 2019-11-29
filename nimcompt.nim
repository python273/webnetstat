include consts/macosx_amd64_consts
import posix

proc nim_inet_ntop*(a1: TSa_Family, a2: pointer): string =
  var addrbuf: array[0..int(INET6_ADDRSTRLEN), char]
  return $posix.inet_ntop(cast[cint](a1), a2, addrbuf[0].addr, addrbuf.sizeof.int32)
