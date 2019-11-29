# Package
version       = "1.0.0"
author        = "python273"
description   = "webnetstat"
license       = "MIT"

srcDir = "src"
binDir = "build"

bin = @["webnetstat"]

skipExt = @["nim"]

# Dependencies

requires "nim >= 1.0.2"
requires "ws 0.3.3"

when defined(nimdistros):
  import distros
  if detectOs(Ubuntu):
    foreignDep "libpcap0.8"
    foreignDep "libpcap0.8-dev"
  else:
    foreignDep "libpcap"

# Tasks
# TODO: copy html/js files to build folder?

task xbuild, "Build":
  exec "nimble c src/webnetstat.nim"
