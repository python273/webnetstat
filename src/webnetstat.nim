include pcaploop

import strutils
import os
import strformat
import json
import ws, asyncdispatch, asynchttpserver
import threadchannel
import geoip
import tables

proc sniffThreadFunc() {.thread.} =
  channel.open()
  var status = startPcapLoop("not port 9001 and not port 22", "en0") # TODO: get from args
  echo "pcap loop error code: ", status


type
  WebData* = object
    ts*: BiggestFloat

    ipSrc*: string
    ipSrcLatitude*: BiggestFloat
    ipSrcLongitude*: BiggestFloat

    ipDst*: string
    ipDstLatitude*: BiggestFloat
    ipDstLongitude*: BiggestFloat

proc intsToFloat(firstPart: uint64, secondPart: uint64): BiggestFloat =
  result = BiggestFloat(secondPart)

  while (result >= 1):
    result /= 10

  result += BiggestFloat(firstPart)


proc webThreadFunc() {.thread.} =
  var cached = initTable[string, tuple[latitude: BiggestFloat,
      longitude: BiggestFloat]]()

  var connections = newSeq[WebSocket]()

  proc getIpInfo(ip: string): Future[tuple[latitude: BiggestFloat,
      longitude: BiggestFloat]] {.async, gcsafe.} =
    if ip in cached:
      return cached[ip]

    var x = await geoip.getIpInfo(ip)
    cached[ip] = x
    return x

  proc cb(req: Request) {.async, gcsafe.} =
    echo req.reqMethod, " ", req.url.path

    if req.url.path == "/cache":
      await req.respond(Http200, repr(cached))
      return

    if req.url.path == "/ws":
      try:
        var ws = await newWebSocket(req)
        connections.add ws

        while ws.readyState == Open:
          let packet = await ws.receiveStrPacket()
      except WebSocketError:
        echo "socket closed:", getCurrentExceptionMsg()

    if req.url.path.startsWith("/static/"):
      var staticFilePath = $req.url.path
      staticFilePath.removePrefix("/")

      if staticFilePath.contains(".."):
        await req.respond(Http404, "")

      var f: string

      try:
        f = readFile(staticFilePath)
      except IOError:
        await req.respond(Http404, "")

      await req.respond(Http200, f)
      return

    var f = readFile("index.html")
    await req.respond(Http200, f)

  proc channelListener() {.async, gcsafe.} =
    while true:
      var count = channel.peek()

      for i in 1..count:
        var (ok, parsedData) = channel.tryRecv()

        if not ok:
          break

        # TODO: filter non-public IPs
        var ipSrcLoc = await getIpInfo(parsedData.ipSrc)
        parsedData.ipSrcLatitude = ipSrcLoc.latitude
        parsedData.ipSrcLongitude = ipSrcLoc.longitude

        var ipDstLoc = await getIpInfo(parsedData.ipDst)
        parsedData.ipDstLatitude = ipDstLoc.latitude
        parsedData.ipDstLongitude = ipDstLoc.longitude

        var webData: WebData;
        webData.ts = intsToFloat(parsedData.tsSec, parsedData.tsUsec)

        webData.ipSrc = parsedData.ipSrc
        webData.ipSrcLatitude = parsedData.ipSrcLatitude
        webData.ipSrcLongitude = parsedData.ipSrcLongitude

        webData.ipDst = parsedData.ipDst
        webData.ipDstLatitude = parsedData.ipDstLatitude
        webData.ipDstLongitude = parsedData.ipDstLongitude

        for c in connections:
          discard c.send($(%*webData))

      await sleepAsync(2)

  var server = newAsyncHttpServer()
  asyncCheck server.serve(Port(9001), cb)
  asyncCheck channelListener()
  runForever()


proc main() =
  var
    enableSniffThread = true

  for param in commandLineParams():
    if param == "--nosniff":
      echo "sniff thread is disabled"
      enableSniffThread = false

  var
    sniffThread: Thread[void]
    webThread: Thread[void]

  if enableSniffThread:
    createThread(sniffThread, sniffThreadFunc)

  createThread(webThread, webThreadFunc)

  if enableSniffThread:
    joinThread(sniffThread)

  joinThread(webThread)

when isMainModule:
  main()
