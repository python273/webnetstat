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
  startPcapLoop("")


proc webThreadFunc() {.thread.} =
  var cached = initTable[string, tuple[latitude: BiggestFloat, longitude: BiggestFloat]]()

  var connections = newSeq[WebSocket]()

  proc getIpInfo(ip: string): Future[tuple[latitude: BiggestFloat, longitude: BiggestFloat]] {.async, gcsafe.} =
    if ip in cached:
      return cached[ip]

    var x = await geoip.getIpInfo(ip)
    cached[ip] = x
    return x

  proc cb(req: Request) {.async, gcsafe.} =
    echo req.url.path

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

      var f = readFile(staticFilePath)
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

        for c in connections:
          asyncCheck c.send($(%*parsedData))

      await sleepAsync(10)

  var server = newAsyncHttpServer()
  asyncCheck server.serve(Port(9001), cb)
  asyncCheck channelListener()
  runForever()


proc main() =
  var
    enableSniffThread = true

  for param in commandLineParams():
    if param == "noSniff":
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
