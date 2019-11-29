import asyncdispatch
import httpclient
import json
import strutils


proc getIpInfo*(ip: string): Future[tuple[latitude: BiggestFloat, longitude: BiggestFloat]] {.async, gcsafe.} = 
    # TODO: use libmaxminddb to reduce latency
    var response = await newAsyncHttpClient().getContent("https://freegeoip.app/json/" & ip)
    var data = parseJson(response)
    return (data["latitude"].getFloat, data["longitude"].getFloat)
