import std/[strformat, strutils]
import std/[tables, times]
import pcap

const Flags = {
      "02": @["SYN"],
      "12": @["SYN", "ACK"],
      "10": @["ACK"],
      "11": @["FIN", "ACK"],
      "14": @["RST", "ACK"],
      "18": @["PSH", "ACK"],
      "19": @["FIN", "PSH", "ACK"]
    }.toTable


type
  Protocol* = object
    ## A type describing the protocol content.
    protocolNumber*: int
    protocolType*: string
    flags*: seq[string]
    sourcePort*: int
    destinationPort*: int
    checksum*: string

  IPv4* = object
    ## A type describing IPv4 information.
    totalSize*: int
    ttl*: int
    sourceIp*: string
    destinationIp*: string
    protocol*: Protocol

  Package* = object
    ## A type describing the package content.
    time*: Time
    strTime*: string
    packageSize*: int
    dataSize*: int
    inetVersion*: string
    sourceMac*: string
    destinationMac*: string
    inetInfo*: IPv4
    payload*: string

  TcpSession* = object
    ## TODO
    ##
    ## A type describing the session content.
    participants*: seq[string]
    packageCount*: int
    packages*: seq[Package]
    averageTtl*: float
    averagePackageSize*: float
    averageDataSize*: float
    sessionDeviation*: float


proc hexData*(data: seq[uint8]): seq[string] =
  ## Returns a HEX from the incoming `data`.
  ## Required for correct processing of the data package.
  for item in data:
    result.add(toHex(item))


proc parseIp*(ipData: seq[string]): string =
  ## Returns a string representation of the IP address from the incoming `ipData`.
  result = fmt"{parseHexInt(ipData[0])}.{parseHexInt(ipData[1])}.{parseHexInt(ipData[2])}.{parseHexInt(ipData[3])}"


proc parseProtocolData*(data: seq[string]): Protocol =
  ## The function is responsible for finding protocol information in the contents of the package (`data`).
  ## 
  ## The content is supplied to the input, `inetData` and protocol information are extracted from it:
  ## 
  ## `protocolNumber` - protocol number (`6` | `17`);
  ## 
  ## `protocolType` - protocol type (`TCP` | `UDP`);
  ## 
  ## `sourcePort` - package source port;
  ## 
  ## `destinationPort` - package destination port;
  ## 
  ## `checksum` - package checksum.
  let inetData = data[14..33]
  result.protocolNumber = parseHexInt(inetData[9])
  case result.protocolNumber
  of 17:
    result.protocolType = "UDP"
    result.sourcePort = parseHexInt(data[34..35].join("").toLower)
    result.destinationPort = parseHexInt(data[36..37].join("").toLower)
    result.checksum = "0x" & data[40..41].join("").toLower
  of 6:
    result.protocolType = "TCP"
    result.sourcePort = parseHexInt(data[34..35].join("").toLower)
    result.destinationPort = parseHexInt(data[36..37].join("").toLower)
    result.flags = Flags[data[47]]
    result.checksum = "0x" & data[50..51].join("").toLower
  else:
    result.protocolType = "Not UDP | TCP"


proc parseIPv4Data*(data: seq[string]): IPv4 =
  ## Collects information about the general contents of a package.
  ## 
  ## `totalSize` - total package size;
  ## 
  ## `ttl` - package Time to Live;
  ## 
  ## `protocol` - protocol information (from `parseProtocolData`);
  ## 
  ## `sourceIp` - Source IP address;
  ## 
  ## `destinationIp` - Destination IP address.
  let inetData = data[14..33]
  result.totalSize = parseHexInt(inetData[2..3].join("").toLower)
  result.ttl = parseHexInt(inetData[8])
  result.protocol = parseProtocolData(data)
  if result.protocol.protocolType == "UDP" or result.protocol.protocolType == "TCP":
    result.sourceIp = parseIp(inetData[12..15])
    result.destinationIp = parseIp(inetData[16..19])


proc getPackageData*(header: PcapRecordHeader, data: seq[string]): Package =
  ## Collecting package information.
  ## 
  ## `time` - time of sending the package (`Unix-time` + ms);
  ## 
  ## `inetVersion` - Internet protocol version (`IPv4` | `Not IPv4`);
  ## 
  ## `packageSize` - package size;
  ## 
  ## `destinationMac` - destination mac address;
  ## 
  ## `sourceMac` - source mac address;
  ## 
  ## `inetInfo` - Internet protocol information (from `parseIPv4Data`)
  ## 
  ## `dataSize` - payload size;
  ## 
  ## `payload` - HEX string of the payload inside the package.
  result.time = fromUnixFloat(parseFloat(fmt"{header.tsSec}.{header.tsUsec}"))
  result.strTime = result.time.format("yyyy-MM-dd, HH:mm:ss (ffffff)")
  result.inetVersion = "IPv4"
  result.packageSize = len(data)
  
  case data[12..13].join("").toLower
  of "0800":
    discard
  else:
    result.inetVersion = "Not IPv4"

  if result.inetVersion == "IPv4":
    result.destinationMac = data[0..5].join(":").toLower
    result.sourceMac = data[6..11].join(":").toLower
    result.inetInfo = parseIPv4Data(data)
    case result.inetInfo.protocol.protocolNumber
    of 17:
      result.dataSize = len(data[42..^1])
      result.payload = data[42..^1].join("").toLower
    of 6:
      result.dataSize = len(data[52..^1])
      result.payload = data[52..^1].join("").toLower
    else:
      result.dataSize = 0
