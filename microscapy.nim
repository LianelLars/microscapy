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
    ## Тип, описывающий содержимое протоколов.
    protocolNumber*: int
    protocolType*: string
    flags*: seq[string]
    sourcePort*: int
    destinationPort*: int
    checksum*: string

  IPv4* = object
    ## Тип, описывающий IPv4 информацию.
    totalSize*: int
    ttl*: int
    sourceIp*: string
    destinationIp*: string
    protocol*: Protocol

  Packet* = object
    ## Тип, описывающий содержимое пакетов.
    time*: Time
    strTime*: string
    packetSize*: int
    dataSize*: int
    inetVersion*: string
    sourceMac*: string
    destinationMac*: string
    inetInfo*: IPv4
    payload*: string

  TcpSession* = object
    ## TODO
    ##
    ## Тип, описывающий содержимое для сессий.
    participants*: seq[string]
    packetCount*: int
    packets*: seq[Packet]
    averageTtl*: float
    averagePacketSize*: float
    averageDataSize*: float
    sessionDeviation*: float


proc hexData*(data: seq[uint8]): seq[string] =
  ## Возвращает HEX от входящих значений `data`. 
  ## Необходимо для корректной обработки содержимого пакета.
  for item in data:
    result.add(toHex(item))


proc parseIp*(ipData: seq[string]): string =
  ## Возвращает строковое представление IP адреса из входящей `ipData`.
  result = fmt"{parseHexInt(ipData[0])}.{parseHexInt(ipData[1])}.{parseHexInt(ipData[2])}.{parseHexInt(ipData[3])}"


proc parseProtocolData*(data: seq[string]): Protocol =
  ## Функция отвечает за поиск информации о протоколе в содержимом пакета (`data`).
  ## 
  ## На вход подается содержимое, из него вычленяется `inetData` и информация о протоколе:
  ## 
  ## `protocolNumber` - номер протокола (`6` | `17`);
  ## 
  ## `protocolType` - тип протокола (`TCP` | `UDP`);
  ## 
  ## `sourcePort` - порт источника пакета;
  ## 
  ## `destinationPort` - порт назначения пакета;
  ## 
  ## `checksum` - хеш-сумма пакета.
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
  ## Собирает информацию об общем содержимом пакета.
  ## 
  ## `totalSize` - общий размер пакета;
  ## 
  ## `ttl` - время жизни пакета;
  ## 
  ## `protocol` - информация о протоколе (берется из функции `parseProtocolData`);
  ## 
  ## `sourceIp` - IP-адрес источника;
  ## 
  ## `destinationIp` - IP-адрес назначения.
  let inetData = data[14..33]
  result.totalSize = parseHexInt(inetData[2..3].join("").toLower)
  result.ttl = parseHexInt(inetData[8])
  result.protocol = parseProtocolData(data)
  if result.protocol.protocolType == "UDP" or result.protocol.protocolType == "TCP":
    result.sourceIp = parseIp(inetData[12..15])
    result.destinationIp = parseIp(inetData[16..19])


proc getPacketData*(header: PcapRecordHeader, data: seq[string]): Packet =
  ## Сбор информации о пакете.
  ## 
  ## `time` - время отправки пакета (Используется `Unix-time` + милисекунды);
  ## 
  ## `inetVersion` - версия Интернет протокола (`IPv4` | `Not IPv4`);
  ## 
  ## `packetSize` - размер пакета;
  ## 
  ## `destinationMac` - мак-адрес назначения;
  ## 
  ## `sourceMac` - мак-адрес источника;
  ## 
  ## `inetInfo` - информация об Интернет протоколе (используется `parseIPv4Data`)
  ## 
  ## `dataSize` - размер полезной нагрузки;
  ## 
  ## `payload` - HEX-строка полезной нагрузки внутри пакета.
  result.time = fromUnixFloat(parseFloat(fmt"{header.tsSec}.{header.tsUsec}"))
  result.strTime = result.time.format("yyyy-MM-dd, HH:mm:ss (ffffff)")
  result.inetVersion = "IPv4"
  result.packetSize = len(data)
  
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
