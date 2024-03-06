import streams, pcap, microscapy


proc main() =
  let
    container = newFileStream("example.pcap", fmRead)
    globalHeader = container.readGlobalHeader

  var packages: seq[Package]
  while not container.atEnd:
    let
      recordHeader = container.readRecordHeader(globalHeader)
      record = container.readRecord(recordHeader)
      header = record.header
      data = hexData(record.data)
    packages.add(getPackageData(header, data))

  echo packages[0]

main()