package hostScan

import (
    "context"
    "github.com/google/gopacket"
    "github.com/google/gopacket/layers"
    "github.com/google/gopacket/pcap"
    manuf "github.com/timest/gomanuf"
    "net"
    "strings"
    "sync"
    "time"
)

//gopacket抓包
func ListenARP(ctx context.Context) {
    handle, err := pcap.OpenLive(iface, 1024, false, 10 * time.Second)
    if err != nil {
        log.Fatal("pcap打开失败:", err)
    }
    defer handle.Close()
    handle.SetBPFFilter("arp")
    ps := gopacket.NewPacketSource(handle, handle.LinkType())
    for {
        select {
        case <-ctx.Done():
            return
        case p := <-ps.Packets():
            arp := p.Layer(layers.LayerTypeARP).(*layers.ARP)
            if arp.Operation == 2 {
                mac := net.HardwareAddr(arp.SourceHwAddress)
                m := manuf.Search(mac.String())
                pushData(ParseIP(arp.SourceProtAddress).String(), mac, "", m)
                if strings.Contains(m, "Apple") {
                    go sendMdns(ParseIP(arp.SourceProtAddress), mac)
                } else {
                    go sendNbns(ParseIP(arp.SourceProtAddress), mac)
                }
            }
        }
    }
}

// gopacket发送arp包
// @param:ip=目标IP地址
func SendArpPackage(ip IP,wg *sync.WaitGroup) {
    defer wg.Done()
    srcIp := net.ParseIP(ipNet.IP.String()).To4()
    dstIp := net.ParseIP(ip.String()).To4()
    if srcIp == nil || dstIp == nil {
        log.Fatal("ip 解析出问题")
    }
    // 以太网首部
    // EthernetType 0x0806  ARP
    ether := &layers.Ethernet{
        SrcMAC: localHaddr,
        DstMAC: net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
        EthernetType: layers.EthernetTypeARP,
    }
    
    a := &layers.ARP{
        AddrType: layers.LinkTypeEthernet,
        Protocol: layers.EthernetTypeIPv4,
        HwAddressSize: uint8(6),
        ProtAddressSize: uint8(4),
        Operation: uint16(1), // 0x0001 arp request 0x0002 arp response
        SourceHwAddress: localHaddr,
        SourceProtAddress: srcIp,
        DstHwAddress: net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
        DstProtAddress: dstIp,
    }
    
    buffer := gopacket.NewSerializeBuffer()
    var opt gopacket.SerializeOptions
    gopacket.SerializeLayers(buffer, opt, ether, a)
    outgoingPacket := buffer.Bytes()
    
    handle, err := pcap.OpenLive(iface, 2048, false, 30 * time.Second)
    if err != nil {
        log.Fatal("pcap打开失败:", err)
    }
    defer handle.Close()
    
    err = handle.WritePacketData(outgoingPacket)
    if err != nil {
        log.Fatal("发送arp数据包失败..")
    }
}
