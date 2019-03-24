package main

import (
	"encoding/binary"
	"fmt"
	"log"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// Create custom layer structure
type GooseLayer struct {
	appid     uint16
	length    uint16
	reserved1 uint16
	reserved2 uint16
	data      []byte
}

// Register the layer type so we can use it
// The first argument is an ID. Use negative
// or 2000+ for custom layers. It must be unique
var GooseLayerType = gopacket.RegisterLayerType(
	2001,
	gopacket.LayerTypeMetadata{
		"GooseLayerType",
		gopacket.DecodeFunc(decodeGooseLayer),
	},
)

// When we inquire about the type, what type of layer should
// we say it is? We want it to return our custom layer type
func (l GooseLayer) LayerType() gopacket.LayerType {
	return GooseLayerType
}

// LayerContents returns the information that our layer
// provides. In this case it is a header layer so
// we return the header information
func (l GooseLayer) LayerContents() []byte {
	return []byte{0, 0} //l.appid, l.length}
}

// LayerPayload returns the subsequent layer built
// on top of our layer or raw payload
func (l GooseLayer) LayerPayload() []byte {
	return l.data
}

// Custom decode function. We can name it whatever we want
// but it should have the same arguments and return value
// When the layer is registered we tell it to use this decode function
func decodeGooseLayer(data []byte, p gopacket.PacketBuilder) error {
	// AddLayer appends to the list of layers that the packet has
	appid := binary.LittleEndian.Uint16(data[0:])
	length := binary.LittleEndian.Uint16(data[2:])
	p.AddLayer(&GooseLayer{appid, length, 0, 0, data[8:]})

	// The return value tells the packet what layer to expect
	// with the rest of the data. It could be another header layer,
	// nothing, or a payload layer.

	// nil means this is the last layer. No more decoding
	// return nil

	// Returning another layer type tells it to decode
	// the next layer with that layer's decoder function
	// return p.NextDecoder(layers.LayerTypeEthernet)

	// Returning payload type means the rest of the data
	// is raw payload. It will set the application layer
	// contents with the payload
	return p.NextDecoder(gopacket.LayerTypePayload)
}

var (
	pcapFile string = "goose.pcap"
	handle   *pcap.Handle
	err      error
)

func handlePacket(packet gopacket.Packet) {
	ethernetLayer := packet.Layer(layers.LayerTypeEthernet)
	if ethernetLayer != nil {
		ethernetPacket, _ := ethernetLayer.(*layers.Ethernet)
		fmt.Printf("%s >> ", ethernetPacket.SrcMAC)
		fmt.Printf("%s\n", ethernetPacket.DstMAC)

		gooseLayer := packet.Layer(GooseLayerType)
		if gooseLayer != nil {
			fmt.Println("Packet was successfully decoded with Goose layer decoder.")
			gooseLayerContent, _ := gooseLayer.(*GooseLayer)
			// Now we can access the elements of the custom struct
			fmt.Println("Payload: ", gooseLayerContent.LayerPayload())
			fmt.Println("SomeByte element:", gooseLayerContent.appid)
			fmt.Println("AnotherByte element:", gooseLayerContent.length)
		}
	}
	for _, layer := range packet.Layers() {
		fmt.Println("- ", layer.LayerType())
	}
}
func main() {
	// Open file instead of device
	handle, err = pcap.OpenOffline(pcapFile)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		handlePacket(packet) // Do something with a packet here.
		//fmt.Printf("%s\n", packet.String())
	}
}
