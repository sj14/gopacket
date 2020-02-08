package layers

import (
	"encoding/binary"
	"fmt"

	"github.com/google/gopacket"
)

type GTPv2C struct {
	BaseLayer
	Version          uint8
	PiggybackingFlag bool
	TEIDFlag         bool
	MessageType      uint8
	MessageLength    uint16

	// ExtensionHeaderFlag bool
	// SequenceNumberFlag  bool
	// NPDUFlag            bool
	TEID           uint32
	SequenceNumber uint32
	// NPDU                uint8
	// GTPExtensionHeaders []GTPExtensionHeader
}

// Register the layer type so we can use it
// The first argument is an ID. Use negative
// or 2000+ for custom layers. It must be unique
var LayerTypeGTPv2C = gopacket.RegisterLayerType(
	2001,
	gopacket.LayerTypeMetadata{
		Name:    "GTPv2C",
		Decoder: gopacket.DecodeFunc(decodeGTPv2c),
	},
)

// When we inquire about the type, what type of layer should
// we say it is? We want it to return our custom layer type
func (g GTPv2C) LayerType() gopacket.LayerType {
	return LayerTypeGTPv2C
}

// // LayerContents returns the information that our layer
// // provides. In this case it is a header layer so
// // we return the header information
// func (g GTPv2C) LayerContents() []byte {
// 	return []byte{l.SomeByte, l.AnotherByte}
// }

// // LayerPayload returns the subsequent layer built
// // on top of our layer or raw payload
// func (g GTPv2C) LayerPayload() []byte {
// 	return l.restOfData
// }

// DecodeFromBytes analyses a byte slice and attempts to decode it as a GTPv1U packet
func (g *GTPv2C) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	hLen := gtpMinimumSizeInBytes
	dLen := len(data)
	if dLen < hLen {
		return fmt.Errorf("GTP packet too small: %d bytes", dLen)
	}

	g.Version = (data[0] >> 5) & 0x07
	g.PiggybackingFlag = ((data[0] >> 4) & 0x01) == 1
	g.TEIDFlag = ((data[0] >> 3) & 0x01) == 1

	g.MessageType = data[1]
	g.MessageLength = binary.BigEndian.Uint16(data[2:4])

	offset := 0
	if g.TEIDFlag {
		offset = 4
		g.TEID = binary.BigEndian.Uint32(data[4:8])
	}

	g.SequenceNumber = binary.BigEndian.Uint32(data[4+offset : 7+offset])

	// g.ProtocolType = (data[0] >> 4) & 0x01
	// g.Reserved = (data[0] >> 3) & 0x01
	// g.SequenceNumberFlag = ((data[0] >> 1) & 0x01) == 1
	// g.NPDUFlag = (data[0] & 0x01) == 1
	// g.ExtensionHeaderFlag = ((data[0] >> 2) & 0x01) == 1

}

func decodeGTPv2c(data []byte, p gopacket.PacketBuilder) error {
	gtp := &GTPv2C{}
	err := gtp.DecodeFromBytes(data, p)
	if err != nil {
		return err
	}
	p.AddLayer(gtp)
	return p.NextDecoder(gtp.NextLayerType())
}
