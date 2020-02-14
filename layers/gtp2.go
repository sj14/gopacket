package layers

import (
	"encoding/binary"
	"log"

	"github.com/google/gopacket"
)

type GTPv2C struct {
	BaseLayer
	Version          uint8
	PiggybackingFlag bool
	TEIDFlag         bool
	MessageType      uint8
	MessageLength    uint16
	TEID             uint32
	SequenceNumber   uint32
}

func (g GTPv2C) LayerType() gopacket.LayerType { return LayerTypeGTPv2C }

// DecodeFromBytes analyses a byte slice and attempts to decode it as a GTPv1U packet
func (g *GTPv2C) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	// hLen := gtpMinimumSizeInBytes
	// dLen := len(data)
	// if dLen < hLen {
	// 	return fmt.Errorf("GTP packet too small: %d bytes", dLen)
	// }

	g.Version = (data[0] >> 5) & 0x07
	g.PiggybackingFlag = ((data[0] >> 4) & 0x01) == 1
	g.TEIDFlag = ((data[0] >> 3) & 0x01) == 1

	g.MessageType = data[1]
	g.MessageLength = binary.BigEndian.Uint16(data[2:4])

	offset := 0
	if g.TEIDFlag {
		offset = 3
		g.TEID = binary.BigEndian.Uint32(data[4:8])
	}

	log.Printf("offset: %+v\n", offset)

	log.Printf("len of data: %v\n", len(data))
	// log.Printf("%#v\n", data[4])
	// log.Printf("%#v\n", data[5])
	// log.Printf("%#v\n", data[6])
	// log.Printf("%#v\n", data[7])
	// log.Printf("%#v\n", data[8])
	// log.Printf("%#v\n", data[9])
	// log.Printf("%#v\n", data[10])
	// log.Printf("%#v\n", data[11])
	// log.Printf("%#v\n", data[12])
	// log.Printf("%#v\n", data[13])

	seqFrom := 4 + offset
	seqTo := 8 + offset
	log.Printf("seq from byte %v to %v\n", seqFrom, seqTo)
	g.SequenceNumber = binary.BigEndian.Uint32(data[seqFrom:seqTo])

	// pLen := offset + 4
	// g.BaseLayer = BaseLayer{Contents: data[:pLen], Payload: data[pLen:]}
	log.Printf("%+v\n", g)

	return nil
}

func (g *GTPv2C) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	log.Printf("we try to serialize: %#v\n", g)

	size := 8
	if g.TEIDFlag {
		size += 4
	}
	data, err := b.PrependBytes(size)
	if err != nil {
		return err
	}

	// data[0] = byte(0x00)
	// data[0] |= (g.Version << 5)

	// data[1] = byte(0xFF)
	// data[2] = byte(0xFF)
	// data[3] = byte(0xFF)
	// data[4] = byte(0xFF)
	// data[5] = byte(0xFF)
	// data[6] = byte(0xFF)
	// data[7] = byte(0xFF)
	// data[8] = byte(0xFF)
	// data[9] = byte(0xFF)
	// data[10] = byte(0xFF)
	// data[11] = byte(0xFF)
	// return nil

	data[0] |= (g.Version << 5)

	if g.PiggybackingFlag {
		data[0] |= (1 << 4)
	}
	if g.TEIDFlag {
		data[0] |= (1 << 3)
	}

	data[1] = g.MessageType
	binary.BigEndian.PutUint16(data[2:4], g.MessageLength)

	// offset := 0
	if g.TEIDFlag {
		// offset = 3
		if err != nil {
			return err
		}
		binary.BigEndian.PutUint32(data[4:8], g.TEID)
	}

	binary.BigEndian.PutUint32(data[:4], g.SequenceNumber)

	log.Printf("buffer: %s", b.Bytes())

	return nil
}

// CanDecode returns a set of layers that GTP objects can decode.
func (g *GTPv2C) CanDecode() gopacket.LayerClass {
	return LayerTypeGTPv2C
}

// NextLayerType specifies the next layer that GoPacket should attempt to
func (g *GTPv2C) NextLayerType() gopacket.LayerType {
	version := uint8(g.LayerPayload()[0]) >> 4
	if version == 4 {
		return LayerTypeIPv4
	} else if version == 6 {
		return LayerTypeIPv6
	} else {
		return LayerTypePPP
	}
}

func decodeGTPv2c(data []byte, p gopacket.PacketBuilder) error {
	gtp2 := &GTPv2C{}
	err := gtp2.DecodeFromBytes(data, p)
	if err != nil {
		return err
	}
	p.AddLayer(gtp2)
	return p.NextDecoder(gtp2.NextLayerType())
}
