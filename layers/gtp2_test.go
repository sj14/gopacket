// Copyright 2017 Google, Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.
//

package layers

import (
	"log"
	"reflect"
	"testing"

	"github.com/google/gopacket"
)

func TestGTP2Decode(t *testing.T) {
	g := &GTPv2C{}

	err := g.DecodeFromBytes(testGTP2PacketBare, nil)
	if err != nil {
		t.Error(err)
	}
	if g.Version != 2 {
		t.Errorf("version should be 2")
	}
	if g.MessageLength != 263 {
		t.FailNow()
	}
	if g.MessageType != 32 {
		t.FailNow()
	}
	if g.PiggybackingFlag != false {
		t.FailNow()
	}
	if g.SequenceNumber != 5196 {
		t.FailNow()
	}
	if g.TEID != 0 {
		t.FailNow()
	}
	if g.TEIDFlag != true {
		t.FailNow()
	}
	// t.Logf("%v\n", g.Version)
	// t.Logf("%v\n", g.MessageLength)
	// t.Logf("%v\n", g.MessageType)
	// t.Logf("%v\n", g.PiggybackingFlag)
	// t.Logf("%#v\n", g.SequenceNumber)
	// t.Logf("%v\n", g.SequenceNumber)
	// t.Logf("%v\n", g.TEID)
	// t.Logf("%v\n", g.TEIDFlag)
	// t.Logf("%#v\n", g.Contents)
	t.Logf("Contents: %v\n", string(g.Contents))
	t.Logf("Payload: %v\n", g.Payload)

}

func TestGTP2Roundtrip(t *testing.T) {
	want := GTPv2C{
		Version:          2,
		MessageType:      32,
		MessageLength:    263,
		TEIDFlag:         true,
		PiggybackingFlag: false,
		TEID:             8,
		SequenceNumber:   5196,
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{}

	err := want.SerializeTo(buf, opts)
	if err != nil {
		t.FailNow()
	}

	// log.Printf("buffer from want: %s", buf.Bytes())

	roundtrip := GTPv2C{}
	err = roundtrip.DecodeFromBytes(buf.Bytes(), nil)
	if err != nil {
		t.FailNow()
	}

	log.Printf("%#v\n", roundtrip)

	if !reflect.DeepEqual(want, roundtrip) {
		t.Errorf("GTP packet serialization failed:\ngot  :\n%#v\n\nwant :\n%#v\n\n", roundtrip, want)
	}
}

func TestGTP2Packet(t *testing.T) {
	p := gopacket.NewPacket(testGTP2PacketWithOtherLayers, LayerTypeEthernet, gopacket.Default)
	if p.ErrorLayer() != nil {
		t.Error("Failed to decode packet:", p.ErrorLayer().Error())
	}
	checkLayers(p, []gopacket.LayerType{LayerTypeEthernet, LayerTypeIPv4, LayerTypeUDP, LayerTypeGTPv2C}, t)
	if got, ok := p.Layer(LayerTypeGTPv2C).(*GTPv2C); ok {
		want := &GTPv2C{
			Version:          2,
			MessageType:      32,
			MessageLength:    263,
			TEIDFlag:         true,
			PiggybackingFlag: false,
			TEID:             0,
			SequenceNumber:   5196,
		}
		want.BaseLayer = BaseLayer{testGTP2PacketBare[:12], testGTP2PacketBare[8:]}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("GTP packet mismatch:\ngot  :\n%#v\n\nwant :\n%#v\n\n", got, want)
		}
		buf := gopacket.NewSerializeBuffer()
		opts := gopacket.SerializeOptions{}
		err := got.SerializeTo(buf, opts)
		if err != nil {
			t.Error(err)
		}
		if !reflect.DeepEqual(got.Contents, buf.Bytes()) {
			t.Errorf("GTP packet serialization failed:\ngot  :\n%#v\n\nwant :\n%#v\n\n", buf.Bytes(), got.Contents)
		}
	} else {
		t.Error("Incorrect gtp packet")
	}
}

// // testGTP2PacketWithEH is the packet
// //000000 00 0c 29 e3 c6 4d 00 0c 29 da d1 de 08 00 45 00 ..)..M..).....E.
// //000010 00 80 00 00 40 00 40 11 67 bb c0 a8 28 b2 c0 a8 ....@.@.g...(...
// //000020 28 b3 08 68 08 68 00 6c c1 95 36 ff 00 58 00 10 (..h.h.l..6..X..
// //000030 06 57 00 05 00 c0 01 09 04 00 45 00 00 54 06 a5 .W........E..T..
// //000040 00 00 40 01 98 00 c0 a8 28 b2 ca 0b 28 9e 00 00 ..@.....(...(...
// //000050 e3 b6 00 00 28 ac 35 11 20 4b a6 3d 0d 00 08 09 ....(.5. K.=....
// //000060 0a 0b 0c 0d 0e 0f 10 11 12 13 14 15 16 17 18 19 ................
// //000070 1a 1b 1c 1d 1e 1f 20 21 22 23 24 25 26 27 28 29 ...... !"#$%&'()
// //000080 2a 2b 2c 2d 2e 2f 30 31 32 33 34 35 36 37

// var testGTP2PacketWithEH = []byte{
// 	0x00, 0x0c, 0x29, 0xe3, 0xc6, 0x4d, 0x00, 0x0c,
// 	0x29, 0xda, 0xd1, 0xde, 0x08, 0x00, 0x45, 0x00,
// 	0x00, 0x80, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11,
// 	0x67, 0xbb, 0xc0, 0xa8, 0x28, 0xb2, 0xc0, 0xa8,
// 	0x28, 0xb3, 0x08, 0x68, 0x08, 0x68, 0x00, 0x6c,
// 	0xc1, 0x95, 0x36, 0xff, 0x00, 0x58, 0x00, 0x10,
// 	0x06, 0x57, 0x00, 0x05, 0x00, 0xc0, 0x01, 0x09,
// 	0x04, 0x00, 0x45, 0x00, 0x00, 0x54, 0x06, 0xa5,
// 	0x00, 0x00, 0x40, 0x01, 0x98, 0x00, 0xc0, 0xa8,
// 	0x28, 0xb2, 0xca, 0x0b, 0x28, 0x9e, 0x00, 0x00,
// 	0xe3, 0xb6, 0x00, 0x00, 0x28, 0xac, 0x35, 0x11,
// 	0x20, 0x4b, 0xa6, 0x3d, 0x0d, 0x00, 0x08, 0x09,
// 	0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11,
// 	0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19,
// 	0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21,
// 	0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29,
// 	0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31,
// 	0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
// }

// func testGTP2PacketWithEH(t *testing.T) {
// 	p := gopacket.NewPacket(testGTP2PacketWithEH, LayerTypeEthernet, gopacket.Default)
// 	if p.ErrorLayer() != nil {
// 		t.Error("Failed to decode packet:", p.ErrorLayer().Error())
// 	}
// 	checkLayers(p, []gopacket.LayerType{LayerTypeEthernet, LayerTypeIPv4, LayerTypeUDP, LayerTypeGTPv2C, LayerTypeIPv4,
// 		LayerTypeICMPv4, gopacket.LayerTypePayload}, t)
// 	if got, ok := p.Layer(LayerTypeGTPv2C).(*GTPv2C); ok {
// 		want := &GTPv2C{
// 			Version:             1,
// 			ProtocolType:        1,
// 			Reserved:            0,
// 			ExtensionHeaderFlag: true,
// 			SequenceNumberFlag:  true,
// 			NPDUFlag:            false,
// 			MessageType:         255,
// 			MessageLength:       88,
// 			TEID:                1050199,
// 			SequenceNumber:      5,
// 			GTPExtensionHeaders: []GTPExtensionHeader{GTPExtensionHeader{Type: uint8(192), Content: []byte{0x9, 0x4}}},
// 		}
// 		want.BaseLayer = BaseLayer{testGTP2PacketWithEH[42:58], testGTP2PacketWithEH[58:]}
// 		if !reflect.DeepEqual(got, want) {
// 			t.Errorf("GTP packet mismatch:\ngot  :\n%#v\n\nwant :\n%#v\n\n", got, want)

// 		}
// 		buf := gopacket.NewSerializeBuffer()
// 		opts := gopacket.SerializeOptions{}
// 		err := got.SerializeTo(buf, opts)
// 		if err != nil {
// 			t.Error(err)
// 		}
// 		if !reflect.DeepEqual(got.Contents, buf.Bytes()) {
// 			t.Errorf("GTP packet serialization failed:\ngot  :\n%#v\n\nbuf :\n%#v\n\n", got.Contents, buf.Bytes())
// 		}
// 	} else {
// 		t.Errorf("Invalid GTP packet")
// 	}

// }
