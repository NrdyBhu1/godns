package main

import (
	"fmt"
	"net"
	"strings"
)

func b2i(v bool) int {
	if v == true {
		return 1
	}

	return 0
}

type BytePacketBuffer struct {
	buf [512]uint8
	pos uint
}

type ResultCode int

const (
	NOERROR ResultCode = iota
	FORMERR
	SERVFAIL
	NXDOMAIN
	NOTIMP
	REFUSED
)

// 72 bits = 12 bytes
type DnsHeader struct {
	id uint16 // 16 bits

	recursion_desired    bool  // 1 bit
	truncated_message    bool  // 1 bit
	authoritative_answer bool  // 1 bit
	opcode               uint8 // 4 bits
	response             bool  // 1 bit

	rescode             ResultCode // 4 bits
	checking_disabled   bool       // 1 bit
	authed_data         bool       // 1 bit
	z                   bool       // 1 bit
	recursion_available bool       // 1 bit

	questions             uint16 // 16 bits
	answers               uint16 // 16 bits
	authoritative_entries uint16 // 16 bits
	resource_entries      uint16 // 16 bits
}

type QueryType struct {
	Type  int
	Value uint16
}

var (
	QueryTypeA = QueryType{Type: 1}
)

type DnsQuestion struct {
	name  string
	qtype QueryType
}

type DnsRecordType int

const (
	DnsRecordTypeUnknown DnsRecordType = iota
	DnsRecordTypeA
)

type DnsRecord struct {
	Type     DnsRecordType
	domain   string
	qtype    uint16
	data_len uint16
	ttl      uint32
	addr     net.IP
}

type DnsPacket struct {
	header      DnsHeader
	questions   []DnsQuestion
	answers     []DnsRecord
	authorities []DnsRecord
	resources   []DnsRecord
}

func NewBytePacketBuffer() *BytePacketBuffer {
	return &BytePacketBuffer{
		pos: 0,
	}
}

func (buffer *BytePacketBuffer) getpos() uint {
	return buffer.pos
}

func (buffer *BytePacketBuffer) step(steps uint) {
	buffer.pos += steps
}

func (buffer *BytePacketBuffer) seek(pos uint) {
	buffer.pos = pos
}

func (buffer *BytePacketBuffer) read() uint8 {
	if buffer.pos >= 512 {
		panic("End of Buffer")
	}
	res := buffer.buf[buffer.pos]
	buffer.pos++
	return res
}

func (buffer *BytePacketBuffer) get(pos uint) uint8 {
	if pos >= 512 {
		panic("End of Buffer")
	}

	return buffer.buf[pos]
}

func (buffer *BytePacketBuffer) get_range(start uint, length uint) []uint8 {
	if start+length >= 512 {
		panic("End of Buffer")

	}

	return buffer.buf[start : start+length]
}

func (buffer *BytePacketBuffer) read_uint16() uint16 {
	var res uint16

	res = uint16(buffer.read())<<8 | uint16(buffer.read())
	return res
}

func (buffer *BytePacketBuffer) read_uint32() uint32 {
	var res uint32

	res = uint32(buffer.read())<<24 | uint32(buffer.read())<<16 | uint32(buffer.read())<<8 | uint32(buffer.read())

	return res
}

func (buffer *BytePacketBuffer) read_qname(outstr *string) {
	var pos uint
	var jumped bool
	var jumps_performed int

	pos = buffer.getpos()
	jumped = false
	jumps_performed = 0

	max_jumps := 5

	delim := ""
	for {

		if jumps_performed > max_jumps {
			panic("Max jumps performed")
		}

		length := buffer.get(pos)

		if (length & 0xC0) == 0xC0 {
			if !jumped {
				buffer.seek(pos + 2)
			}

			b2 := buffer.get(pos + 1)
			offset := (uint16(length)^0xC0)<<8 | uint16(b2)
			pos = uint(offset)

			jumped = true
			jumps_performed++

			continue

		} else {

			pos++

			if length == 0 {
				if *outstr == "" {
					*outstr = "."
				}

				break
			}

			*outstr += delim
			str_buffer := buffer.get_range(pos, uint(length))
			*outstr += string(str_buffer)

			delim = "."

			pos += uint(length)

		}
	}

	if !jumped {
		buffer.seek(pos)
	}
}

func (buffer *BytePacketBuffer) write(val uint8) {
	if buffer.pos >= 512 {
		panic("End of Buffer")
	}

	buffer.buf[buffer.pos] = val
	buffer.pos++
}

func (buffer *BytePacketBuffer) write_uint8(val uint8) {
	buffer.write(val)
}

func (buffer *BytePacketBuffer) write_uint16(val uint16) {
	buffer.write(uint8(val >> 8))
	buffer.write(uint8(val & 0xFF))
}

func (buffer *BytePacketBuffer) write_uint32(val uint32) {
	buffer.write(uint8((val >> 24) & 0xFF))
	buffer.write(uint8((val >> 16) & 0xFF))
	buffer.write(uint8((val >> 8) & 0xFF))
	buffer.write(uint8((val >> 0) & 0xFF))
}

func (buffer *BytePacketBuffer) write_qname(qname *string) {

	slice := strings.Split(*qname, ".")

	for _, v := range slice {
		length := len(v)
		if length > 0x3f {
			panic("Single label exceeds 63 bytes of character")
		}

		buffer.write_uint8(uint8(length))
		for _, i := range v {
			buffer.write_uint8(uint8(i))
		}
	}

	buffer.write_uint8(0)
}

func ResCodeFromNum(num uint8) ResultCode {
	var res ResultCode
	switch num {
	case 1:
		res = FORMERR

	case 2:
		res = SERVFAIL

	case 3:
		res = NXDOMAIN

	case 4:
		res = NOTIMP

	case 5:
		res = REFUSED

	case 0:
	default:
		res = NOERROR

	}

	return res
}

func NewDnsHeader() DnsHeader {
	return DnsHeader{
		id: 0,

		recursion_desired:    false,
		truncated_message:    false,
		authoritative_answer: false,
		opcode:               0,
		response:             false,

		rescode:             NOERROR,
		checking_disabled:   false,
		authed_data:         false,
		z:                   false,
		recursion_available: false,

		questions:             0,
		answers:               0,
		authoritative_entries: 0,
		resource_entries:      0,
	}
}

func (self *DnsHeader) read(buffer *BytePacketBuffer) {
	self.id = buffer.read_uint16()

	flags := buffer.read_uint16()
	a := uint8(flags >> 8)
	b := uint8(flags & 0xFF)

	self.recursion_desired = (a & (1 << 0)) > 0
	self.truncated_message = (a & (1 << 1)) > 0
	self.authoritative_answer = (a & (1 << 2)) > 0
	self.opcode = (a >> 3) & 0x0F
	self.response = (a & (1 << 7)) > 0

	self.rescode = ResCodeFromNum(b & 0x0F)
	self.checking_disabled = (b & (1 << 4)) > 0
	self.authed_data = (b & (1 << 5)) > 0
	self.z = (b & (1 << 6)) > 0
	self.recursion_available = (b & (1 << 7)) > 0

	self.questions = buffer.read_uint16()
	self.answers = buffer.read_uint16()
	self.authoritative_entries = buffer.read_uint16()
	self.resource_entries = buffer.read_uint16()
}

func (self *DnsHeader) write(buffer *BytePacketBuffer) {
	buffer.write_uint16(self.id)

	buffer.write_uint8(uint8(b2i(self.recursion_desired)) | uint8(b2i(self.truncated_message) << 1) | uint8(b2i(self.authoritative_answer) << 2) | uint8(self.opcode << 3) | uint8(self.rescode << 7))

	buffer.write_uint8(uint8(self.rescode) | uint8(b2i(self.checking_disabled) << 4) | uint8(b2i(self.authed_data) << 5) | uint8(b2i(self.z) << 6) | uint8(b2i(self.recursion_available) << 7))

	buffer.write_uint16(self.questions)
	buffer.write_uint16(self.answers)
	buffer.write_uint16(self.authoritative_entries)
	buffer.write_uint16(self.resource_entries)
}

func QueryTypeToNum(queryType QueryType) uint16 {
	if queryType.Type == 0 {
		return queryType.Value
	} else {
		return 1
	}
}

func QueryTypeFromNum(num uint16) QueryType {
	if num == 1 {
		return QueryTypeA
	} else {
		return QueryType{
			Type:  0,
			Value: num,
		}
	}
}

func NewDnsQuestion(name string, qtype QueryType) DnsQuestion {
	return DnsQuestion{
		name:  name,
		qtype: qtype,
	}
}

func (self *DnsQuestion) read(buffer *BytePacketBuffer) {
	buffer.read_qname(&self.name)
	qtype := buffer.read_uint16()
	buffer.read_uint16()

	self.qtype = QueryTypeFromNum(qtype)

}

func (self *DnsQuestion) write(buffer *BytePacketBuffer) {
	buffer.write_qname(&self.name)
	typenum := self.qtype.Type
	buffer.write_uint16(uint16(typenum))
	buffer.write_uint16(1)
}

func DnsRecordRead(buffer *BytePacketBuffer) DnsRecord {
	dns := DnsRecord{}
	var domain string
	buffer.read_qname(&domain)

	dns.domain = domain

	qtype_num := buffer.read_uint16()

	qtype := QueryTypeFromNum(qtype_num)
	buffer.read_uint16()

	ttl := buffer.read_uint32()
	data_len := buffer.read_uint16()

	switch qtype.Type {
	case 1:
		raw_addr := buffer.read_uint32()

		addr := net.IPv4(uint8((raw_addr>>24)&0xFF), uint8((raw_addr>>16)&0xFF), uint8((raw_addr>>8)&0xFF), uint8((raw_addr>>0)&0xFF))

		dns.Type = DnsRecordTypeA
		dns.domain = domain
		dns.qtype = qtype_num
		dns.data_len = data_len
		dns.addr = addr
		dns.ttl = ttl

	default:

		dns.Type = DnsRecordTypeUnknown
		dns.domain = domain
		dns.qtype = qtype_num
		dns.data_len = data_len
		dns.ttl = ttl
		buffer.step(uint(data_len))

	}
	return dns
}

func (self *DnsRecord) write(buffer *BytePacketBuffer) uint {
	start_pos := buffer.getpos()

	if self.Type == DnsRecordTypeUnknown {
		fmt.Println("Skipping unknown record")
		return (buffer.getpos() - start_pos)
	}

	buffer.write_qname(&self.domain)
	buffer.write_uint16(self.qtype)
	buffer.write_uint16(1)
	buffer.write_uint32(self.ttl)
	buffer.write_uint16(4)

	octects := self.addr.To4()
	buffer.write_uint8(octects[0])
	buffer.write_uint8(octects[1])
	buffer.write_uint8(octects[2])
	buffer.write_uint8(octects[3])

	return (buffer.getpos() - start_pos)
}

func NewDnsPacket() *DnsPacket {
	return &DnsPacket{
		header: NewDnsHeader(),
		// questions: []DnsQuestion{},
		// answers: []DnsRecord{},
		// authorities: []DnsRecord{},
		// resources: []DnsRecord{},
	}
}

func DnsPacketFromBuffer(buffer *BytePacketBuffer) *DnsPacket {
	result := NewDnsPacket()
	result.header.read(buffer)

	for i := uint16(0); i < result.header.questions; i++ {
		question := NewDnsQuestion("", QueryType{Type: 0, Value: 0})
		question.read(buffer)
		result.questions = append(result.questions, question)
	}

	for i := uint16(0); i < result.header.answers; i++ {
		answer := DnsRecordRead(buffer)
		result.answers = append(result.answers, answer)
	}

	for i := uint16(0); i < result.header.authoritative_entries; i++ {
		rec := DnsRecordRead(buffer)
		result.authorities = append(result.authorities, rec)
	}

	for i := uint16(0); i < result.header.resource_entries; i++ {
		rec := DnsRecordRead(buffer)
		result.resources = append(result.resources, rec)
	}
	return result
}

func (self *DnsPacket) write(buffer *BytePacketBuffer) {
	self.header.questions = uint16(len(self.questions))
	self.header.answers = uint16(len(self.answers))
	self.header.authoritative_entries = uint16(len(self.authorities))
	self.header.resource_entries = uint16(len(self.resources))

	self.header.write(buffer)

	for _,question := range self.questions {
		question.write(buffer)
	}

	for _,rec := range self.answers {
		rec.write(buffer)
	}

	for _,rec := range self.authorities {
		rec.write(buffer)
	}

	for _,rec := range self.resources {
		rec.write(buffer)
	}
}

func main() {
	qname := "google.com"
	qtype := QueryTypeA

	serverAddr, err := net.ResolveUDPAddr("udp", "8.8.8.8:53")
	if err != nil {
		fmt.Println(err)
		return
	}

	localAddr, err := net.ResolveUDPAddr("udp", "0.0.0.0:43210")
	if err != nil {
		fmt.Println(err)
		return
	}

	conn, err := net.ListenUDP("udp", localAddr)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer conn.Close()

	packet := NewDnsPacket()
	packet.header.id = 6666
	packet.header.questions = 1
	packet.header.recursion_desired = true
	packet.questions = append(packet.questions, NewDnsQuestion(qname, qtype))

	req_buffer := NewBytePacketBuffer()
	packet.write(req_buffer)

	conn.WriteTo(req_buffer.buf[:], serverAddr)

	res_buffer := NewBytePacketBuffer()
	conn.ReadFromUDP(res_buffer.buf[:])

	res_packet := DnsPacketFromBuffer(res_buffer)
	fmt.Printf("%#v\n", res_packet)
	fmt.Printf("%#v\n", res_packet.header)
	fmt.Println(res_packet.answers[0].addr.String())


}
