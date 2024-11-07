package main

import (
    "errors"
    "net"
	"fmt"
	"os"
)

var EndOfBuffer = errors.New("End of Buffer")
var MaxJumps = errors.New("Max jumps exceeded")

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
    id uint16                       // 16 bits

    recursion_desired bool          // 1 bit
    truncated_message bool          // 1 bit
    authoritative_answer bool       // 1 bit
    opcode uint8                    // 4 bits
    response bool                   // 1 bit

    rescode ResultCode              // 4 bits
    checking_disabled bool          // 1 bit
    authed_data bool                // 1 bit
    z bool                          // 1 bit
    recursion_available bool        // 1 bit

    questions uint16                 // 16 bits
    answers uint16                  // 16 bits
    authoritative_entries uint16    // 16 bits
    resource_entries uint16         // 16 bits

}

type QueryType struct {
    Type int
    Value uint16
}

var (
    QueryTypeA = QueryType{Type: 1}
)

type DnsQuestion struct {
    name string
    qtype QueryType
}

type DnsRecordType int

const (
    DnsRecordTypeUnknown DnsRecordType = iota
    DnsRecordTypeA
)

type DnsRecord struct {
    Type DnsRecordType
    domain string
    qtype uint16
    data_len uint16
    ttl uint32
    addr net.IP
}

type DnsPacket struct {
    header DnsHeader
    questions []DnsQuestion
    answers []DnsRecord
    authorities []DnsRecord
    resources []DnsRecord
}
  

func NewBytePacketBuffer() *BytePacketBuffer {
    return &BytePacketBuffer {
        pos: 0,
    }
}

func (buffer *BytePacketBuffer) getpos() (uint) {
    return buffer.pos
}

func (buffer *BytePacketBuffer) step(steps uint) {
    buffer.pos += steps
}

func (buffer *BytePacketBuffer) seek(pos uint) {
    buffer.pos = pos
}

func (buffer *BytePacketBuffer) read() (uint8, error) {
    if buffer.pos >= 512 {
        return 0,EndOfBuffer
    }
    res := buffer.buf[buffer.pos]
    buffer.pos++
    return res,nil
}

func (buffer *BytePacketBuffer) get(pos uint) (uint8, error) {
    if pos >= 512 {
        return 0,EndOfBuffer
    }

    return buffer.buf[pos],nil
}

func (buffer *BytePacketBuffer) get_range(start uint, length uint) ([]uint8, error) {
    if start + length >= 512 {
        return []uint8{},EndOfBuffer
    }
    
    return buffer.buf[start:start + length],nil
}

func (buffer *BytePacketBuffer) read_uint16() (uint16, error) {
    var res uint16

    bitone,err := buffer.read()
    if err != nil {
        return res,err
    }

    bittwo, err := buffer.read()
    if err != nil {
        return res,err
    }

    res = uint16(bitone) << 8 | uint16(bittwo)
    return res,nil
}

func (buffer *BytePacketBuffer) read_uint32() (uint32, error) {
    var res uint32

    bitone,err := buffer.read()
    if err != nil { return res,err }

    bittwo,err := buffer.read()
    if err != nil { return res,err }

    bitthree,err := buffer.read()
    if err != nil { return res,err }

    bitfour,err := buffer.read()
    if err != nil { return res,err }

    res = uint32(bitone) << 24 | uint32(bittwo) << 16 | uint32(bitthree) << 8 | uint32(bitfour)

    return res,nil
}

func (buffer *BytePacketBuffer) read_qname(outstr *string) error {
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
            return MaxJumps
        }

        length,err := buffer.get(pos)
        if err != nil { return err }

        if (length & 0xC0) == 0xC0 {
            if !jumped {
                buffer.seek(pos + 2)
            }

            b2, err := buffer.get(pos + 1)
            if err != nil { return err }
            offset := (uint16(length) ^ 0xC0) << 8 | uint16(b2)
            pos = uint(offset)

            jumped = true
            jumps_performed++

            continue

        } else {

            pos++

            if length == 0 {
                break
            }

            *outstr += delim
            str_buffer,err := buffer.get_range(pos, uint(length))
            if err != nil { return err }
            *outstr += string(str_buffer)

            delim = "."

            pos += uint(length)

        }
    }
    
    if !jumped {
        buffer.seek(pos)
    }

    return nil
}

func ResCodeFromNum (num uint8) ResultCode {
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

func NewDnsHeader() *DnsHeader {
    return &DnsHeader {
        id: 0,

        recursion_desired: false,
        truncated_message: false,
        authoritative_answer: false,
        opcode: 0,
        response: false,

        rescode: NOERROR,
        checking_disabled: false,
        authed_data: false,
        z: false,
        recursion_available: false,

        questions: 0,
        answers: 0,
        authoritative_entries: 0,
        resource_entries: 0,
    }
}

func (self *DnsHeader) read(buffer *BytePacketBuffer) error {
    var err error
    self.id,err = buffer.read_uint16()
    if err != nil { return err }
    
    flags,err := buffer.read_uint16()
    if err != nil { return err }
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

    self.questions,err = buffer.read_uint16()
    if err != nil { return err }
    self.answers,err = buffer.read_uint16()
    if err != nil { return err }
    self.authoritative_entries,err = buffer.read_uint16()
    if err != nil { return err }
    self.resource_entries,err = buffer.read_uint16()
    if err != nil { return err }

    return nil
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
        return QueryType {
            Type: 0,
            Value: num,
        }
    }
}

func NewDnsQuestion (name string, qtype QueryType) (DnsQuestion) {
    return DnsQuestion {
        name: name,
        qtype: qtype,
    }
}

func (self *DnsQuestion) read(buffer *BytePacketBuffer) error {
    buffer.read_qname(&self.name)
    qtype,err := buffer.read_uint16()
    if err != nil { return err }

    self.qtype = QueryTypeFromNum(qtype)

    return nil
}

func DnsRecordRead (buffer *BytePacketBuffer, dns *DnsRecord) (error) {
    var domain string
    buffer.read_qname(&domain)
    qtype_num, err := buffer.read_uint16()
    if err != nil { return err }

    qtype := QueryTypeFromNum(qtype_num)
    buffer.read_uint16()

    ttl, err := buffer.read_uint32()
    if err != nil { return err }
    data_len, err := buffer.read_uint16()
    if err != nil { return err }

    switch qtype.Type {
    case 1:
        raw_addr, err := buffer.read_uint32()
        if err != nil { return err }

        addr := net.IPv4(uint8((raw_addr >> 24) & 0xFF), uint8((raw_addr >> 16) & 0xFF), uint8((raw_addr >> 8) & 0xFF), uint8((raw_addr >> 0) & 0xFF))

        dns.domain = domain
        dns.addr = addr
        dns.ttl = ttl

    default:
        buffer.step(uint(data_len))

        dns.domain = domain
        dns.qtype = qtype_num
        dns.data_len = data_len
        dns.ttl = ttl
        
    }

    return nil
}

func NewDnsPacket() (*DnsPacket) {
    return &DnsPacket {
        header: *NewDnsHeader(),
        // questions: []DnsQuestion{},
        // answers: []DnsRecord{},
        // authorities: []DnsRecord{},
        // resources: []DnsRecord{},
    }
}

func DnsPacketFromBuffer (buffer *BytePacketBuffer, result *DnsPacket) error {
    var i uint16
    result = NewDnsPacket()
    result.header.read(buffer)

    for i = 0; i < result.header.questions; i++ {
        question := NewDnsQuestion("", QueryType { Type: 0, Value: 0 })
        question.read(buffer)
        result.questions = append(result.questions, question)
    }

    for i = 0; i < result.header.answers; i++ {
        var answer DnsRecord
        DnsRecordRead(buffer, &answer)
        result.answers = append(result.answers, answer)
    }

    for i = 0; i < result.header.authoritative_entries; i++ {
        var rec DnsRecord
        DnsRecordRead(buffer, &rec)
        result.authorities = append(result.authorities, rec)
    }

    for i = 0; i < result.header.resource_entries ; i++ {
        var rec DnsRecord
        DnsRecordRead(buffer, &rec)
        result.resources = append(result.resources, rec)
    }

    return nil
}

func main() {
	f, err := os.Open("response_packet.txt")
	if err != nil {
		fmt.Println(err)
		return
	}
	defer f.Close()

	var buffer *BytePacketBuffer
	var packet DnsPacket
	buffer = NewBytePacketBuffer()
	_, err = f.Read(buffer.buf[:])
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Printf("%#v\n", *buffer)

	err = DnsPacketFromBuffer(buffer, &packet)
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("%#v\n", packet.header)


}
