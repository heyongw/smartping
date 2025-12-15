package nettools

import (
	"bytes"
	"encoding/binary"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"math/rand"
	"net"
	"time"
)

type pkg struct {
	conn     net.PacketConn
	ipv4conn *ipv4.PacketConn
	msg      icmp.Message
	netmsg   []byte
	id       int
	seq      int
	maxrtt   time.Duration
	dest     net.Addr
}

type ICMP struct {
	Addr    net.Addr
	RTT     time.Duration
	MaxRTT  time.Duration
	MinRTT  time.Duration
	AvgRTT  time.Duration
	Final   bool
	Timeout bool
	Down    bool
	Error   error
}

func (t *pkg) Send(ttl int) ICMP {
	var hop ICMP
	var err error
	sendOn := time.Now() // 定义发送时间
	
	// Check if target is IPv6
	isIPv6 := false
	if t.dest != nil {
		if ip, ok := t.dest.(*net.IPAddr); ok && ip.IP != nil && ip.IP.To4() == nil {
			isIPv6 = true
		}
	}
	
	// Setup connection based on IP version
	if isIPv6 {
		t.conn, err = net.ListenPacket("ip6:ipv6-icmp", "::")
	} else {
		t.conn, err = net.ListenPacket("ip4:icmp", "0.0.0.0")
	}
	
	if nil != err {
		return hop
	}
	defer t.conn.Close()
	
	// Setup packet connection based on IP version
	if isIPv6 {
		ipv6conn := ipv6.NewPacketConn(t.conn)
		defer ipv6conn.Close()
		hop.Error = t.conn.SetReadDeadline(time.Now().Add(t.maxrtt))
		if nil != hop.Error {
			return hop
		}
		hop.Error = ipv6conn.SetHopLimit(ttl)
		if nil != hop.Error {
			return hop
		}
		sendOn = time.Now() // 重置发送时间
		_, hop.Error = t.conn.WriteTo(t.netmsg, t.dest)
	} else {
		t.ipv4conn = ipv4.NewPacketConn(t.conn)
		defer t.ipv4conn.Close()
		hop.Error = t.conn.SetReadDeadline(time.Now().Add(t.maxrtt))
		if nil != hop.Error {
			return hop
		}
		hop.Error = t.ipv4conn.SetTTL(ttl)
		if nil != hop.Error {
			return hop
		}
		sendOn = time.Now() // 重置发送时间
		_, hop.Error = t.conn.WriteTo(t.netmsg, t.dest)
	}
	
	if nil != hop.Error {
		return hop
	}
	
	buf := make([]byte, 1500)
	for {
		var readLen int
		readLen, hop.Addr, hop.Error = t.conn.ReadFrom(buf)
		if nerr, ok := hop.Error.(net.Error); ok && nerr.Timeout() {
			hop.Timeout = true
			return hop
		}
		if nil != hop.Error {
			return hop
		}
		
		var result *icmp.Message
		var proto int
		if isIPv6 {
			proto = 58 // ICMPv6
		} else {
			proto = 1 // ICMPv4
		}
		
		result, hop.Error = icmp.ParseMessage(proto, buf[:readLen])
		if nil != hop.Error {
			return hop
		}
		
		if isIPv6 {
			switch result.Type {
			case ipv6.ICMPTypeEchoReply:
				if rply, ok := result.Body.(*icmp.Echo); ok {
					if t.id == rply.ID && t.seq == rply.Seq {
						hop.Final = true
						hop.RTT = time.Since(sendOn)
						return hop
					}
				}
			case ipv6.ICMPTypeTimeExceeded:
				if rply, ok := result.Body.(*icmp.TimeExceeded); ok {
					if len(rply.Data) > 44 { // IPv6 headers are longer
						if uint16(t.id) == binary.BigEndian.Uint16(rply.Data[44:46]) {
							hop.RTT = time.Since(sendOn)
							return hop
						}
					}
				}
			case ipv6.ICMPTypeDestinationUnreachable:
				if rply, ok := result.Body.(*icmp.Echo); ok {
					if t.id == rply.ID && t.seq == rply.Seq {
						hop.Down = true
						hop.RTT = time.Since(sendOn)
						return hop
					}
				}
			}
		} else {
			switch result.Type {
			case ipv4.ICMPTypeEchoReply:
				if rply, ok := result.Body.(*icmp.Echo); ok {
					if t.id == rply.ID && t.seq == rply.Seq {
						hop.Final = true
						hop.RTT = time.Since(sendOn)
						return hop
					}
				}
			case ipv4.ICMPTypeTimeExceeded:
				if rply, ok := result.Body.(*icmp.TimeExceeded); ok {
					if len(rply.Data) > 24 {
						if uint16(t.id) == binary.BigEndian.Uint16(rply.Data[24:26]) {
							hop.RTT = time.Since(sendOn)
							return hop
						}
					}
				}
			case ipv4.ICMPTypeDestinationUnreachable:
				if rply, ok := result.Body.(*icmp.Echo); ok {
					if t.id == rply.ID && t.seq == rply.Seq {
						hop.Down = true
						hop.RTT = time.Since(sendOn)
						return hop
					}
				}
			}
		}
	}
}

func RunPing(IpAddr *net.IPAddr, maxrtt time.Duration, maxttl int, seq int) (float64, error) {
	var res pkg
	var err error
	res.dest = IpAddr
	res.maxrtt = maxrtt
	res.id = rand.Intn(65535)
	res.seq = seq
	
	// Check if target is IPv6
	if IpAddr != nil && IpAddr.IP != nil && IpAddr.IP.To4() == nil {
		// IPv6
		res.msg = icmp.Message{Type: ipv6.ICMPTypeEchoRequest, Code: 0, Body: &icmp.Echo{ID: res.id, Seq: res.seq, Data: bytes.Repeat([]byte("Go Smart Ping!"), 4) }}
	} else {
		// IPv4
		res.msg = icmp.Message{Type: ipv4.ICMPTypeEcho, Code: 0, Body: &icmp.Echo{ID: res.id, Seq: res.seq, Data: bytes.Repeat([]byte("Go Smart Ping!"), 4) }}
	}
	
	res.netmsg, err = res.msg.Marshal(nil)
	if nil != err {
		return 0, err
	}
	pingRsult := res.Send(maxttl)
	return float64(pingRsult.RTT.Nanoseconds()) / 1e6, pingRsult.Error
}
