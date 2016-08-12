package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"time"

	"dnsmessage"
	"github.com/golang/protobuf/proto"
)

var (
	listenAddress = flag.String("pb.listen-address", ":4242", "Address on which to listen for PBDNSMessages")
)

func main() {
	flag.Parse()

	c := make(chan *pb.PBDNSMessage)
	// empty channel
	go func() {
		for {
			m := <-c
			if t := m.GetType(); t == pb.PBDNSMessage_DNSQueryType {
				printQueryMessage(m)
			} else if t == pb.PBDNSMessage_DNSResponseType {
				printResponseMessage(m)
			}
		}
	}()

	// listen
	ln, err := net.Listen("tcp", *listenAddress)
	if err != nil {
		log.Fatal("Cannot listen: %s", err)
	}
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("Error accepting: %s", err)
			continue
		}
		go handleConnection(conn, c)
	}
}

func readBE32(conn io.Reader) (val uint16, err error) {
	err = binary.Read(conn, binary.BigEndian, &val)
	if err != nil {
		return 0, err
	}
	return
}

func handleConnection(conn net.Conn, c chan *pb.PBDNSMessage) {
	fmt.Println("Connection established")
	defer conn.Close()

	pblen, err := readBE32(conn)
	if err != nil {
		log.Fatalf("Cannot read pb length: %s", err)
	}
	data := make([]byte, pblen)
	n, err := conn.Read(data)
	if err != nil {
		log.Fatalf("Cannot read: %s", err)
	}
	if n != int(pblen) {
		log.Print(">> read != advertised?")
	}

	message := &pb.PBDNSMessage{}
	err = proto.Unmarshal(data[0:n], message)
	if err != nil {
		log.Printf("Cannot unmarshal packet: %s", err)
		return
	}
	c <- message
}

func printSummary(m *pb.PBDNSMessage) {
	var (
		ipfromstr                                  = "N/A"
		iptostr                                    = "N/A"
		messageidstr, datestr, initialrequestidstr string
		requestorstr, protostr                     string
	)
	datestr = time.Unix(int64(r.GetTimeSec()), int64(r.GetTimeUsec())).Format("2006-01-02 15:04:05")
	if from := m.GetFrom(); from != nil {
		ipfromstr = net.IP(from).String()
	}
	if to := m.GetTo(); to != nil {
		iptostr = net.IP(to).String()
	}
	if m.GetSocketProtocol == pb.PBDNSMessage_UDP {
		protostr = "UDP"
	} else {
		protostr = "TCP"
	}

	if sub := m.GetOriginalRequestorSubnet(); d != nil {
		requestorstr = " (" + net.IP(sub) + ")"
	}

	/*
	   messageidstr = binascii.hexlify(m.GetMessageId())
	*/

	fmt.Printf("[%s] %s of size %d: %s%s -> %s (%s), id: %d, uuid: %s%s\n",
		datestr,
		typestr,
		msg.inBytes,
		ipfromstr,
		requestorstr,
		iptostr,
		protostr,
		msg.id,
		messageidstr,
		initialrequestidstr)
}

func printResponseMessage(m *pb.PBDNSMessage) {
	var (
		tagsstr, policystr string
		rrscount           int
		datestring         string
	)

	r := m.GetResponse()
	if r == nil {
		return
	}

	datestring = time.Unix(int64(r.GetQueryTimeSec()), int64(r.GetQueryTimeUsec())).Format("2006-01-02 15:04:05")
	fmt.Printf("- Query time: %s\n", datestring)

	if p := r.GetAppliedPolicy(); p != "" {
		policystr = ", Applied policy: " + p
	}

	if t := r.GetTags(); t != nil {
		tagsstr = ", Tags: " + strings.Join(t, ", ")
	}

	rrs := r.GetRrs()
	rrscount = len(rrs)

	fmt.Printf("- Response Code: %d, RRs: %d%s%s\n", r.GetRcode(), rrscount,
		policystr,
		tagsstr)

	for _, rr := range rrs {
		rrclass := rr.GetClass()
		if rrclass != 0 && rrclass != 1 && rrclass != 255 {
			continue
		}
		/* d := rr.GetRdata()
		if d == nil {
			continue
		}
		*/
		rrtype := rr.GetType()
		rdatastr := "<not decoded>"

		switch rr.GetType() {
		case 1, 28:
			ip := net.IP(rr.GetRdata())
			rdatastr = ip.String()
		case 5, 15, 2, 12, 6:
			rdatastr = string(rr.GetRdata())
		}

		fmt.Printf("\t - %d, %d, %s, %d, %s\n", rrclass,
			rrtype,
			rr.GetName(),
			rr.GetTtl(),
			rdatastr)
	}
}

func printQueryMessage(message *pb.PBDNSMessage) {
	q := message.GetQuestion()
	if q == nil {
		return
	}
	qclass := q.GetQClass()
	if qclass == 0 {
		qclass = 1
	}
	fmt.Printf("- Question: %d, %d, %s", qclass, q.GetQType(), q.GetQName())
}
