package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	pb "github.com/CpuID/pdns-protobuf-exporter/dnsmessage"
	"github.com/golang/protobuf/proto"

	"github.com/prometheus/client_golang/prometheus"
)

var (
	pbAddress     = flag.String("pb.listen-address", ":4242", "Address on which to listen for PBDNSMessages")
	listenAddress = flag.String("web.listen-address", ":9142", "Address on which to expose metrics and web interface.")
	metricsPath   = flag.String("web.telemetry-path", "/metrics", "Path under which to expose metrics.")
	timeformat    = "2006-01-02 15:04:05.000"

	appliedPolicy = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "pdns_protobuf",
			Subsystem: "rpz",
			Name:      "applied_policy_total",
			Help:      "Number of packets applied in each received policyName",
		},
		[]string{"policy"},
	)
	answersTotal = prometheus.NewCounter(
		prometheus.CounterOpts{
			Namespace: "pdns_protobuf",
			Subsystem: "rpz",
			Name:      "answers_total",
			Help:      "Number of packets answered in total",
		},
	)
)

func init() {
	prometheus.MustRegister(appliedPolicy)
	prometheus.MustRegister(answersTotal)
}

func main() {
	flag.Parse()

	c := make(chan *pb.PBDNSMessage)
	// empty channel
	go func() {
		for {
			m := <-c
			if t := m.GetType(); t == pb.PBDNSMessage_DNSQueryType {
				printSummary(m, "Query")
				printQueryMessage(m)
			} else if t == pb.PBDNSMessage_DNSResponseType {
				if p := m.GetResponse().GetAppliedPolicy(); p != "" {
					appliedPolicy.WithLabelValues(p).Inc()
				}
				answersTotal.Inc()
				printSummary(m, "Response")
				printQueryMessage(m)
				printResponseMessage(m)
			}
		}
	}()

	// listen for protobuf
	go func() {
		ln, err := net.Listen("tcp", *pbAddress)
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
	}()

	// listen for prometheus scrapes
	handler := prometheus.Handler()
	http.Handle(*metricsPath, handler)
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`
		<html>
			<head>
				<title>Powerdns PBDNSMessage stats exporter</title>
			</head>
			<body>
				<h1>Powerdns PBDNSMessage stats exporter</h1>
				<p>
					<a href="` + *metricsPath + `">Metrics</a>
				</p>
			</body>
		</html>`))
	})
	log.Println("Listening on", *listenAddress)
	log.Fatal(http.ListenAndServe(*listenAddress, nil))
}

func readBE32(conn io.Reader) (val uint16, err error) {
	err = binary.Read(conn, binary.BigEndian, &val)
	if err != nil {
		return 0, err
	}
	return
}

func handleConnection(conn net.Conn, c chan *pb.PBDNSMessage) {
	log.Print("Protobuf Connection established from ", conn.RemoteAddr())
	defer conn.Close()

	for {
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
			continue
		}
		c <- message
	}
}

func printSummary(m *pb.PBDNSMessage, typestr string) {
	var (
		ipfromstr                                  = "N/A"
		iptostr                                    = "N/A"
		messageidstr, datestr, initialrequestidstr string
		requestorstr, protostr                     string
	)
	datestr = time.Unix(int64(m.GetTimeSec()), int64(m.GetTimeUsec())).Format(time.StampMilli)
	if from := m.GetFrom(); from != nil {
		ipfromstr = net.IP(from).String()
	}
	if to := m.GetTo(); to != nil {
		iptostr = net.IP(to).String()
	}
	if m.GetSocketProtocol() == pb.PBDNSMessage_UDP {
		protostr = "UDP"
	} else {
		protostr = "TCP"
	}

	if sub := m.GetOriginalRequestorSubnet(); sub != nil {
		requestorstr = " (" + net.IP(sub).String() + ")"
	}

	messageidstr = fmt.Sprintf("%x", m.GetMessageId())

	fmt.Printf("[%s] %s of size %d: %s%s -> %s (%s), id: %d, uuid: %s%s\n",
		datestr,
		typestr,
		m.GetInBytes(),
		ipfromstr,
		requestorstr,
		iptostr,
		protostr,
		m.GetId(),
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

	datestring = time.Unix(int64(r.GetQueryTimeSec()), int64(r.GetQueryTimeUsec())).Format(time.StampMilli)
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
	fmt.Printf("- Question: %d, %d, %s\n", qclass, q.GetQType(), q.GetQName())
}
