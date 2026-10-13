package main

import (
	"bytes"
	"crypto/rand"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

const (
	nsWSD      = "http://schemas.xmlsoap.org/ws/2005/04/discovery"
	nsWSA      = "http://schemas.xmlsoap.org/ws/2004/08/addressing"
	nsWSAAnon  = "http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous"
	nsDevice   = "http://schemas.xmlsoap.org/ws/2006/02/devprof"
	nsComputer = "http://schemas.microsoft.com/windows/pub/2005/07"
	wsdGroup   = "239.255.255.250:3702"
	actionGet  = "http://schemas.xmlsoap.org/ws/2004/09/transfer/Get"
)

type QName struct{ URI, Local string }
type WSDMessage struct {
	Action, MessageID, RelatesTo, Target, XAddrs string
	Types                                        []QName
	MetadataVersion                              int
}

var qnameExpr = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.-]*(:[A-Za-z_][A-Za-z0-9_.-]*)?$`)
var uuidExpr = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

func validUUID(s string) bool { return uuidExpr.MatchString(s) }
func newUUID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	b[6] = (b[6] & 0xf) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[:4], b[4:6], b[6:8], b[8:10], b[10:])
}
func escapeXML(s string) string {
	var b bytes.Buffer
	_ = xml.EscapeText(&b, []byte(s))
	return b.String()
}
func parseWSD(data []byte) (WSDMessage, error) {
	var out WSDMessage
	if len(data) == 0 || len(data) > 32768 {
		return out, errors.New("invalid WSD size")
	}
	dec := xml.NewDecoder(bytes.NewReader(data))
	var stk []xml.Name
	ns := map[string]string{"wsdp": nsDevice, "pub": nsComputer}
	var typesText, versionText strings.Builder
	for {
		tk, err := dec.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return out, err
		}
		switch t := tk.(type) {
		case xml.StartElement:
			stk = append(stk, t.Name)
			if len(stk) > 32 {
				return out, errors.New("XML depth exceeded")
			}
			for _, a := range t.Attr {
				if a.Name.Space == "xmlns" && len(a.Name.Local) < 48 && len(a.Value) < 300 {
					ns[a.Name.Local] = a.Value
				}
				if a.Name.Space == "" && a.Name.Local == "xmlns" {
					ns[""] = a.Value
				}
			}
		case xml.EndElement:
			if len(stk) == 0 {
				return out, errors.New("invalid XML nesting")
			}
			stk = stk[:len(stk)-1]
		case xml.CharData:
			if len(stk) < 3 || stk[0].Local != "Envelope" {
				continue
			}
			last := stk[len(stk)-1]
			text := string(t)
			if len(stk) == 3 && stk[1].Local == "Header" && last.Space == nsWSA {
				switch last.Local {
				case "Action":
					out.Action += text
				case "MessageID":
					out.MessageID += text
				case "RelatesTo":
					out.RelatesTo += text
				}
			}
			if last.Space == nsWSD {
				switch last.Local {
				case "XAddrs":
					out.XAddrs += text
				case "Types":
					typesText.WriteString(text)
				case "MetadataVersion":
					versionText.WriteString(text)
				}
			}
			if last.Local == "Address" && last.Space == nsWSA && len(stk) >= 5 && stk[len(stk)-2].Local == "EndpointReference" {
				out.Target += text
			}
		}
	}
	if len(stk) != 0 {
		return out, errors.New("unterminated XML")
	}
	out.Action = strings.TrimSpace(out.Action)
	out.MessageID = strings.TrimSpace(out.MessageID)
	out.Target = strings.TrimSpace(out.Target)
	out.XAddrs = strings.TrimSpace(out.XAddrs)
	if len(out.MessageID) > 256 || len(out.Target) > 256 || len(out.XAddrs) > 4096 {
		return out, errors.New("oversized WSD fields")
	}
	if versionText.Len() > 0 {
		n, err := strconv.Atoi(strings.TrimSpace(versionText.String()))
		if err == nil && n > 0 && n < 1000000 {
			out.MetadataVersion = n
		}
	}
	for _, token := range strings.Fields(typesText.String()) {
		if !qnameExpr.MatchString(token) {
			return out, errors.New("invalid QName")
		}
		pieces := strings.SplitN(token, ":", 2)
		if len(pieces) == 2 {
			uri, ok := ns[pieces[0]]
			if !ok || uri == "" {
				return out, fmt.Errorf("unknown QName prefix %s", pieces[0])
			}
			out.Types = append(out.Types, QName{uri, pieces[1]})
		} else {
			out.Types = append(out.Types, QName{ns[""], token})
		}
		if len(out.Types) > 32 {
			return out, errors.New("too many WSD types")
		}
	}
	return out, nil
}
func matchesProbe(req WSDMessage, dev Device) bool {
	if !strings.HasSuffix(req.Action, "/Probe") {
		return false
	}
	if len(req.Types) == 0 {
		return true
	}
	for _, want := range req.Types {
		found := false
		for _, have := range dev.Types {
			if want == have {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// Metadata paths are learned from a verified source network; proxy clients
// cannot choose or edit them. Accept standard device-specific HTTP paths,
// but refuse ambiguous or dot-traversing forms.
func validMetaPath(path, id string) (string, bool) {
	if !validUUID(id) || len(path) < 1 || len(path) > 256 || !strings.HasPrefix(path, "/") ||
		strings.HasPrefix(path, "//") || strings.ContainsAny(path, "?#\\\\%") {
		return "", false
	}
	for _, part := range strings.Split(path, "/") {
		if part == "." || part == ".." {
			return "", false
		}
	}
	return path, true
}

// Upstream destination is ALWAYS the observed UDP source IP. We do not resolve
// device-supplied hostnames and never act as a client-selected HTTP forward proxy.
func parseXAddr(msg WSDMessage, ip net.IP, allowedPorts map[int]bool) (string, int, bool) {
	id := strings.TrimPrefix(strings.ToLower(msg.Target), "urn:uuid:")
	if !validUUID(id) || ip.To4() == nil {
		return "", 0, false
	}
	for _, raw := range strings.Fields(msg.XAddrs) {
		u, err := url.Parse(raw)
		if err != nil || u.Scheme != "http" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
			continue
		}
		if u.Hostname() == "" {
			continue
		}
		port, err := strconv.Atoi(u.Port())
		if err != nil || !allowedPorts[port] {
			continue
		}
		path, ok := validMetaPath(u.EscapedPath(), id)
		if !ok {
			continue
		}
		return path, port, true
	}
	return "", 0, false
}
func writeReply(kind string, relates, sequence, instance string, count uint64, dev Device, xaddr string) []byte {
	match := "ProbeMatch"
	if kind == "ResolveMatches" {
		match = "ResolveMatch"
	}
	var nsattrs strings.Builder
	var typeText []string
	for i, t := range dev.Types {
		if len(t.URI) > 256 || len(t.Local) > 80 || !qnameExpr.MatchString(t.Local) {
			continue
		}
		prefix := fmt.Sprintf("typ%d", i)
		nsattrs.WriteString(fmt.Sprintf(` xmlns:%s="%s"`, prefix, escapeXML(t.URI)))
		typeText = append(typeText, prefix+":"+t.Local)
	}
	v := dev.MetadataVersion
	if v < 1 {
		v = 1
	}
	return []byte(fmt.Sprintf(`<?xml version="1.0" encoding="utf-8"?>`+
		`<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope" xmlns:wsa="%s" xmlns:wsd="%s"%s>`+
		`<soap:Header><wsa:To>%s</wsa:To><wsa:Action>%s/%s</wsa:Action>`+
		`<wsa:MessageID>urn:uuid:%s</wsa:MessageID><wsa:RelatesTo>%s</wsa:RelatesTo>`+
		`<wsd:AppSequence InstanceId="%s" SequenceId="urn:uuid:%s" MessageNumber="%d"/>`+
		`</soap:Header><soap:Body><wsd:%s><wsd:%s>`+
		`<wsa:EndpointReference><wsa:Address>urn:uuid:%s</wsa:Address></wsa:EndpointReference>`+
		`<wsd:Types>%s</wsd:Types><wsd:XAddrs>%s</wsd:XAddrs>`+
		`<wsd:MetadataVersion>%d</wsd:MetadataVersion></wsd:%s></wsd:%s></soap:Body></soap:Envelope>`,
		nsWSA, nsWSD, nsattrs.String(), nsWSAAnon, nsWSD, kind, newUUID(), escapeXML(relates),
		escapeXML(instance), sequence, count, kind, match, dev.UUID, escapeXML(strings.Join(typeText, " ")),
		escapeXML(xaddr), v, match, kind))
}
func makeProbe() []byte {
	return []byte(fmt.Sprintf(`<?xml version="1.0" encoding="utf-8"?>`+
		`<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:a="%s" xmlns:d="%s" xmlns:wsdp="%s">`+
		`<s:Header><a:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</a:To>`+
		`<a:Action>%s/Probe</a:Action><a:MessageID>urn:uuid:%s</a:MessageID></s:Header>`+
		`<s:Body><d:Probe><d:Types>wsdp:Device</d:Types></d:Probe></s:Body></s:Envelope>`,
		nsWSA, nsWSD, nsDevice, nsWSD, newUUID()))
}
func makeMetadataGet(id string) []byte {
	return []byte(fmt.Sprintf(`<?xml version="1.0" encoding="utf-8"?>`+
		`<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:a="%s">`+
		`<s:Header><a:To>urn:uuid:%s</a:To><a:Action>%s</a:Action>`+
		`<a:MessageID>urn:uuid:%s</a:MessageID>`+
		`<a:ReplyTo><a:Address>%s</a:Address></a:ReplyTo></s:Header>`+
		`<s:Body/></s:Envelope>`, nsWSA, id, actionGet, newUUID(), nsWSAAnon))
}
