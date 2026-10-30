// Package weborigin normalizes configured HTTPS origins before they are used
// for Host, CSRF, passkey and enrollment checks.
package weborigin

import (
	"errors"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"

	"golang.org/x/net/idna"
)

func Parse(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.ForceQuery || strings.Contains(raw, "#") || u.Opaque != "" || strings.HasSuffix(u.Host, ":") {
		return nil, errors.New("origin must be exactly https://hostname[:port], without a path, credentials, query or fragment")
	}
	host := strings.ToLower(u.Hostname())
	if address, e := netip.ParseAddr(host); e == nil {
		if address.Zone() != "" {
			return nil, errors.New("origin cannot contain an IPv6 zone")
		}
		host = address.String()
	} else {
		host, err = idna.Lookup.ToASCII(host)
		if err != nil || host == "" {
			return nil, errors.New("invalid origin hostname")
		}
		// Browsers reinterpret legacy numeric hostnames as IPv4 addresses.
		// Require their ordinary dotted-decimal form instead.
		last := host[strings.LastIndex(host, ".")+1:]
		if _, e := strconv.ParseUint(last, 0, 64); e == nil || strings.Trim(last, "0123456789") == "" {
			return nil, errors.New("use a complete IPv4 address or DNS hostname")
		}
	}
	port := u.Port()
	if port != "" {
		number, e := strconv.Atoi(port)
		if e != nil || number < 1 || number > 65535 {
			return nil, errors.New("origin port must be between 1 and 65535")
		}
		port = strconv.Itoa(number)
		if number == 443 {
			port = ""
		}
	}
	u.Host = host
	if port != "" {
		u.Host = net.JoinHostPort(host, port)
	} else if strings.Contains(host, ":") {
		u.Host = "[" + host + "]"
	}
	return u, nil
}
