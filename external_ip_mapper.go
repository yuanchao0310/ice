package ice

import (
	"net"
	"strings"
)

func validateIPString(ipStr string) (net.IP, bool, error) {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return nil, false, ErrInvalidNAT1To1IPMapping
	}
	return ip, (ip.To4() != nil), nil
}

type externalIPMapper struct {
	ipv4Map            map[string]net.IP
	ipv6Map            map[string]net.IP
	isLocIPv4Specified bool // if true, ipv4Map has 0 or 1 external IPv4
	isLocIPv6Specified bool // if true, ipv6Map has 0 or 1 external IPv6
	candidateType      CandidateType
}

func newExternalIPMapper(candidateType CandidateType, ips []string) (*externalIPMapper, error) {
	if len(ips) == 0 {
		return nil, nil
	}
	if candidateType == CandidateTypeUnspecified {
		candidateType = CandidateTypeHost // defaults to host
	} else if candidateType != CandidateTypeHost && candidateType != CandidateTypeServerReflexive {
		return nil, ErrUnsupportedNAT1To1IPCandidateType
	}

	m := &externalIPMapper{
		ipv4Map:       map[string]net.IP{},
		ipv6Map:       map[string]net.IP{},
		candidateType: candidateType,
	}

	for _, extIPStr := range ips {
		ipPair := strings.Split(extIPStr, "/")
		if len(ipPair) == 0 || len(ipPair) > 2 {
			return nil, ErrInvalidNAT1To1IPMapping
		}

		extIP, isExtIPv4, err := validateIPString(ipPair[0])
		if err != nil {
			return nil, err
		}
		if len(ipPair) == 1 {
			if isExtIPv4 {
				if m.isLocIPv4Specified || len(m.ipv4Map) > 0 {
					return nil, ErrInvalidNAT1To1IPMapping
				}
				m.ipv4Map["*"] = extIP
			} else {
				if m.isLocIPv6Specified || len(m.ipv6Map) > 0 {
					return nil, ErrInvalidNAT1To1IPMapping
				}
				m.ipv6Map["*"] = extIP
			}
		} else {
			locIP, isLocIPv4, err := validateIPString(ipPair[1])
			if err != nil {
				return nil, err
			}
			if isExtIPv4 {
				m.isLocIPv4Specified = true
				if !isLocIPv4 {
					return nil, ErrInvalidNAT1To1IPMapping
				}
				// check if dup of local IP
				if _, ok := m.ipv4Map[locIP.String()]; ok {
					return nil, ErrInvalidNAT1To1IPMapping
				}
				m.ipv4Map[locIP.String()] = extIP
			} else {
				if isLocIPv4 {
					return nil, ErrInvalidNAT1To1IPMapping
				}
				// check if dup of local IP
				if _, ok := m.ipv6Map[locIP.String()]; ok {
					return nil, ErrInvalidNAT1To1IPMapping
				}
				m.isLocIPv6Specified = true
				m.ipv6Map[locIP.String()] = extIP
			}
		}
	}

	return m, nil
}

func (m *externalIPMapper) findExternalIP(localIPStr string) (net.IP, error) {
	locIP, isLocIPv4, err := validateIPString(localIPStr)
	if err != nil {
		return nil, err
	}

	if isLocIPv4 {
		if m.isLocIPv4Specified {
			extIP, ok := m.ipv4Map[locIP.String()]
			if !ok {
				return nil, ErrExternalMappedIPNotFound
			}
			return extIP, nil
		}

		extIP, ok := m.ipv4Map["*"]
		if !ok {
			return nil, ErrExternalMappedIPNotFound
		}
		return extIP, nil
	}

	if m.isLocIPv6Specified {
		extIP, ok := m.ipv6Map[locIP.String()]
		if !ok {
			return nil, ErrExternalMappedIPNotFound
		}
		return extIP, nil
	}

	extIP, ok := m.ipv6Map["*"]
	if !ok {
		return nil, ErrExternalMappedIPNotFound
	}
	return extIP, nil
}
