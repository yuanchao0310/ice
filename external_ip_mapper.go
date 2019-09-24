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

type mappings struct {
	mapAllIP net.IP
	ipMap    map[string]net.IP
}

func (m *mappings) setMapAllIP(ip net.IP) error {
	if m.mapAllIP != nil || len(m.ipMap) > 0 {
		return ErrInvalidNAT1To1IPMapping
	}

	m.mapAllIP = ip

	return nil
}

func (m *mappings) addIPMapping(src string, dest net.IP) error {
	if m.mapAllIP != nil {
		return ErrInvalidNAT1To1IPMapping
	}

	// check if dup of local IP
	if _, ok := m.ipMap[src]; ok {
		return ErrInvalidNAT1To1IPMapping
	}

	m.ipMap[src] = dest

	return nil
}

func (m *mappings) findExternalIP(localIPStr string) (net.IP, error) {
	if m.mapAllIP != nil {
		return m.mapAllIP, nil
	}

	extIP, ok := m.ipMap[localIPStr]
	if !ok {
		return nil, ErrExternalMappedIPNotFound
	}

	return extIP, nil
}

type externalIPMapper struct {
	ipv4Mappings  mappings
	ipv6Mappings  mappings
	candidateType CandidateType
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
		ipv4Mappings:  mappings{ipMap: map[string]net.IP{}},
		ipv6Mappings:  mappings{ipMap: map[string]net.IP{}},
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
				if err := m.ipv4Mappings.setMapAllIP(extIP); err != nil {
					return nil, err
				}
			} else {
				if err := m.ipv6Mappings.setMapAllIP(extIP); err != nil {
					return nil, err
				}
			}
		} else {
			locIP, isLocIPv4, err := validateIPString(ipPair[1])
			if err != nil {
				return nil, err
			}
			if isExtIPv4 {
				if !isLocIPv4 {
					return nil, ErrInvalidNAT1To1IPMapping
				}

				if err := m.ipv4Mappings.addIPMapping(locIP.String(), extIP); err != nil {
					return nil, err
				}
			} else {
				if isLocIPv4 {
					return nil, ErrInvalidNAT1To1IPMapping
				}

				if err := m.ipv6Mappings.addIPMapping(locIP.String(), extIP); err != nil {
					return nil, err
				}
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
		return m.ipv4Mappings.findExternalIP(locIP.String())
	}

	return m.ipv6Mappings.findExternalIP(locIP.String())
}
