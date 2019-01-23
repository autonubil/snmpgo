package snmpgo

import (
	"encoding/asn1"
	"errors"
	"fmt"
	"time"
)

// The PduTrapV1 is used by SNMP V1 and V2c, other than the SNMP V1 Trap
type PduTrapV1 struct {
	pduType      PduType
	enterprise   *Oid
	agentAddr    *Ipaddress
	genericTrap  int
	specificTrap int
	timeStamp    int
	varBinds     VarBinds
}

func (pdu *PduTrapV1) PduType() PduType {
	return pdu.pduType
}

func (pdu *PduTrapV1) RequestId() int {
	return 0
}
func (pdu *PduTrapV1) SetRequestId(int) {

}
func (pdu *PduTrapV1) ErrorStatus() ErrorStatus {
	return NoError
}
func (pdu *PduTrapV1) SetErrorStatus(ErrorStatus) {

}
func (pdu *PduTrapV1) ErrorIndex() int {
	return 0
}
func (pdu *PduTrapV1) SetErrorIndex(int) {

}
func (pdu *PduTrapV1) SetNonrepeaters(int) {

}
func (pdu *PduTrapV1) SetMaxRepetitions(int) {

}

func (pdu *PduTrapV1) AppendVarBind(oid *Oid, variable Variable) {
	pdu.varBinds = append(pdu.varBinds, &VarBind{
		Oid:      oid,
		Variable: variable,
	})
}

func (pdu *PduTrapV1) VarBinds() VarBinds {
	return pdu.varBinds
}

func (pdu *PduTrapV1) Marshal() (b []byte, err error) {
	var buf []byte
	raw := asn1.RawValue{Class: classContextSpecific, Tag: int(pdu.pduType), IsCompound: true}

	buf, err = asn1.Marshal(pdu.enterprise.Value)
	if err != nil {
		return
	}
	raw.Bytes = buf

	buf, err = asn1.MarshalWithParams(pdu.agentAddr.Value, "tag:0,application")
	if err != nil {
		return
	}
	raw.Bytes = append(raw.Bytes, buf...)

	buf, err = asn1.Marshal(pdu.genericTrap)
	if err != nil {
		return
	}
	raw.Bytes = append(raw.Bytes, buf...)

	buf, err = asn1.Marshal(pdu.specificTrap)
	if err != nil {
		return
	}
	raw.Bytes = append(raw.Bytes, buf...)

	buf, err = asn1.MarshalWithParams(pdu.timeStamp, "tag:3,application")
	if err != nil {
		return
	}
	raw.Bytes = append(raw.Bytes, buf...)

	varBinds := asn1.RawValue{Class: classUniversal, Tag: tagSequence, IsCompound: true}
	for i := 0; i < len(pdu.varBinds); i++ {
		buf, err = pdu.varBinds[i].Marshal()
		if err != nil {
			return
		}
		varBinds.Bytes = append(varBinds.Bytes, buf...)
	}

	buf, err = asn1.Marshal(varBinds)
	if err != nil {
		return
	}
	raw.Bytes = append(raw.Bytes, buf...)

	return asn1.Marshal(raw)
}

func (pdu *PduTrapV1) Unmarshal(b []byte) (rest []byte, err error) {
	return nil, errors.New("Not Implemented")
}

func (pdu *PduTrapV1) String() string {
	return fmt.Sprintf(
		`{"Type": "%s", "Enterprise": "%v", "genericTrap": "%v", `+
			`"specificTrap": "%d", "VarBinds": %s}`,
		pdu.pduType, pdu.enterprise, pdu.genericTrap, pdu.specificTrap,
		pdu.varBinds.String())
}

func NewPduTrapV1(ver SNMPVersion, t PduType, enterprise *Oid, genericTrap int, specificTrap int, ipaddress *Ipaddress) (pdu Pdu) {
	p := PduTrapV1{
		pduType:      t,
		enterprise:   enterprise,
		agentAddr:    ipaddress,
		genericTrap:  6,
		specificTrap: specificTrap,
		timeStamp:    int(time.Now().UnixNano() / 10000000),
	}
	switch ver {
	case V1:
		pdu = &p
	}
	return
}

func NewTrapV1WithOids(ver SNMPVersion, t PduType, enterprise *Oid, genericTrap int, specificTrap int, ipaddress *Ipaddress, oids Oids) (pdu Pdu) {
	pdu = NewPduTrapV1(ver, t, enterprise, genericTrap, specificTrap, ipaddress)
	for _, o := range oids {
		pdu.AppendVarBind(o, NewNull())
	}
	return
}

func NewPduTrapV1WithVarBinds(ver SNMPVersion, t PduType, enterprise *Oid, genericTrap int, specificTrap int, ipaddress *Ipaddress, varBinds VarBinds) (pdu Pdu) {
	pdu = NewPduTrapV1(ver, t, enterprise, genericTrap, specificTrap, ipaddress)
	for _, v := range varBinds {
		pdu.AppendVarBind(v.Oid, v.Variable)
	}
	return
}
