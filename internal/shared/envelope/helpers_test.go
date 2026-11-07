package envelope

import (
	"encoding/asn1"
	"encoding/hex"
)

type asn1OID = asn1.ObjectIdentifier

func hexKey(b []byte) string { return hex.EncodeToString(b) }
