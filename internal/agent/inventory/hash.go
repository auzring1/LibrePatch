package inventory

import (
	"crypto/sha256"

	"google.golang.org/protobuf/proto"
)

func hashMsg(m proto.Message) []byte {
	b, _ := proto.MarshalOptions{Deterministic: true}.Marshal(m)
	h := sha256.Sum256(b)
	return h[:]
}
