package jobs

import (
	"google.golang.org/protobuf/proto"

	agentv1 "github.com/auzring1/librepatch/gen/proto/librepatch/agent/v1"
)

func marshal(m proto.Message) ([]byte, error) { return proto.Marshal(m) }

func marshalSigned(se *agentv1.SignedEnvelope) ([]byte, error) { return proto.Marshal(se) }
