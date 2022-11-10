package plugin

import "github.com/notaryproject/notation-go/plugin/proto"

func binName(name string) string {
	return proto.Prefix + name + ".exe"
}
