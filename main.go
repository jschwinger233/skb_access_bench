package main

import (
	"encoding/hex"
	"fmt"
	"time"

	"github.com/jschwinger233/skb_access_bench/bpf"

	"github.com/cilium/ebpf"
)

func main() {
	progs := bpf.LoadProgram()
	// curl 1.1.1.1
	tcpseg := "7898e85e227d58ef687e15eb08004500003c488240004006e6310a00000701010101d03c0050b98fd0d000000000a002faf00c370000020405b40402080afa389db60000000001030307"
	data := make([]byte, 256)
	data, _ = hex.DecodeString(tcpseg)

	ctx := make([]byte, 256)
	for _, prog := range progs {
		start := time.Now()
		_, _, _, err := runBpfProgram(prog, data, ctx)
		if err != nil {
			panic(err)
		}
		fmt.Printf("%s: %v\n", prog.String(), time.Since(start))
	}
}

func runBpfProgram(prog *ebpf.Program, data, ctx []byte) (statusCode uint32, dataOut, ctxOut []byte, err error) {
	dataOut = make([]byte, len(data))
	ctxOut = make([]byte, len(ctx))
	opts := &ebpf.RunOptions{
		Data:       data, // skb->data
		DataOut:    dataOut,
		Context:    ctx, // memcpy(skb, ctx, sizeof(skb))
		ContextOut: ctxOut,
		Repeat:     9999999,
	}
	ret, err := prog.Run(opts)
	return ret, opts.DataOut, ctxOut, err
}
