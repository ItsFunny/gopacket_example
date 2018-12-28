package examples

import (
	"unsafe"

	"github.com/google/gopacket/pcap"

	"golang.org/x/net/bpf"
)

// ToPcapBPFInstructions converts a []bpf.RawInstruction into a []pcap.BPFInstruction
//#nosec
func Raw2PcapBPFInstructionSlice(in []bpf.RawInstruction) []pcap.BPFInstruction {
	return *(*[]pcap.BPFInstruction)(unsafe.Pointer(&in))
}

// ToPcapBPFInstruction converts a bpf.RawInstruction into a pcap.BPFInstruction
//#nosec
func Raw2PcapBPFInstruction(in bpf.RawInstruction) pcap.BPFInstruction {
	return *(*pcap.BPFInstruction)(unsafe.Pointer(&in))
}

// ToBpfRawInstructions converts a []pcap.BPFInstruction into a []bpf.RawInstruction
//#nosec
func Bpf2RawInstructions(in []pcap.BPFInstruction) []bpf.RawInstruction {
	return *(*[]bpf.RawInstruction)(unsafe.Pointer(&in))
}

// ToBpfRawInstruction converts a pcap.BPFInstruction into a bpf.RawInstruction
//#nosec
func Bpf2RawInstruction(in pcap.BPFInstruction) bpf.RawInstruction {
	return *(*bpf.RawInstruction)(unsafe.Pointer(&in))
}

// ToBpfInstructions converts a []pcap.BPFInstruction into a []bpf.Instructions
func Bpf2BpfInstructionSlice(in []pcap.BPFInstruction) ([]bpf.Instruction, bool) {
	return bpf.Disassemble(Bpf2RawInstructions(in))
}

// ToBpfInstruction converts a pcap.BPFInstruction into a bpf.Instruction
func Bpf2BpfInstruction(in pcap.BPFInstruction) bpf.Instruction {
	return Bpf2RawInstruction(in).Disassemble()
}
