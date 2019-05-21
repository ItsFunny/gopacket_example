/*
# -*- coding: utf-8 -*-
# @Author : joker
# @Time : 2019-05-18 08:37 
# @File : filterJob.go
# @Description : 
*/
package jobs

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"myLibrary/library/src/main/go/job"
)

const JOB_FILTER = "FILTER"

var (
	FILTER_COPY = func(app job.IAppEvent, data interface{}) {
		switch data.(type) {
		case *FilterUdp:
			udp := data.(*FilterUdp)
			app.SetJobType(udp.JobType)
			app.SetData(udp.UDP)
		case *FilterTcp:
			tcp := data.(*FilterTcp)
			app.SetJobType(tcp.JobType)
			wrapper := &TcpPacketWrapper{
				Seq:               tcp.TCP.Seq,
				DuplicateAckTimes: 0,
			}
			m := &PacketModel{
				HashCode: uint64(tcp.TCP.Ack),
				Wrapper:  wrapper,
				Data:     tcp.Flow,
			}
			app.SetData(m)
		}
	}
)

type IPacketFilter interface {
	job.IJobHandler
}
type FilterJobExecutor struct {
	*job.BaseJobExecutor
}

func (e *FilterJobExecutor) DoExecute(job job.IAppEvent) (interface{}, bool) {
	dataInterface := job.GetData()
	p := dataInterface.(gopacket.Packet)

	if udpLayer := p.Layer(layers.LayerTypeUDP); nil != udpLayer {
		udp := udpLayer.(*layers.UDP)
		filterUdp := &FilterUdp{
			UDP:     udp,
			JobType: "udp",
		}
		return filterUdp, true
	} else if tcpLayerType := p.Layer(layers.LayerTypeTCP); nil != tcpLayerType {
		tcp := tcpLayerType.(*layers.TCP)
		netFlow := p.NetworkLayer()
		filterTcp := &FilterTcp{
			TCP:     tcp,
			JobType: "tcp",
			Flow:    netFlow.NetworkFlow(),
		}
		return filterTcp, true
	} else {
		return nil, false
	}
}

func NewFilterJobExecutor(next job.IJobExecutor) job.IJobExecutor {
	executor := &FilterJobExecutor{new(job.BaseJobExecutor)}
	executor.Type = JOB_FILTER
	executor.ConcreteExecutor = executor
	executor.NextExecutor = next
	return executor
}
