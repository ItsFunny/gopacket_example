/*
# -*- coding: utf-8 -*-
# @Author : joker
# @Time : 2019-05-18 08:47 
# @File : filterResp.go
# @Description : 
*/
package jobs

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"myLibrary/library/src/main/go/job"
)

type FilterUdp struct {
	UDP *layers.UDP
	JobType job.JobType
}
type FilterTcp struct {
	TCP *layers.TCP
	Flow gopacket.Flow
	JobType job.JobType
}
