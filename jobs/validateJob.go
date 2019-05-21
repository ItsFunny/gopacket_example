/*
# -*- coding: utf-8 -*-
# @Author : joker
# @Time : 2019-05-18 08:52 
# @File : validateJob.go
# @Description : 
*/
package jobs

import (
	"fmt"
	"github.com/emirpasic/gods/lists/arraylist"
	ll "github.com/hashicorp/golang-lru"
	"myLibrary/library/src/main/go/job"
	"sync"
	"sync/atomic"
)

var (
	tcpHolder *TcpHolder
)

const JOB_VALIDATE = "VALIDATE"

func init() {
	tcpHolder = &TcpHolder{
		RWMutex: sync.RWMutex{},
		// tcps:    doublylinkedlist.New(),
		tcpss: NewLRUCache(),
	}
}

type IPacketValidateJob interface {
	job.IJobConcreteHandler
}
type PacketValidateJobExecutor struct {
	*job.BaseJobExecutor
	JobValidate job.IJobHandler
}
type BasePacketValidateJobHandler struct {
	*job.BaseJobHandler
}

func NewPacketValidateJobExecutor(handler job.IJobHandler) job.IJobExecutor {
	executor := &PacketValidateJobExecutor{}
	executor.BaseJobExecutor = new(job.BaseJobExecutor)
	executor.ConcreteExecutor = executor
	executor.Type = JOB_VALIDATE
	executor.JobValidate = handler
	cache := ll.Cache{}
	fmt.Println(cache)
	return executor
}
func NewValidateHandler() job.IJobHandler {
	tcpHander := &BasePacketValidateJobHandler{new(job.BaseJobHandler)}
	tcpHander.Type = "tcp"
	tcpHander.ConcreteHandler = new(TcpPacketValidation)

	udpHandler := &BasePacketValidateJobHandler{new(job.BaseJobHandler)}
	udpHandler.Type = "udp"
	udpHandler.ConcreteHandler = new(UdpPacketValidation)
	tcpHander.NextHandler = udpHandler
	return tcpHander
}

func (e *PacketValidateJobExecutor) DoExecute(job job.IAppEvent) (interface{}, bool) {
	return e.JobValidate.Handle(job), false
}

type LRUCache struct {
	sync.RWMutex
	// Cache *lru.Cache
	Cache      *ll.Cache
	Count      int64
	ThresholdCache int64
}

func (this *LRUCache) AtomicIncreCount() {
	atomic.AddInt64(&this.Count, 1)
}
func (this *LRUCache) ClearCount() {
	this.Lock()
	defer this.Unlock()
	this.Count = 0
}

func (this *LRUCache) Add(key, value interface{}) {
	this.Cache.Add(key, value)
	this.AtomicIncreCount()
}

func NewLRUCache() *LRUCache {
	cache := LRUCache{}
	cache.ThresholdCache=80
	// cache.Cache = lru.NewCache(100)
	c, e := ll.New(100)
	if nil != e {
		panic(e)
	}
	cache.Cache = c
	return &cache
}
func NewFixedLRUCache(size int) *LRUCache {
	cache := LRUCache{}
	// cache.Cache = lru.NewCache(size)
	// cache.Cache = lru.NewCache(100)
	c, e := ll.New(100)
	if nil != e {
		panic(e)
	}
	cache.Cache = c
	return &cache
}

type TcpPacketValidation struct {
}

// FIXME
type TcpNode struct {
	sync.RWMutex
	id   uint64
	list *arraylist.List
	List *LRUCache
}

// FIXME
type TcpPacketWrapper struct {
	sync.Mutex
	Seq               uint32
	Ack               uint32
	DuplicateAckTimes byte
}

type PacketModel struct {
	HashCode uint64
	Wrapper  *TcpPacketWrapper
	Data     interface{}
}

func (t *TcpPacketValidation) DoHandle(job job.IAppEvent) interface{} {
	data := job.GetData().(*PacketModel)
	hashCode := data.HashCode
	wrapper := data.Wrapper
	// wg := sync.WaitGroup{}
	// wg.Add(3)

	// 校验是否是duplicateAck
	// 校验是否是TCP Restransmission
	// 校验是否是sync-flood
	// go func() {
	// 	defer wg.Done()
	fmt.Println(tcpHolder.IsDuplicateAck(hashCode, wrapper))
	// go func() {
	// 	web.Record(data.Data.(gopacket.Flow).Dst())
	// }()
	// }()
	// wg.Wait()

	return nil
}

type UdpPacketValidation struct {
}

func (this *UdpPacketValidation) DoHandle(job job.IAppEvent) interface{} {
	panic("implement me")
}

// FIXME
type TcpHolder struct {
	sync.RWMutex
	// tcps  *doublylinkedlist.List
	tcpss *LRUCache
}

func (t *TcpHolder) IsDuplicateAck(hashCode uint64, wrapper *TcpPacketWrapper) bool {
	var isDuplicateAck bool
	var isExist bool
	t.RLock()

	for _, key := range t.tcpss.Cache.Keys() {
		if isDuplicateAck {
			break
		}
		if id := key.(uint64); id == hashCode {
			isExist = true
			t.RUnlock()

			nodeInterface, _ := t.tcpss.Cache.Peek(key)
			node := nodeInterface.(*TcpNode)
			node.RLock()
			for _, nKey := range node.List.Cache.Keys() {
				tcpWrapperInterface, _ := node.List.Cache.Peek(nKey)
				if tcpWrapper := tcpWrapperInterface.(*TcpPacketWrapper); tcpWrapper.Seq == wrapper.Seq {
					// 异常流量
					node.RUnlock()
					if tcpWrapper.DuplicateAckTimes < 2 {
						tcpWrapper.Lock()
						if tcpWrapper.DuplicateAckTimes < 2 {
							tcpWrapper.DuplicateAckTimes++
							tcpWrapper.Unlock()
						} else {
							tcpWrapper.Unlock()
							isDuplicateAck = true
							break
						}
					} else {
						break
					}
				}

			}
			if !isDuplicateAck {
				node.list.Add(wrapper)
				node.List.Lock()
				defer node.List.Unlock()
				node.List.Cache.Add(hashCode, wrapper)
				node.Unlock()
			}
		}
	}
	if !isExist {
		// t.RUnlock()
		// t.Lock()
		// tcpNode := &TcpNode{
		// 	id:   hashCode,
		// 	list: arraylist.New(),
		// 	List: NewLRUCache(),
		// }
		// tcpNode.list.Add(wrapper)
		// t.tcps.Add(tcpNode)
		// t.Unlock()

		tcpNode := &TcpNode{
			id:   hashCode,
			list: arraylist.New(),
			List: NewLRUCache(),
		}

		t.tcpss.Lock()
		defer t.tcpss.Unlock()
		t.tcpss.Cache.Add(hashCode, tcpNode)

		tcpNode.List.Lock()
		tcpNode.List.Unlock()
		tcpNode.List.Cache.Add(hashCode, wrapper)
	}
	return isDuplicateAck
}
func (t *TcpHolder) ValidatePacket(hashCode uint64, wrapper *TcpPacketWrapper) {
	wg := sync.WaitGroup{}
	wg.Add(3)
	// duplicate ack
	go func() {
		defer wg.Done()
		t.IsDuplicateAck(hashCode, wrapper)
	}()
	// tcp restransmission 包重传
	go func() { defer wg.Done() }()

	// sync flood
	go func() {
		defer wg.Done()
	}()
	wg.Wait()
}
