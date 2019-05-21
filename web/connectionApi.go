/*
# -*- coding: utf-8 -*-
# @Author : joker
# @Time : 2019-05-18 14:02 
# @File : connectionApi.go
# @Description :    获取ip通信的前10名
*/
package web

import (
	"encoding/json"
	"fmt"
	"github.com/google/gopacket"
	"gopacket_example/db"
	"gopacket_example/jobs"
	"log"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync/atomic"
)

var (
	sendRecord *SendRecord
)

func init() {
	sendRecord = new(SendRecord)
	sendRecord.SendDstMap = jobs.NewLRUCache()
}

type SendRecord struct {
	// sync.Mutex
	SendDstMap *jobs.LRUCache
	// sendDstMap map[uint64]*Definition
}

type Definition struct {
	IP     string
	MAC    net.HardwareAddr
	Counts uint64
}

func Record(dst gopacket.Endpoint) {
	key := dst.FastHash()
	if value, ok := sendRecord.SendDstMap.Cache.Peek(key); ok {
		definition := value.(*Definition)
		atomic.AddUint64(&definition.Counts, 1)
	} else {
		definition := &Definition{
			IP:     dst.String(),
			Counts: 1,
		}
		sendRecord.SendDstMap.Add(key, definition)
	}
}
func (s *SendRecord) Record(dst gopacket.Endpoint) {
	key := dst.FastHash()

	if value, ok := s.SendDstMap.Cache.Peek(key); ok {
		definition := value.(*Definition)
		atomic.AddUint64(&definition.Counts, 1)
	} else {
		definition := &Definition{
			IP:     dst.String(),
			Counts: 1,
		}
		s.SendDstMap.Add(key, definition)
	}
}

type DefinitionSorter []*Definition

func (this DefinitionSorter) Len() int {
	return len(this)
}

func (this DefinitionSorter) Less(i, j int) bool {
	if this[i].Counts < this[j].Counts {
		return false
	} else {
		return true
	}
}

func (this DefinitionSorter) Swap(i, j int) {
	this[i], this[j] = this[j], this[i]
}
func GetConnectionsFromDB(topK int) []ConnectionRecordJSON {
	var connections []NetFlow
	if err := db.DB.Raw("SELECT * FROM dlxy_flow ORDER BY count DESC LIMIT ?", topK).Find(&connections).Error; nil != err {
		log.Println("[GetConnectionsFromDB]err", err.Error())
		return GetConnections(topK)
	} else if len(connections) == 0 {
		records := GetConnections(topK)
		PersistenceIPConnection()
		return records
	} else {
		l := len(connections)
		records := make([]ConnectionRecordJSON, l)
		for i := 0; i < l; i++ {
			records[i].Counts = uint64(connections[i].Count)
			records[i].IP = connections[i].Ip
			if hw, err := net.ParseMAC(connections[i].Mac); nil == err {
				records[i].MAC = hw
			}
		}
		return records
	}
}
func GetConnections(topK int) []ConnectionRecordJSON {
	values := make([]*Definition, 0)
	keys := sendRecord.SendDstMap.Cache.Keys()
	for _, k := range keys {
		if value, exist := sendRecord.SendDstMap.Cache.Peek(k); exist {
			values = append(values, value.(*Definition))
		}
	}
	length := len(values)
	if length < topK {
		topK = length
	}

	// qSort(values, 0, length-1, topK)
	sort.Sort(DefinitionSorter(values))
	nodes := make([]ConnectionRecordJSON, topK)
	for i := 0; i < topK; i++ {
		nodes[i].Counts = values[i].Counts
		nodes[i].IP = values[i].IP
		nodes[i].MAC = values[i].MAC
	}
	return nodes
}
func (s *SendRecord) Show(topK int) {
	fmt.Println("本地向如下ip地址发送消息,top:", topK)
	values := make([]*Definition, 0)
	keys := s.SendDstMap.Cache.Keys()
	for _, k := range keys {
		if value, exist := s.SendDstMap.Cache.Peek(k); exist {
			values = append(values, value.(*Definition))
		}
	}
	length := len(values)
	if length < topK {
		topK = length
	}
	qSort(values, 0, length-1, topK)
	fmt.Println(fmt.Sprintf(strings.Repeat("=", 19) + "destinition" + strings.Repeat("=", 19) + "totalCounts"))
	for i := 0; i < topK; i++ {
		s := strings.Repeat(" ", 19) + "%v" + strings.Repeat(" ", 19) + "%d" + "\n"
		fmt.Printf(s, values[i].IP, values[i].Counts)
	}
}

func qSort(definitions []*Definition, start, end, topK int) {
	if start >= end {
		return
	}
	dealPivot(definitions, start, end)
	pivot := end - 1
	i, j := start, end-1
	for {
		for i < pivot && definitions[i].Counts > definitions[pivot].Counts {
			i++
		}
		for j > pivot && definitions[j].Counts < definitions[pivot].Counts {
			j--
		}
		if i < j {
			definitions[i], definitions[j] = definitions[j], definitions[i]
		} else {
			break
		}
	}

	if i < end {
		definitions[i], definitions[end-1] = definitions[end-1], definitions[i]
	}
	qSort(definitions, start, i-1, topK)
	if pivot < topK {
		qSort(definitions, i+1, end, topK)
	}
}

func dealPivot(definitions []*Definition, start, end int) {
	mid := (start + end) / 2
	if definitions[start].Counts < definitions[mid].Counts {
		definitions[start], definitions[mid] = definitions[mid], definitions[start]
	}
	if definitions[start].Counts < definitions[end].Counts {
		definitions[start], definitions[end] = definitions[end], definitions[start]
	}
	if definitions[end].Counts > definitions[mid].Counts {
		definitions[end], definitions[mid] = definitions[mid], definitions[end]
	}
}

type ConnectionRecordJSON struct {
	IP     string
	MAC    net.HardwareAddr
	Counts uint64
}

func GetConnectionsTopNumber(w http.ResponseWriter, req *http.Request) {
	connections := GetConnectionsFromDB(5)
	bytes, _ := json.Marshal(connections)
	w.Write(bytes)
}
