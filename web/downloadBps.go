/*
# -*- coding: utf-8 -*-
# @Author : joker
# @Time : 2019-05-18 13:23 
# @File : api.go
# @Description : 
*/
package web

import (
	"encoding/json"
	"gopacket_example/jobs"
	"net/http"
	"time"
)

var (
	downLoadDateRecorder *DownloadDateRecorder
)

func init() {
	downLoadDateRecorder = new(DownloadDateRecorder)
	downLoadDateRecorder.Cache = jobs.NewLRUCache()
}

type DownloadRecordListNode struct {
	// unixTime
	RecordTime     int64
	DownBps, UpBps float64
}
type DownloadDateRecorder struct {
	PeekDownBps, PeekUpStreamBps float64
	Cache                        *jobs.LRUCache
}

func AddRecord(timeUnix int64, downStream, upStream float64) {
	downLoadDateRecorder.Cache.Add(time.Now().Unix(), DownloadRecordListNode{
		RecordTime: time.Now().Unix(),
		DownBps:    downStream,
		UpBps:      upStream,
	})
	if downStream > downLoadDateRecorder.PeekDownBps {
		downLoadDateRecorder.PeekDownBps = downStream
	}
	if upStream > downLoadDateRecorder.PeekUpStreamBps {
		downLoadDateRecorder.PeekUpStreamBps = upStream
	}
}

type DownloadRecordJSON struct {
	RecordTime      int64   `json:"recordTime"`
	DownBps         float64 `json:"downBps"`
	UpBps           float64 `json:"upBps"`
	PeekDownBps     float64 `json:"peekDownBps"`
	PeekUpStreamBps float64 `json:"peekUpStreamBps"`
}

func GetLatestSpeed(w http.ResponseWriter, req *http.Request) {
	keys := downLoadDateRecorder.Cache.Cache.Keys()
	l := len(keys)
	record := DownloadRecordListNode{}
	if l != 0 {
		value, ok := downLoadDateRecorder.Cache.Cache.Peek(keys[l-1])
		if ok {
			record = value.(DownloadRecordListNode)
		}
		res := DownloadRecordJSON{
			RecordTime:      record.RecordTime,
			DownBps:         record.DownBps,
			UpBps:           record.UpBps,
			PeekDownBps:     downLoadDateRecorder.PeekDownBps,
			PeekUpStreamBps: downLoadDateRecorder.PeekUpStreamBps,
		}
		bytes, _ := json.Marshal(res)
		w.Write(bytes)
	}

}
