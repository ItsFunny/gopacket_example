/*
# -*- coding: utf-8 -*-
# @Author : joker
# @Time : 2019-05-19 08:05 
# @File : consisten.go
# @Description : 
*/
package web

import (
	"github.com/gitstliu/go-id-worker"
	"github.com/hashicorp/golang-lru"
	"github.com/jinzhu/gorm"
	"gopacket_example/db"
	"log"
	"time"
)

var (
	worker idworker.IdWorker
)

func init() {
	worker.InitIdWorker(11, 13)
}

type NetFlow struct {
	Id          int64     `gorm:"column:id" `
	Ip          string    `gorm:"column:ip" `
	CreatedDate time.Time `gorm:"column:created_date" `
	UpdatedDate time.Time `gorm:"column:updated_date" `
	Data        string    `gorm:"column:data" `
	Count       int64     `gorm:"column:count" `
	Mac         string    `gorm:"column:mac" `
}

func PersistenceIPConnection() {
	keys := sendRecord.SendDstMap.Cache.Keys()
	for _, key := range keys {
		now := time.Now()
		if value, exist := sendRecord.SendDstMap.Cache.Peek(key); exist {
			definition := value.(*Definition)
			var netFlow NetFlow
			if err := db.DB.Table("dlxy_flow").Where("ip=?", definition.IP).Find(&netFlow).Error; nil != err && err != gorm.ErrRecordNotFound {
				log.Println("[PersistenceIPConnection] count,err:", err.Error())
				return
			} else if netFlow.Id > 0 {
				if err := db.DB.Exec("UPDATE dlxy_flow SET count=?,updated_date=? WHERE ip=?", int64(definition.Counts)+netFlow.Count, now, netFlow.Ip).Error; nil != err {
					log.Println("[PersistenceIPConnection] count,err:", err.Error())
					return
				}
				continue
			}
			time.Sleep(time.Microsecond)
			id, _ := worker.NextId()
			if err := db.DB.Table("dlxy_flow").Create(&NetFlow{
				Id:          id,
				Ip:          definition.IP,
				CreatedDate: time.Now(),
				UpdatedDate: time.Now(),
				Data:        "",
				Count:       int64(definition.Counts),
				Mac:         definition.MAC.String(),
			}).Error; nil != err {
				log.Println("[PersistenceIPConnection] persistence error")
			}
		}
	}
	sendRecord.SendDstMap.Lock()
	defer sendRecord.SendDstMap.Unlock()
	sendRecord.SendDstMap.Cache, _ = lru.New(100)
}
