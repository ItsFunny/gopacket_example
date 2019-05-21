/*
# -*- coding: utf-8 -*-
# @Author : joker
# @Time : 2019-05-19 09:02 
# @File : monitor.go
# @Description : 
*/
package web

func MonitorConenctionMap() {
	if sendRecord.SendDstMap.Count >= sendRecord.SendDstMap.ThresholdCache {
		PersistenceIPConnection()
		sendRecord.SendDstMap.ClearCount()
	}
}
