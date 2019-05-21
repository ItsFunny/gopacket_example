/*
# -*- coding: utf-8 -*-
# @Author : joker
# @Time : 2019-05-18 13:25 
# @File : db.go
# @Description : 
*/
package db

import (
	_ "database/sql/driver"
	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/mysql"
)

var (
	DB  *gorm.DB
	err error
)

func init() {
	// local
	DB, err = gorm.Open("mysql", "root:123456@tcp(127.0.0.1:3306)/JN?charset=utf8&parseTime=true&loc=Local")
	// dev
	// DB, err = gorm.Open("mysql", "root:mysql@jialong.com@tcp(172.16.2.69:3306)/PLATFORM?charset=utf8&parseTime=true")
	// test
	// DB, err = gorm.Open("mysql", "root:mysql@jialong.com@tcp(172.16.2.150:3306)/PLATFORM?charset=utf8&parseTime=true")
	// 阿里云
	// DB, err = gorm.Open("mysql", "root:123456@tcp(120.78.240.211:3306)/JN?charset=utf8&parseTime=true&loc=Local")

	if nil != err {
		panic(err)
	}
	DB.LogMode(true)

}
