/*
# -*- coding: utf-8 -*-
# @Author : joker
<<<<<<< HEAD
# @Time : 2019-05-01 09:53 
# @File : jobType.go
# @Description : 
=======
# @Time : 2019-05-01 09:53
# @File : jobType.go
# @Description :
>>>>>>> 3d740cf8d36b89bfff643ad65f83345d942d5ca8
*/
package job

type JobTypeNode struct {
	Type JobType
	Next *JobTypeNode
}

type JobTypeLinkedList struct {
	Head *JobTypeNode
}

func (receiver *JobTypeLinkedList) Push(jobType JobType) {
}
