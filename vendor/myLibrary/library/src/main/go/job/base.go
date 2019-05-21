/*
# -*- coding: utf-8 -*-
# @Author : joker
# @Time : 2019-05-18 09:08 
# @File : base.go
# @Description : 
*/
package job

type BaseJobExecutor struct {
	ConcreteExecutor IConcreteExecutor
	Type             JobType
	NextExecutor     IJobExecutor
}

// func (receiver *BaseJobExecutor) ValidJobType(jobType JobType) bool {
// 	return receiver.Type == jobType
// }

func (receiver *BaseJobExecutor) Execute(job IAppEvent) interface{} {
	if nil == receiver.ConcreteExecutor {
		return nil
	}
	if job.ValidJobType(receiver.Type) {
		data, b := receiver.ConcreteExecutor.DoExecute(job)
		if !b || nil == receiver.NextExecutor {
			return data
		} else if b {
			return receiver.NextExecutor.Execute(job.Copy(data))
		}
		return data
	} else if nil != receiver.NextExecutor {
		return receiver.NextExecutor.Execute(job)
	} else {
		return nil
	}
}

type IJobConcreteHandler interface {
	DoHandle(job IAppEvent) interface{}
}
type BaseJobHandler struct {
	ConcreteHandler IJobConcreteHandler
	Type            JobType
	NextHandler     IJobHandler
}

func (receiver *BaseJobHandler) Handle(job IAppEvent) interface{} {
	if nil == receiver.ConcreteHandler {
		return nil
	}
	if job.ValidJobType(receiver.Type) {
		data := receiver.ConcreteHandler.DoHandle(job)
		return data
	} else if nil != receiver.NextHandler {
		return receiver.NextHandler.Handle(job)
	} else {
		return nil
	}
}
