# JOB 任务分发



# 使用方法

* 比如说有validatePacket的业务
    * 先创建对应的executor:
    ```
    type PacketValidateJobExecutor struct {
    	*job.BaseJobExecutor
    	JobValidate job.IJobHandler
    }
    内部只需要继承BaseJobExecutor,再添加job.IJobHandler即可
    
    ```
    * 创建的executor实现job.IConcreteExecutor接口
    ```
    func (e *PacketValidateJobExecutor) DoExecute(job job.IAppEvent) (interface{}, bool) {
    	return e.JobValidate.Handle(job), false
    }
    
    ```
    *  创建业务的handler接口
    ```
    type IPacketValidateJob interface {
    	job.IJobConcreteHandler
    }
    内部可根据需求再添加额外的方法
    ```
    * 根据不同的策略实现具体的方法
    ```
    func (this *TcpPacketValidation) DoHandle(job job.IAppEvent) interface{} {
    	panic("implement me")
    }
    
    func (this *UdpPacketValidation) DoHandle(job job.IAppEvent) interface{} {
    	panic("implement me")
    }
    ```
    * 最后,工厂方式创建:
        -   创建业务对应的executor工厂方法:
        ```
        func NewPacketValidateJobExecutor(handler job.IJobHandler) job.IJobExecutor {
        	executor := &PacketValidateJobExecutor{}
        	executor.BaseJobExecutor = new(job.BaseJobExecutor)
        	executor.Type = JOB_VALIDATE
        	executor.JobValidate = handler
        	return executor
        }
        ```
        - 创建业务对应的handler工厂方法:
        ```
        func NewValidateHandler() job.IJobHandler {
        	tcpHander := &BasePacketValidateJobHandler{}
        	tcpHander.Type = "tcp"
        	tcpHander.ConcreteHandler = new(TcpPacketValidation)
        
        	udpHandler := &BasePacketValidateJobHandler{}
        	udpHandler.Type = "udp"
        	udpHandler.ConcreteHandler = new(UdpPacketValidation)
        	tcpHander.NextHandler = udpHandler
        
        	return tcpHander
        }
        ```
        - 最后再统一固定格式:
        ```
            mediator := job.NewJobExecuteMediator(jobs.NewPacketValidateJobExecutor(jobs.NewValidateHandler()))
            res := mediator.Execute(job.NewAppEvent().SetData(packet).SetJobType(jobs.JOB_VALIDATE))
            NewJobExecuteMediator方法,在base中已提供
        ```
