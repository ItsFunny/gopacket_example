package job

type UUID string
type JobType string

const (
	JOB_SORT JobType = "sort"
)

type INext interface {
}

type IValidator interface {
	ValidJobType(jobType JobType) bool
}

type IAppEvent interface {
	SetTimeStamp(timeStamp int64) IAppEvent
	GetTimeStamp() int64

	SetData(data interface{}) IAppEvent
	GetData() interface{}

	SetUUID(uuid UUID) IAppEvent
	GetUUID() UUID

	SetExtPropsMap(propsMap map[string]interface{}) IAppEvent
	GetExtPropsMap() map[string]interface{}

	SetJobType(jobType ...JobType) IAppEvent
	GetJobType() JobType

	ValidJobType(jobType JobType) bool

	Copy(data interface{}) IAppEvent
}

type IJobExecutor interface {
	Execute(job IAppEvent) interface{}
}

type IConcreteExecutor interface {
	DoExecute(job IAppEvent) (interface{}, bool)
}

type IJobHandler interface {
	// INext
	// IValidator
	Handle(job IAppEvent) interface{}
}
type LinkedJobHandler interface {
	SetNext(next INext) LinkedJobHandler
	GetNext() LinkedJobHandler
}

// 核心结构体
type JobExecuteMediator struct {
	Executor IJobExecutor
}

func NewJobExecuteMediator(executor IJobExecutor) *JobExecuteMediator {
	return &JobExecuteMediator{Executor: executor}
}
func (receiver *JobExecuteMediator) Execute(job IAppEvent) interface{} {
	return receiver.Executor.Execute(job)
}

type appEvent struct {
	jobTypes         []JobType
	timeStamp        int64
	uuid             UUID
	serializableData interface{}
	extraPropsMap    map[string]interface{}
	Clone            func(app IAppEvent, data interface{})
}

func (receiver *appEvent) Copy(data interface{}) IAppEvent {
	receiver.Clone(receiver, data)
	return receiver
}

func NewAppEvent() *appEvent {
	return &appEvent{jobTypes: make([]JobType, 0)}
}
func NewAppEventWithCopy(copy func(IAppEvent, interface{})) *appEvent {
	return &appEvent{
		jobTypes: make([]JobType, 0),
		Clone:    copy,
	}
}

func (receiver *appEvent) SetJobType(jobType ...JobType) IAppEvent {
	receiver.jobTypes = append(receiver.jobTypes, jobType...)
	return receiver
}

func (receiver *appEvent) GetJobType() JobType {
	return receiver.jobTypes[0]
}

func (receiver *appEvent) SetTimeStamp(timeStamp int64) IAppEvent {
	receiver.timeStamp = timeStamp
	return receiver
}

func (receiver *appEvent) GetTimeStamp() int64 {
	return receiver.timeStamp
}

func (receiver *appEvent) SetData(data interface{}) IAppEvent {
	receiver.serializableData = data
	return receiver
}

func (receiver *appEvent) GetData() interface{} {
	return receiver.serializableData
}

func (receiver *appEvent) SetUUID(uuid UUID) IAppEvent {
	receiver.uuid = uuid
	return receiver
}

func (receiver *appEvent) GetUUID() UUID {
	return receiver.uuid
}

func (receiver *appEvent) SetExtPropsMap(propsMap map[string]interface{}) IAppEvent {
	receiver.extraPropsMap = propsMap
	return receiver
}

func (receiver *appEvent) GetExtPropsMap() map[string]interface{} {
	return receiver.extraPropsMap
}

func (receiver *appEvent) ValidJobType(jobType JobType) bool {
	l := len(receiver.jobTypes)
	if l > 0 {
		if receiver.jobTypes[0] == jobType {
			if l > 1 {
				receiver.jobTypes = append(receiver.jobTypes[:0], receiver.jobTypes[1:]...)
			} else {
				receiver.jobTypes[0] = ""
			}
			return true
		}
	}
	return false
}
