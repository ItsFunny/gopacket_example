package job

import (
	"sort"
)

type ISortJobHandler interface {
	IJobHandler
}

type ISorter interface {
	sort.Interface

	Sort(event IAppEvent) interface{}
	ValidSortedBy(jobType JobType) bool

	SetSortItems(data interface{})
	GetSortedItems() interface{}
}

type SortJobExecutor struct {
	*BaseJobExecutor
	SortHandler IJobHandler
}

func NewSortExecutorMediator(sorter ISorter) *JobExecuteMediator {
	return NewJobExecuteMediator(NewSortJobExecutor(NewSortJobHandler(sorter)))
}

func NewSortJobExecutor(sortHandler IJobHandler) *SortJobExecutor {
	executor := &SortJobExecutor{
		BaseJobExecutor: new(BaseJobExecutor),
	}
	executor.SortHandler = sortHandler
	executor.Type = JOB_SORT
	executor.ConcreteExecutor = executor

	return executor
}

func SortAppEventBuilder(data interface{}, sortType JobType) IAppEvent {
	appEvent := NewAppEvent()
	return appEvent.SetJobType(JOB_SORT, sortType).SetData(data)
}

func NewSortJobHandler(sorter ISorter) *BaseSortJobHandler {
	return &BaseSortJobHandler{Sorter: sorter}
}

func (receiver *SortJobExecutor) DoExecute(job IAppEvent) (interface{},bool) {
	return receiver.SortHandler.Handle(job),false
}

type BaseSortJobHandler struct {
	Sorter ISorter
}

func (receiver *BaseSortJobHandler) ValidJobType(jobType JobType) bool {
	return jobType == JOB_SORT
}

func (receiver *BaseSortJobHandler) Handle(job IAppEvent) interface{} {
	if nil == receiver.Sorter {
		return nil
	} else {
		return receiver.Sorter.Sort(job)
	}
}
