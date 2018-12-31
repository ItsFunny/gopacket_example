package main

import "log"

func main() {
	values := []uint64{3, 21235, 123, 1, 2, 6123, 24, 0,2,34123,1234,2465,0,34,123}
	qSort2(values, 0, len(values)-1,3)

}
func qSort2(values []uint64, start, end ,topK int,) {
	if start >= end {
		return
	}
	p := paration2(values, start, end)
	if p>=topK{
		qSort2(values, start, p-1,topK)
	}else {
		qSort2(values, start, p-1,topK)
		qSort2(values, p+1, end,topK)
	}
	log.Println(values)
}
func paration2(values []uint64, start, end int) int {
	key := values[start]
	for start < end {
		for end > start && values[end] <= key {
			end--
		}
		values[start] = values[end]
		for start < end && values[start] >= key {
			start++
		}
		values[end] = values[start]
	}
	values[start] = key
	return start
}
