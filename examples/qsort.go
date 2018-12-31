package main

func main() {
	values := []uint64{3, 4, 123, 1, 2, 6123, 24, 0}
	qSort(values, 0, len(values)-1)

}
func qSort(values []uint64, start, end int) {
	if start >= end {
		return
	}
	p := paration(values, start, end)
	qSort(values, start, p-1)
	qSort(values, p+1, end)
}
func paration(values []uint64, start, end int) int {
	key := values[start]
	for start < end {
		for end > start && values[end] >= key {
			end--
		}
		values[start] = values[end]
		for start < end && values[start] <= key {
			start++
		}
		values[end] = values[start]
	}
	values[start] = key
	return start
}
