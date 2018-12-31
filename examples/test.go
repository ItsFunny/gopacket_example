package main

func main() {
}

func buildHeap(values []uint64) {
	for i := 0; i < len(values); i++ {

	}

}
func doBuildMaxHeap(values []uint64, start, limit int) {
	getLeftChildIndex := func(i int) int {
		return ((i + 1) << 1) - 1
	}
	getRightChildIndex := func(i int) int {
		return (i + 1) << 1
	}
	leftChildIndex, rightChildIndex, maxIndex := getLeftChildIndex(start), getRightChildIndex(start), start
	if leftChildIndex < limit && values[leftChildIndex] > values[maxIndex] {
		maxIndex = leftChildIndex
	}
	if rightChildIndex < limit && values[rightChildIndex] > values[rightChildIndex] {
		maxIndex = rightChildIndex
	}
	if maxIndex == start {
		return
	}
	values[start], values[maxIndex] = values[maxIndex], values[start]
	doBuildMaxHeap(values, maxIndex, limit)

}
func mergeSort2(values []uint64) {
	for i := 0; i < len(values); i++ {
		values[0], values[i] = values[i], values[0]
		doBuildMaxHeap(values, 0, i)
	}
}
