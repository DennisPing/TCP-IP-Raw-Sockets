package main

type Queue []interface{}

func (q *Queue) IsEmpty() bool {
	return len(*q) == 0
}

func (q *Queue) Enqueue(item interface{}) {
	*q = append(*q, item)
}

func (q *Queue) Dequeue() interface{} {
	item := (*q)[0]
	*q = (*q)[1:]
	return item
}
