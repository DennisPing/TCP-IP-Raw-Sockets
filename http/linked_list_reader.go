package http

import (
	"io"
)

// LinkedListReader implements Reader interface for streaming
type LinkedListReader struct {
	list    *LinkedList
	curr    *Node
	offset  int
	readLen int
}

func NewLinkedListReader(list *LinkedList) *LinkedListReader {
	return &LinkedListReader{
		list: list,
	}
}

func (r *LinkedListReader) Read(buf []byte) (n int, err error) {
	if r.curr == nil {
		r.curr = r.list.head // Start reading from the head
	}

	for n < len(buf) && r.curr != nil {
		nCopied := copy(buf[n:], r.curr.payload[r.offset:])
		n += nCopied
		r.offset += nCopied
		r.readLen += nCopied

		if r.offset == len(r.curr.payload) {
			r.curr = r.curr.next // Move onto the next node
			r.offset = 0
		}
	}

	if r.curr == nil {
		return n, io.EOF // No more data to read
	}

	return n, nil
}
