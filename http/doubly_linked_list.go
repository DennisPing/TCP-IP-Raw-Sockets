package http

// Thanks OpenAI :)

type Node struct {
	seqNum  uint32
	payload []byte
	next    *Node
	prev    *Node
}

type DoublyLinkedList struct {
	head     *Node
	tail     *Node
	totalLen int // Number of bytes
}

func NewDoublyLinkedList() *DoublyLinkedList {
	return &DoublyLinkedList{}
}

func (dll *DoublyLinkedList) InsertNode(newNode *Node) {
	if dll.head == nil {
		// List is empty, so the new node becomes both head and tail.
		dll.head = newNode
		dll.tail = newNode
	} else if newNode.seqNum <= dll.head.seqNum {
		// Insert before the head.
		newNode.next = dll.head
		dll.head.prev = newNode
		dll.head = newNode
	} else if newNode.seqNum >= dll.tail.seqNum {
		// Insert after the tail.
		newNode.prev = dll.tail
		dll.tail.next = newNode
		dll.tail = newNode
	} else {
		// Insert somewhere in the middle; find the insertion point.
		insertAfter := dll.findInsertionPoint(newNode.seqNum)
		newNode.next = insertAfter.next
		newNode.prev = insertAfter

		if insertAfter.next != nil { // Check if insertAfter is not the tail
			insertAfter.next.prev = newNode
		} else {
			dll.tail = newNode // Update tail if the new node is at the end
		}

		insertAfter.next = newNode
	}
	dll.totalLen += len(newNode.payload)
}

func (dll *DoublyLinkedList) ToBytes() []byte {
	if dll.head == nil {
		return nil
	}

	buffer := make([]byte, 0, dll.totalLen)
	current := dll.head
	for current != nil {
		buffer = append(buffer, current.payload...)
		current = current.next
	}
	return buffer
}

func (dll *DoublyLinkedList) findInsertionPoint(seqNum uint32) *Node {
	var current *Node
	if seqNum-dll.head.seqNum <= dll.tail.seqNum-seqNum {
		// Start from the head.
		current = dll.head
		for current != nil && current.seqNum < seqNum {
			current = current.next
		}
	} else {
		// Start from the tail.
		current = dll.tail
		for current != nil && current.seqNum > seqNum {
			current = current.prev
		}
	}
	// Return the node after which the new node should be inserted.
	return current.prev
}
