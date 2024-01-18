package http

// Thanks OpenAI :)

const MaxSeqNum = 1<<32 - 1

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

// InsertNode inserts a new Node in the linked list in the correct order based on sequence number.
func (dll *DoublyLinkedList) InsertNode(newNode *Node) {
	if dll.head == nil {
		// List is empty, so the new node becomes both head and tail.
		dll.head = newNode
		dll.tail = newNode
	} else if compareSeqNums(newNode.seqNum, dll.head.seqNum) <= 0 {
		// Insert before the head.
		newNode.next = dll.head
		dll.head.prev = newNode
		dll.head = newNode
	} else if compareSeqNums(newNode.seqNum, dll.tail.seqNum) >= 0 {
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
	// Start searching from the tail of the list.
	current := dll.tail

	// Traverse the list in reverse until we find the insertion point.
	for current != nil {
		// Compare the sequence numbers to find where to insert the new node.
		if compareSeqNums(seqNum, current.seqNum) >= 0 {
			// We've found the insertion point: it's after the current node.
			return current
		}
		current = current.prev
	}

	return dll.head // Should not happen
}

// compareSeqNums returns a negative number if seqNum1 is "less than" seqNum2,
// zero if they are "equal", and a positive number if seqNum1 is "greater than" seqNum2,
// taking into account potential wraparound.
func compareSeqNums(seqNum1, seqNum2 uint32) int {
	diff := int64(seqNum1) - int64(seqNum2)
	if diff < -int64(MaxSeqNum/2) {
		diff += int64(MaxSeqNum)
	} else if diff > int64(MaxSeqNum/2) {
		diff -= int64(MaxSeqNum)
	}
	return int(diff)
}
