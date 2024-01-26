package http

// Thanks OpenAI :)

const MaxSeqNum = 1<<32 - 1

type Node struct {
	seqNum  uint32
	payload []byte
	next    *Node
	prev    *Node
}

type LinkedList struct {
	head     *Node
	tail     *Node
	totalLen int // Number of bytes
}

func NewLinkedList() *LinkedList {
	return &LinkedList{}
}

// InsertNode inserts a new Node in the linked list in the correct order based on sequence number.
func (ll *LinkedList) InsertNode(newNode *Node) {
	if ll.head == nil {
		// List is empty, so the new node becomes both head and tail.
		ll.head = newNode
		ll.tail = newNode
	} else if compareSeqNums(newNode.seqNum, ll.head.seqNum) <= 0 {
		// Insert before the head.
		newNode.next = ll.head
		ll.head.prev = newNode
		ll.head = newNode
	} else if compareSeqNums(newNode.seqNum, ll.tail.seqNum) >= 0 {
		// Insert after the tail.
		newNode.prev = ll.tail
		ll.tail.next = newNode
		ll.tail = newNode
	} else {
		// Insert somewhere in the middle; find the insertion point.
		insertAfter := ll.findInsertionPoint(newNode.seqNum)
		newNode.next = insertAfter.next
		newNode.prev = insertAfter

		if insertAfter.next != nil { // Check if insertAfter is not the tail
			insertAfter.next.prev = newNode
		}

		insertAfter.next = newNode
	}
	ll.totalLen += len(newNode.payload)
}

func (ll *LinkedList) ToBytes() []byte {
	if ll.head == nil {
		return nil
	}

	buffer := make([]byte, 0, ll.totalLen)
	current := ll.head
	for current != nil {
		buffer = append(buffer, current.payload...)
		current = current.next
	}
	return buffer
}

func (ll *LinkedList) findInsertionPoint(seqNum uint32) *Node {
	// Start searching from the tail of the list.
	current := ll.tail

	// Traverse the list in reverse until we find the insertion point.
	for current != nil {
		// Compare the sequence numbers to find where to insert the new node.
		if compareSeqNums(seqNum, current.seqNum) >= 0 {
			// We've found the insertion point: it's after the current node.
			return current
		}
		current = current.prev
	}

	return ll.head // Should not happen
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
