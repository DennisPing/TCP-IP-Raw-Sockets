package http

import (
	"math"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestInsertNode(t *testing.T) {
	tests := []struct {
		name          string
		insertSeqNums []uint32 // Sequence numbers to insert in the given order
		sortedSeqNums []uint32
	}{
		{
			name:          "OrderedInsertion",
			insertSeqNums: []uint32{1, 2, 3},
			sortedSeqNums: []uint32{1, 2, 3},
		},
		{
			name:          "UnorderedInsertion",
			insertSeqNums: []uint32{1, 2, 5, 3, 4},
			sortedSeqNums: []uint32{1, 2, 3, 4, 5},
		},
		{
			name:          "UnorderedInsertionHead",
			insertSeqNums: []uint32{3, 4, 5, 1, 2},
			sortedSeqNums: []uint32{1, 2, 3, 4, 5},
		},
		{
			name:          "WrapAroundInsertion",
			insertSeqNums: []uint32{math.MaxUint32 - 1, math.MaxUint32, 0, 1, 2},
			sortedSeqNums: []uint32{math.MaxUint32 - 1, math.MaxUint32, 0, 1, 2},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ll := NewLinkedList()

			// Create nodes and add them to a slice for insertion.
			nodes := make(map[uint32]*Node)
			for _, seqNum := range tt.insertSeqNums {
				nodes[seqNum] = &Node{seqNum: seqNum, payload: []byte("node" + strconv.Itoa(int(seqNum)))}
			}

			// Insert nodes into the doubly linked list.
			for _, seqNum := range tt.insertSeqNums {
				ll.InsertNode(nodes[seqNum])
			}

			// Verify the order and connections of the nodes in the list by iterating from head to tail.
			current := ll.head
			expectedTotalLen := 0
			for i, expectedSeqNum := range tt.sortedSeqNums {
				expectedNode := nodes[expectedSeqNum]
				assert.Equal(t, expectedNode, current)
				if i > 0 { // For nodes after the first one, check the prev pointer.
					assert.Equal(t, nodes[tt.sortedSeqNums[i-1]], current.prev)
				} else {
					assert.Nil(t, current.prev) // The first node's prev should be nil.
				}
				expectedTotalLen += len(expectedNode.payload)
				current = current.next
			}
			assert.Nil(t, current)                                                     // After the last node, current should be nil.
			assert.Equal(t, nodes[tt.sortedSeqNums[len(tt.sortedSeqNums)-1]], ll.tail) // The last node should be the tail.

			// Verify the total length of the payloads in the list.
			assert.Equal(t, expectedTotalLen, ll.totalLen)

			// Verify the combined payload using ToBytes.
			var expectedBytes []byte
			for _, seqNum := range tt.sortedSeqNums {
				expectedBytes = append(expectedBytes, nodes[seqNum].payload...)
			}
			actualBytes := ll.ToBytes()
			assert.Equal(t, expectedBytes, actualBytes)
		})
	}
}
