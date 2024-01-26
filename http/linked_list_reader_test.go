package http

import (
	"bytes"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestReadLinkedList(t *testing.T) {
	tests := []struct {
		name       string
		dataChunks []string
		body       string
	}{
		{
			name: "OrderedRead",
			dataChunks: []string{
				"Hello world! ",
				"I'm a little teapot. ",
				"Short and stout.",
			},
			body: "Hello world! I'm a little teapot. Short and stout.",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Build the linked list
			ll := NewLinkedList()

			for i, chunk := range tt.dataChunks {
				node := &Node{seqNum: uint32(i), payload: []byte(chunk)}
				ll.InsertNode(node)
			}

			reader := NewLinkedListReader(ll)
			var buffer bytes.Buffer
			_, err := io.Copy(&buffer, reader)
			assert.Nil(t, err)

			output := buffer.Bytes()
			assert.Equal(t, tt.body, string(output))
		})
	}
}
