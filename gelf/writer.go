// Copyright 2012 SocialCode. All rights reserved.
// Use of this source code is governed by the MIT
// license that can be found in the LICENSE file.

package gelf

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net"
)

type WriterInterface interface {
	Close() error
	Write([]byte) (int, error)
	WriteMessage(*Message) error
}

// Writer implements io.Writer and is used to send both discrete
// messages to a graylog2 server, or data from a stream-oriented
// interface (like the functions in log).
type Writer struct {
	addr     string
	conn     net.Conn
	hostname string
	Facility string // defaults to current process name
	proto    string
}

// writes the gzip compressed byte array to the connection as a series
// of GELF chunked messages.  The format is documented at
// http://docs.graylog.org/en/2.1/pages/gelf.html as:
//
//     2-byte magic (0x1e 0x0f), 8 byte id, 1 byte sequence id, 1 byte
//     total, chunk-data
func (w *Writer) writeChunked(zBytes []byte) (err error) {
	b := make([]byte, 0, ChunkSize)
	buf := bytes.NewBuffer(b)
	nChunksI := numChunks(zBytes)
	if nChunksI > 128 {
		return fmt.Errorf("msg too large, would need %d chunks", nChunksI)
	}
	nChunks := uint8(nChunksI)
	// use urandom to get a unique message id
	msgId := make([]byte, 8)
	n, err := io.ReadFull(rand.Reader, msgId)
	if err != nil || n != 8 {
		return fmt.Errorf("rand.Reader: %d/%s", n, err)
	}

	bytesLeft := len(zBytes)
	for i := uint8(0); i < nChunks; i++ {
		buf.Reset()
		// manually write header.  Don't care about
		// host/network byte order, because the spec only
		// deals in individual bytes.
		buf.Write(magicChunked) //magic
		buf.Write(msgId)
		buf.WriteByte(i)
		buf.WriteByte(nChunks)
		// slice out our chunk from zBytes
		chunkLen := chunkedDataLen
		if chunkLen > bytesLeft {
			chunkLen = bytesLeft
		}
		off := int(i) * chunkedDataLen
		chunk := zBytes[off : off+chunkLen]
		buf.Write(chunk)

		// write this chunk, and make sure the write was good
		n, err := w.conn.Write(buf.Bytes())
		if err != nil {
			return fmt.Errorf("Write (chunk %d/%d): %s", i,
				nChunks, err)
		}
		if n != len(buf.Bytes()) {
			return fmt.Errorf("Write len: (chunk %d/%d) (%d/%d)",
				i, nChunks, n, len(buf.Bytes()))
		}

		bytesLeft -= chunkLen
	}

	if bytesLeft != 0 {
		return fmt.Errorf("error: %d bytes left after sending", bytesLeft)
	}
	return nil
}

// Close connection and interrupt blocked Read or Write operations
func (w *Writer) Close() error {
	if w.conn == nil {
		return nil
	}
	return w.conn.Close()
}

func ToByte(in interface{}) []byte {
	o, _ := json.Marshal(in)
	return o
}

func ToMap(in interface{}) (out map[string]interface{}) {
	o, _ := json.Marshal(in)
	json.Unmarshal(o, &out)
	return
}

func ByteToMap(in []byte) (out map[string]interface{}) {
	json.Unmarshal(in, &out)
	return
}
