// Copyright 2012 SocialCode. All rights reserved.
// Use of this source code is governed by the MIT
// license that can be found in the LICENSE file.

package gelf

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"fmt"
	"io"
	"net"
	"os"
	"path"
	"sync"
)

type UDPWriter struct {
	Writer
	CompressionLevel int // one of the consts from compress/flate
	CompressionType  CompressType
}

// What compression type the writer should use when sending messages
// to the graylog2 server
type CompressType int

const (
	CompressGzip CompressType = iota
	CompressZlib
	CompressNone
)

// Used to control GELF chunking.  Should be less than (MTU - len(UDP
// header)).
//
// TODO: generate dynamically using Path MTU Discovery?
const (
	ChunkSize        = 1420
	chunkedHeaderLen = 12
	chunkedDataLen   = ChunkSize - chunkedHeaderLen
)

var (
	magicChunked = []byte{0x1e, 0x0f}
	magicZlib    = []byte{0x78}
	magicGzip    = []byte{0x1f, 0x8b}
)

// numChunks returns the number of GELF chunks necessary to transmit
// the given compressed buffer.
func numChunks(b []byte) int {
	lenB := len(b)
	if lenB <= ChunkSize {
		return 1
	}
	return len(b)/chunkedDataLen + 1
}

// New returns a new GELF Writer.  This writer can be used to send the
// output of the standard Go log functions to a central GELF server by
// passing it to log.SetOutput()
func NewUDPWriter(addr string) (*UDPWriter, error) {
	var err error
	w := new(UDPWriter)
	w.CompressionLevel = flate.BestSpeed

	if w.conn, err = net.Dial("udp", addr); err != nil {
		return nil, err
	}
	if w.hostname, err = os.Hostname(); err != nil {
		return nil, err
	}

	w.Facility = path.Base(os.Args[0])

	return w, nil
}

// 1k bytes buffer by default
var bufPool = sync.Pool{
	New: func() interface{} {
		return bytes.NewBuffer(make([]byte, 0, 1024))
	},
}

func newBuffer() *bytes.Buffer {
	b := bufPool.Get().(*bytes.Buffer)
	if b != nil {
		b.Reset()
		return b
	}
	return bytes.NewBuffer(nil)
}

// WriteMessage sends the specified message to the GELF server
// specified in the call to New().  It assumes all the fields are
// filled out appropriately.  In general, clients will want to use
// Write, rather than WriteMessage.
func (w *UDPWriter) WriteMessage(m *Message) (err error) {
	mBuf := newBuffer()
	defer bufPool.Put(mBuf)
	if err = m.MarshalJSONBuf(mBuf); err != nil {
		return err
	}
	mBytes := mBuf.Bytes()

	var (
		zBuf   *bytes.Buffer
		zBytes []byte
	)

	var zw io.WriteCloser
	switch w.CompressionType {
	case CompressGzip:
		zBuf = newBuffer()
		defer bufPool.Put(zBuf)
		zw, err = gzip.NewWriterLevel(zBuf, w.CompressionLevel)
	case CompressZlib:
		zBuf = newBuffer()
		defer bufPool.Put(zBuf)
		zw, err = zlib.NewWriterLevel(zBuf, w.CompressionLevel)
	case CompressNone:
		zBytes = mBytes
	default:
		panic(fmt.Sprintf("unknown compression type %d",
			w.CompressionType))
	}
	if zw != nil {
		if err != nil {
			return
		}
		if _, err = zw.Write(mBytes); err != nil {
			zw.Close()
			return
		}
		zw.Close()
		zBytes = zBuf.Bytes()
	}

	if numChunks(zBytes) > 1 {
		return w.writeChunked(zBytes)
	}
	n, err := w.conn.Write(zBytes)
	if err != nil {
		return
	}
	if n != len(zBytes) {
		return fmt.Errorf("bad write (%d/%d)", n, len(zBytes))
	}

	return nil
}

// Write encodes the given string in a GELF message and sends it to
// the server specified in New().
func (w *UDPWriter) Write(p []byte) (n int, err error) {
	// 1 for the function that called us.
	file, line := getCallerIgnoringLogMulti(1)

	m := constructMessage(p, w.hostname, w.Facility, file, line)
	if err = w.WriteMessage(m); err != nil {
		return 0, err
	}

	return len(p), nil
}
