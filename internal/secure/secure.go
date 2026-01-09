package secure

import (
	"bytes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

// DeriveKey generates a 32-byte key from the provided secret using SHA-256.
func DeriveKey(secret string) []byte {
	sum := sha256.Sum256([]byte(secret))
	return sum[:]
}

// EncryptBytes encrypts the given plaintext with a random nonce and returns nonce||ciphertext.
func EncryptBytes(plaintext, key []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	cipherText := aead.Seal(nil, nonce, plaintext, nil)
	out := make([]byte, len(nonce)+len(cipherText))
	copy(out, nonce)
	copy(out[len(nonce):], cipherText)
	return out, nil
}

// DecryptBytes expects input in the format nonce||ciphertext and returns the plaintext.
func DecryptBytes(data, key []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	nonceSize := aead.NonceSize()
	if len(data) < nonceSize {
		return nil, fmt.Errorf("encrypted payload too short")
	}
	nonce := data[:nonceSize]
	cipherText := data[nonceSize:]
	return aead.Open(nil, nonce, cipherText, nil)
}

// secureConn wraps a net.Conn and transparently encrypts all traffic using AEAD frames.
type secureConn struct {
	conn     net.Conn
	aead     cipher.AEAD
	readBuf  bytes.Buffer
	writeBuf [4]byte
	maxChunk int
}

const maxFramePayload = 32 * 1024 // keep frames small to avoid head-of-line blocking

// WrapConn creates an encrypted connection wrapper.
func WrapConn(c net.Conn, key []byte) (net.Conn, error) {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	return &secureConn{conn: c, aead: aead, maxChunk: maxFramePayload}, nil
}

func (s *secureConn) Read(p []byte) (int, error) {
	// Serve from buffered plaintext if available.
	if s.readBuf.Len() > 0 {
		return s.readBuf.Read(p)
	}

	// Otherwise, read the next encrypted frame.
	if err := s.readFrame(); err != nil {
		return 0, err
	}
	return s.readBuf.Read(p)
}

func (s *secureConn) readFrame() error {
	// Frame format: [4-byte length][nonce][ciphertext]
	// length excludes the 4-byte header.
	header := s.writeBuf[:]
	if _, err := io.ReadFull(s.conn, header); err != nil {
		return err
	}
	frameLen := binary.BigEndian.Uint32(header)
	nonceSize := s.aead.NonceSize()
	if frameLen < uint32(nonceSize) {
		return fmt.Errorf("invalid frame length: %d", frameLen)
	}
	buf := make([]byte, frameLen)
	if _, err := io.ReadFull(s.conn, buf); err != nil {
		return err
	}
	nonce := buf[:nonceSize]
	cipherText := buf[nonceSize:]
	plain, err := s.aead.Open(nil, nonce, cipherText, nil)
	if err != nil {
		return err
	}
	s.readBuf.Write(plain)
	return nil
}

func (s *secureConn) Write(p []byte) (int, error) {
	written := 0
	for len(p) > 0 {
		chunkSize := len(p)
		if chunkSize > s.maxChunk {
			chunkSize = s.maxChunk
		}
		chunk := p[:chunkSize]
		p = p[chunkSize:]

		if err := s.writeFrame(chunk); err != nil {
			return written, err
		}
		written += chunkSize
	}
	return written, nil
}

func (s *secureConn) writeFrame(plain []byte) error {
	nonce := make([]byte, s.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	cipherText := s.aead.Seal(nil, nonce, plain, nil)

	frameLen := len(nonce) + len(cipherText)
	binary.BigEndian.PutUint32(s.writeBuf[:], uint32(frameLen))

	if _, err := s.conn.Write(s.writeBuf[:]); err != nil {
		return err
	}
	if _, err := s.conn.Write(nonce); err != nil {
		return err
	}
	_, err := s.conn.Write(cipherText)
	return err
}

func (s *secureConn) Close() error { return s.conn.Close() }

func (s *secureConn) LocalAddr() net.Addr { return s.conn.LocalAddr() }

func (s *secureConn) RemoteAddr() net.Addr { return s.conn.RemoteAddr() }

func (s *secureConn) SetDeadline(t time.Time) error { return s.conn.SetDeadline(t) }

func (s *secureConn) SetReadDeadline(t time.Time) error { return s.conn.SetReadDeadline(t) }

func (s *secureConn) SetWriteDeadline(t time.Time) error { return s.conn.SetWriteDeadline(t) }
