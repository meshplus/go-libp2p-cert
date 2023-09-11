package go_libp2p_cert

import (
	"context"
	"github.com/libp2p/go-libp2p/core/protocol"
	"net"

	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/sec"
)

// ID is the protocol ID for cert
const ID = "/cert"

var _ sec.SecureTransport = &Transport{}

// Transport implements the interface sec.SecureTransport
// https://godoc.org/github.com/libp2p/go-libp2p/core/sec#SecureConn
type Transport struct {
	transportID protocol.ID
	localID     peer.ID
	privateKey  crypto.PrivKey
	certs       *Certs
}

// New creates a new Noise transport using the given private key as its
// libp2p identity key.
func New(id protocol.ID, privkey crypto.PrivKey, certs *Certs) (*Transport, error) {
	if id == "" {
		id = ID
	}
	localID, err := peer.IDFromPrivateKey(privkey)
	if err != nil {
		return nil, err
	}

	return &Transport{
		transportID: id,
		localID:     localID,
		privateKey:  privkey,
		certs:       certs,
	}, nil
}

// SecureInbound runs the Noise handshake as the responder.
func (t *Transport) SecureInbound(ctx context.Context, insecure net.Conn, remote peer.ID) (sec.SecureConn, error) {
	return newSecureSession(t, ctx, insecure, remote, false)
}

// SecureOutbound runs the Noise handshake as the initiator.
func (t *Transport) SecureOutbound(ctx context.Context, insecure net.Conn, p peer.ID) (sec.SecureConn, error) {
	return newSecureSession(t, ctx, insecure, p, true)
}

func (t *Transport) ID() protocol.ID {
	return t.transportID
}
