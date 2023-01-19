package go_libp2p_cert

import (
	"io/ioutil"
	"testing"

	crypto2 "github.com/meshplus/bitxhub-kit/crypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParsePrivateKey(t *testing.T) {
	data, err := ioutil.ReadFile("certs/ca.priv")
	assert.Nil(t, err)
	privKey, err := ParsePrivateKey(data, crypto2.ECDSA_P256)
	assert.Nil(t, err)
	assert.NotNil(t, privKey)
}

func TestVerifySign(t *testing.T) {
	data, err := ioutil.ReadFile("certs/ca.cert")
	require.Nil(t, err)
	caCert, err := ParseCert(data)
	require.Nil(t, err)

	subData, err := ioutil.ReadFile("certs/agency.cert")
	require.Nil(t, err)
	subCert, err := ParseCert(subData)
	require.Nil(t, err)
	err = VerifySign(subCert, caCert)
	require.Nil(t, err)

	nodeData, err := ioutil.ReadFile("certs/node.cert")
	require.Nil(t, err)
	nodeCert, err := ParseCert(nodeData)
	require.Nil(t, err)
	err = VerifySign(nodeCert, subCert)
	require.Nil(t, err)
}
