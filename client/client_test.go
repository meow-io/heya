package client

import (
	"context"
	crypto_rand "crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestMain(m *testing.M) {
	// to disable tls
	os.Setenv("SKIP_VERIFY", "1")
	code := m.Run()
	os.Exit(code)
}

type testServer struct {
	t            *testing.T
	listener     net.Listener
	client       net.Conn
	clientDigest [32]byte
	finished     sync.WaitGroup
}

func newTestServer(t *testing.T, port int, opening string) *testServer {
	require := require.New(t)
	var err error

	os.Remove("key.pem")
	os.Remove("cert.pem")

	key, err := rsa.GenerateKey(crypto_rand.Reader, 2048)
	require.Nil(err)
	keyOut, err := os.Create("key.pem")
	require.Nil(err)

	// Generate a pem block with the private key
	if err := pem.Encode(keyOut, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}); err != nil {
		require.Nil(err)
	}

	tml := x509.Certificate{
		// you can add any attr that you need
		NotBefore: time.Now(),
		NotAfter:  time.Now().AddDate(5, 0, 0),
		// you have to generate a different serial number each execution
		SerialNumber: big.NewInt(123123),
		Subject: pkix.Name{
			CommonName:   "localhost",
			Organization: []string{"New Org."},
		},
		DNSNames:              []string{"localhost"},
		BasicConstraintsValid: true,
	}
	cert, err := x509.CreateCertificate(crypto_rand.Reader, &tml, &tml, &key.PublicKey, key)
	require.Nil(err)

	// Generate a pem block with the certificate
	certOut, err := os.Create("cert.pem")
	require.Nil(err)
	if err := pem.Encode(certOut, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert,
	}); err != nil {
		require.Nil(err)
	}

	pemcert, err := tls.LoadX509KeyPair("cert.pem", "key.pem")
	require.Nil(err)
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{pemcert},
		ClientAuth:   tls.RequireAnyClientCert,
	}
	listener, err := tls.Listen("tcp", fmt.Sprintf(":%d", port), tlsConfig)
	require.Nil(err)

	ts := &testServer{
		t:        t,
		listener: listener,
	}

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				continue
			}
			tlscon := conn.(*tls.Conn)
			require.Nil(tlscon.Handshake())
			state := tlscon.ConnectionState()
			cert := state.PeerCertificates[0]
			clientDigest := sha256.Sum256(cert.Raw)

			if _, err := conn.Write([]byte(opening)); err != nil {
				require.Nil(err)
			}
			ts.client = conn
			ts.clientDigest = clientDigest
		}
	}()

	return ts
}

func (ts *testServer) stop() {
	ts.t.Logf("waiting")
	ts.finished.Wait()
	ts.t.Logf("done waiting")
	ts.listener.Close()
	ts.t.Logf("done Closing")
}

func (ts *testServer) expect(req, res string) {
	ts.finished.Add(1)
	require := require.New(ts.t)
	if ts.client == nil {
		require.Eventually(func() bool {
			return ts.client != nil
		}, 2*time.Second, 10*time.Millisecond)
	}

	reqBuf := make([]byte, len(req))
	ts.t.Logf("reading request %s", req)
	if _, err := io.ReadFull(ts.client, reqBuf); err != nil {
		require.Nil(err)
	}
	ts.t.Logf("done reading request %s, sending response %s", req, res)
	require.Equal(req, string(reqBuf))
	if _, err := ts.client.Write([]byte(res)); err != nil {
		require.Nil(err)
	}
	ts.t.Logf("done sending response %s", res)
	ts.finished.Done()
}

func (ts *testServer) send(res string) {
	require := require.New(ts.t)
	if ts.client == nil {
		require.Eventually(func() bool {
			return ts.client != nil
		}, 2*time.Second, 10*time.Millisecond)
	}

	if _, err := ts.client.Write([]byte(res)); err != nil {
		require.Nil(err)
	}
}

func TestSend(t *testing.T) {
	require := require.New(t)
	ts := newTestServer(t, 20202, "HEYA 0\nDONE\n")
	defer ts.stop()
	go ts.expect(
		"SEND 0123456701234567012345670123456701234567012345670123456701234567 3733cd977ff8eb18b987357e22ced99f46097f31ecb239e878ae63760e83e4d5 5\nHELLO\n",
		"RECV 3733cd977ff8eb18b987357e22ced99f46097f31ecb239e878ae63760e83e4d5\n",
	)

	c, err := NewClient(&Config{"localhost", 20202, false, false, nil, true, nil, nil})
	require.Nil(err)
	defer c.Close()
	ctx := context.Background()
	require.Nil(c.Connect(ctx))
	err = c.Send(context.Background(), []byte{0x01, 0x23, 0x45, 0x67, 0x01, 0x23, 0x45, 0x67, 0x01, 0x23, 0x45, 0x67, 0x01, 0x23, 0x45, 0x67, 0x01, 0x23, 0x45, 0x67, 0x01, 0x23, 0x45, 0x67, 0x01, 0x23, 0x45, 0x67, 0x01, 0x23, 0x45, 0x67}, []byte("HELLO"))
	require.Nil(err)
}

func TestPing(t *testing.T) {
	require := require.New(t)
	ts := newTestServer(t, 20202, "HEYA 0\nDONE\n")
	defer ts.stop()
	go ts.expect(
		"PING\n",
		"PONG\n",
	)
	c, err := NewClient(&Config{"localhost", 20202, false, false, nil, true, nil, nil})
	require.Nil(err)
	defer c.Close()
	ctx := context.Background()
	require.Nil(c.Connect(ctx))
	err = c.Ping(ctx)
	require.Nil(err)
}

func TestPinger(t *testing.T) {
	require := require.New(t)
	ts := newTestServer(t, 20202, "HEYA 0\nDONE\n")
	go ts.expect(
		"PING\n",
		"PONG\n",
	)
	c, err := NewClient(&Config{"localhost", 20202, false, true, nil, true, nil, nil})
	require.Nil(err)
	ctx := context.Background()
	require.Nil(c.Connect(ctx))
	time.Sleep(1 * time.Second)
	ts.stop()
	c.Close()
}

func TestPingTimeout(t *testing.T) {
	require := require.New(t)
	ts := newTestServer(t, 20202, "HEYA 0\nDONE\n")
	c, err := NewClient(&Config{"localhost", 20202, false, false, nil, true, nil, nil})
	require.Nil(err)
	defer c.Close()
	require.Nil(c.Connect(context.Background()))
	ts.stop()
	ctx, cancelFn := context.WithTimeout(context.Background(), time.Second)
	defer cancelFn()
	err = c.Ping(ctx)
	require.ErrorIs(err, context.DeadlineExceeded)
}

func TestGetHave(t *testing.T) {
	require := require.New(t)
	ts := newTestServer(t, 20202, "HEYA 0\nDONE\n")
	defer ts.stop()
	c, err := NewClient(&Config{"localhost", 20202, false, false, nil, true, nil, nil})
	require.Nil(err)
	defer c.Close()
	ctx := context.Background()
	require.Nil(c.Connect(ctx))
	ts.send("HAVE 0123456701234567012345670123456701234567012345670123456701234567 1\n")
	notification := <-c.Notifications()
	require.IsType(&DoneIntro{}, notification)
	notification = <-c.Notifications()
	require.Equal(uint64(1), notification.(*Notification).Seq)
	require.Equal([]byte{0x01, 0x23, 0x45, 0x67, 0x01, 0x23, 0x45, 0x67, 0x01, 0x23, 0x45, 0x67, 0x01, 0x23, 0x45, 0x67, 0x01, 0x23, 0x45, 0x67, 0x01, 0x23, 0x45, 0x67, 0x01, 0x23, 0x45, 0x67, 0x01, 0x23, 0x45, 0x67}, notification.(*Notification).Token)
}

func TestLastNotification(t *testing.T) {
	require := require.New(t)
	ts := newTestServer(t, 20202, "HEYA 0\nLAST 0123456701234567012345670123456701234567012345670123456701234567 12\nDONE\n")
	defer ts.stop()
	c, err := NewClient(&Config{"localhost", 20202, false, false, nil, true, nil, nil})
	require.Nil(err)
	defer c.Close()
	ctx := context.Background()
	require.Nil(c.Connect(ctx))
	notification := <-c.Notifications()
	require.Equal(uint64(12), notification.(*Notification).Seq)
	require.Equal([]byte{0x01, 0x23, 0x45, 0x67, 0x01, 0x23, 0x45, 0x67, 0x01, 0x23, 0x45, 0x67, 0x01, 0x23, 0x45, 0x67, 0x01, 0x23, 0x45, 0x67, 0x01, 0x23, 0x45, 0x67, 0x01, 0x23, 0x45, 0x67, 0x01, 0x23, 0x45, 0x67}, notification.(*Notification).Token)
	notification = <-c.Notifications()
	require.IsType(&DoneIntro{}, notification)
}

func TestRetainKeys(t *testing.T) {
	require := require.New(t)
	ts := newTestServer(t, 20202, "HEYA 0\nDONE\n")
	defer ts.stop()
	c1, err := NewClient(&Config{"localhost", 20202, false, false, nil, true, nil, nil})
	require.Nil(err)
	ctx := context.Background()
	require.Nil(c1.Connect(ctx))
	expectedDigest := ts.clientDigest
	c1.Close()
	c2, err := NewClientFromKey(&Config{"localhost", 20202, false, false, nil, true, c1.PrivateKeyPKCS1, c1.Certificate})
	require.Nil(err)
	require.Nil(c2.Connect(ctx))
	c2.Close()
	require.Equal(expectedDigest, ts.clientDigest)
}

func TestRegisterIncoming(t *testing.T) {
	require := require.New(t)
	ts := newTestServer(t, 20202, "HEYA 0\nDONE\n")
	defer ts.stop()
	go ts.expect(
		"INCO 0123456701234567012345670123456701234567012345670123456701234567\n",
		"INCO 0123456701234567012345670123456701234567012345670123456701234567\n",
	)
	c1, err := NewClient(&Config{"localhost", 20202, false, false, nil, true, nil, nil})
	require.Nil(err)
	ctx := context.Background()
	require.Nil(c1.Connect(ctx))
	_, err = c1.RegisterIncoming(ctx, "0123456701234567012345670123456701234567012345670123456701234567")
	require.Nil(err)
}

func TestAuthorize(t *testing.T) {
	require := require.New(t)
	ts := newTestServer(t, 20202, "HEYA 0\nDONE\n")
	defer ts.stop()
	go ts.expect(
		"AUTH 12345 56789\n",
		"AUTH 0123456701234567012345670123456701234567012345670123456701234567 12345 56789\n",
	)
	c1, err := NewClient(&Config{"localhost", 20202, false, false, nil, true, nil, nil})
	require.Nil(err)
	ctx := context.Background()
	require.Nil(c1.Connect(ctx))
	token, err := c1.MakeSendToken(ctx, time.Unix(12345, 0), time.Unix(56789, 0))
	require.Nil(err)
	require.Equal(token, []byte{0x01, 0x23, 0x45, 0x67, 0x01, 0x23, 0x45, 0x67, 0x01, 0x23, 0x45, 0x67, 0x01, 0x23, 0x45, 0x67, 0x01, 0x23, 0x45, 0x67, 0x01, 0x23, 0x45, 0x67, 0x01, 0x23, 0x45, 0x67, 0x01, 0x23, 0x45, 0x67})
}

func TestDeauthorize(t *testing.T) {
	require := require.New(t)
	ts := newTestServer(t, 20202, "HEYA 0\nDONE\n")
	defer ts.stop()
	go ts.expect(
		"DEAU 0123456701234567012345670123456701234567012345670123456701234567\n",
		"DEAU 0123456701234567012345670123456701234567012345670123456701234567\n",
	)
	c1, err := NewClient(&Config{"localhost", 20202, false, false, nil, true, nil, nil})
	require.Nil(err)
	ctx := context.Background()
	require.Nil(c1.Connect(ctx))
	require.Nil(c1.RevokeSendToken(ctx, []byte{0x01, 0x23, 0x45, 0x67, 0x01, 0x23, 0x45, 0x67, 0x01, 0x23, 0x45, 0x67, 0x01, 0x23, 0x45, 0x67, 0x01, 0x23, 0x45, 0x67, 0x01, 0x23, 0x45, 0x67, 0x01, 0x23, 0x45, 0x67, 0x01, 0x23, 0x45, 0x67}))
}

func TestExtendToken(t *testing.T) {
	require := require.New(t)
	ts := newTestServer(t, 20202, "HEYA 0\nDONE\n")
	defer ts.stop()
	go ts.expect(
		"EXTD 0123456701234567012345670123456701234567012345670123456701234567 100\n",
		"EXTD 0123456701234567012345670123456701234567012345670123456701234567 12445\n",
	)
	c1, err := NewClient(&Config{"localhost", 20202, false, false, nil, true, nil, nil})
	require.Nil(err)
	ctx := context.Background()
	require.Nil(c1.Connect(ctx))
	newEndTime, err := c1.ExtendSendToken(ctx, []byte{0x01, 0x23, 0x45, 0x67, 0x01, 0x23, 0x45, 0x67, 0x01, 0x23, 0x45, 0x67, 0x01, 0x23, 0x45, 0x67, 0x01, 0x23, 0x45, 0x67, 0x01, 0x23, 0x45, 0x67, 0x01, 0x23, 0x45, 0x67, 0x01, 0x23, 0x45, 0x67}, 100)
	require.Nil(err)
	require.Equal(time.Unix(12445, 0), newEndTime)
}

func TestListTokens(t *testing.T) {
	require := require.New(t)
	ts := newTestServer(t, 20202, "HEYA 0\nDONE\n")
	defer ts.stop()
	go ts.expect(
		"LIST\n",
		"LIST 3\n0123456701234567012345670123456701234567012345670123456701234567 2 0 0\n0123456701234567012345670123456701234567012345670123456701234568 3 1 1\n0123456701234567012345670123456701234567012345670123456701234569 4 2 2\n",
	)
	c1, err := NewClient(&Config{"localhost", 20202, false, false, nil, true, nil, nil})
	require.Nil(err)
	ctx := context.Background()
	require.Nil(c1.Connect(ctx))
	tokens, err := c1.ListTokens(ctx)
	require.Nil(err)
	require.Equal(3, len(tokens))

	require.Equal([]byte{0x01, 0x23, 0x45, 0x67, 0x01, 0x23, 0x45, 0x67, 0x01, 0x23, 0x45, 0x67, 0x01, 0x23, 0x45, 0x67, 0x01, 0x23, 0x45, 0x67, 0x01, 0x23, 0x45, 0x67, 0x01, 0x23, 0x45, 0x67, 0x01, 0x23, 0x45, 0x67}, tokens[0].Value)
	require.Equal(uint64(2), tokens[0].Seq)
	require.Equal(time.Unix(0, 0), tokens[0].StartTime)
	require.Equal(time.Unix(0, 0), tokens[0].EndTime)
	require.Equal(uint64(3), tokens[1].Seq)
	require.Equal(time.Unix(1, 0), tokens[1].StartTime)
	require.Equal(time.Unix(1, 0), tokens[1].EndTime)
	require.Equal(uint64(4), tokens[2].Seq)
	require.Equal(time.Unix(2, 0), tokens[2].StartTime)
	require.Equal(time.Unix(2, 0), tokens[2].EndTime)
}

func TestIOSListTokens(t *testing.T) {
	require := require.New(t)
	ts := newTestServer(t, 20202, "HEYA 0\nDONE\n")
	defer ts.stop()
	go ts.expect(
		"IOSL\n",
		"IOSL 3\n0123456701234567012345670123456701234567012345670123456701234567 0\n0123456701234567012345670123456701234567012345670123456701234568 1\n0123456701234567012345670123456701234567012345670123456701234569 2\n",
	)
	c1, err := NewClient(&Config{"localhost", 20202, false, false, nil, true, nil, nil})
	require.Nil(err)
	ctx := context.Background()
	require.Nil(c1.Connect(ctx))
	tokens, err := c1.ListIOSPushTokens(ctx)
	require.Nil(err)
	require.Equal(3, len(tokens))
}

func TestIOSAddToken(t *testing.T) {
	require := require.New(t)
	ts := newTestServer(t, 20202, "HEYA 0\nDONE\n")
	defer ts.stop()
	go ts.expect(
		"IOSA 0123456701234567012345670123456701234567012345670123456701234567\n",
		"IOSA 0123456701234567012345670123456701234567012345670123456701234567\n",
	)
	c1, err := NewClient(&Config{"localhost", 20202, false, false, nil, true, nil, nil})
	require.Nil(err)
	ctx := context.Background()
	require.Nil(c1.Connect(ctx))
	require.Nil(c1.AddIOSPushToken(ctx, "0123456701234567012345670123456701234567012345670123456701234567"))
}

func TestIOSDeleteToken(t *testing.T) {
	require := require.New(t)
	ts := newTestServer(t, 20202, "HEYA 0\nDONE\n")
	defer ts.stop()
	go ts.expect(
		"IOSD 0123456701234567012345670123456701234567012345670123456701234567\n",
		"IOSD 0123456701234567012345670123456701234567012345670123456701234567\n",
	)
	c1, err := NewClient(&Config{"localhost", 20202, false, false, nil, true, nil, nil})
	require.Nil(err)
	ctx := context.Background()
	require.Nil(c1.Connect(ctx))
	require.Nil(c1.DeleteIOSPushToken(ctx, "0123456701234567012345670123456701234567012345670123456701234567"))
}

func TestWantGiveMessage(t *testing.T) {
	require := require.New(t)
	ts := newTestServer(t, 20202, "HEYA 0\nDONE\n")
	defer ts.stop()
	go ts.expect(
		"WANT 0123456701234567012345670123456701234567012345670123456701234567 0\n",
		"GIVE 0123456701234567012345670123456701234567012345670123456701234567 0 5\nHELLO\n",
	)
	c1, err := NewClient(&Config{"localhost", 20202, false, false, nil, true, nil, nil})
	require.Nil(err)
	ctx := context.Background()
	require.Nil(c1.Connect(ctx))
	message, err := c1.Want(ctx, []byte{0x01, 0x23, 0x45, 0x67, 0x01, 0x23, 0x45, 0x67, 0x01, 0x23, 0x45, 0x67, 0x01, 0x23, 0x45, 0x67, 0x01, 0x23, 0x45, 0x67, 0x01, 0x23, 0x45, 0x67, 0x01, 0x23, 0x45, 0x67, 0x01, 0x23, 0x45, 0x67}, 0)
	require.Nil(err)
	require.Equal(uint64(0), message.Seq)
	require.Equal("HELLO", string(message.Body))
}

func TestTrimMessages(t *testing.T) {
	require := require.New(t)
	ts := newTestServer(t, 20202, "HEYA 0\nDONE\n")
	defer ts.stop()
	go ts.expect(
		"TRIM 0123456701234567012345670123456701234567012345670123456701234567 4\n",
		"TRIM 0123456701234567012345670123456701234567012345670123456701234567 4 12\n",
	)
	c1, err := NewClient(&Config{"localhost", 20202, false, false, nil, true, nil, nil})
	require.Nil(err)
	ctx := context.Background()
	require.Nil(c1.Connect(ctx))
	count, err := c1.Trim(ctx, []byte{0x01, 0x23, 0x45, 0x67, 0x01, 0x23, 0x45, 0x67, 0x01, 0x23, 0x45, 0x67, 0x01, 0x23, 0x45, 0x67, 0x01, 0x23, 0x45, 0x67, 0x01, 0x23, 0x45, 0x67, 0x01, 0x23, 0x45, 0x67, 0x01, 0x23, 0x45, 0x67}, 4)
	require.Nil(err)
	require.Equal(uint64(12), count)
}

func TestWantGoneMessage(t *testing.T) {
	require := require.New(t)
	ts := newTestServer(t, 20202, "HEYA 0\nDONE\n")
	defer ts.stop()
	go ts.expect(
		"WANT 0123456701234567012345670123456701234567012345670123456701234567 0\n",
		"GONE 0123456701234567012345670123456701234567012345670123456701234567 0\n",
	)
	c1, err := NewClient(&Config{"localhost", 20202, false, false, nil, true, nil, nil})
	require.Nil(err)
	ctx := context.Background()
	require.Nil(c1.Connect(ctx))
	message, err := c1.Want(ctx, []byte{0x01, 0x23, 0x45, 0x67, 0x01, 0x23, 0x45, 0x67, 0x01, 0x23, 0x45, 0x67, 0x01, 0x23, 0x45, 0x67, 0x01, 0x23, 0x45, 0x67, 0x01, 0x23, 0x45, 0x67, 0x01, 0x23, 0x45, 0x67, 0x01, 0x23, 0x45, 0x67}, 0)
	require.Nil(err)
	require.Nil(message)
}

func TestDeauthAll(t *testing.T) {
	require := require.New(t)
	ts := newTestServer(t, 20202, "HEYA 0\nDONE\n")
	defer ts.stop()
	go ts.expect(
		"DALL\n",
		"DALL\n",
	)
	c1, err := NewClient(&Config{"localhost", 20202, false, false, nil, true, nil, nil})
	require.Nil(err)
	ctx := context.Background()
	require.Nil(c1.Connect(ctx))
	require.Nil(c1.DeauthAll(ctx))
}
