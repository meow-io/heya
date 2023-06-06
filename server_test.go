package heya

import (
	crypto_rand "crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
	"os"
	"testing"
	"time"

	"github.com/jmoiron/sqlx"
	"github.com/stretchr/testify/require"
)

func getEnv(key, fallback string) string {
	value, exists := os.LookupEnv(key)
	if !exists {
		value = fallback
	}
	return value
}

type testPush struct {
	token string
}

type testPusher struct {
	testPushes []*testPush
}

func (tp *testPusher) DoPush(token string) error {
	tp.testPushes = append(tp.testPushes, &testPush{token})
	return nil
}

type testServer struct {
	pusher *testPusher
	server *Server
}

var ts *testServer
var token []byte
var postgresURL = getEnv("POSTGRES_URL", "pg://heya_development:heya@localhost:5432/heya_development?sslmode=disable")

func newServer(port int) (*testServer, error) {
	os.Remove("key.pem")
	os.Remove("cert.pem")

	key, err := rsa.GenerateKey(crypto_rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	keyOut, err := os.Create("key.pem")
	if err != nil {
		return nil, err
	}

	// Generate a pem block with the private key
	if err := pem.Encode(keyOut, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}); err != nil {
		return nil, err
	}

	tml := x509.Certificate{
		// you can add any attr that you need
		NotBefore: time.Now(),
		NotAfter:  time.Now().AddDate(5, 0, 0),
		// you have to generate a different serial number each execution
		SerialNumber: big.NewInt(123123),
		Subject: pkix.Name{
			CommonName:   "New Name",
			Organization: []string{"New Org."},
		},
		BasicConstraintsValid: true,
	}
	cert, err := x509.CreateCertificate(crypto_rand.Reader, &tml, &tml, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}

	// Generate a pem block with the certificate
	certOut, err := os.Create("cert.pem")
	if err != nil {
		return nil, err
	}
	if err := pem.Encode(certOut, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert,
	}); err != nil {
		return nil, err
	}

	c := &Config{
		Port:         port,
		APNSCertPath: "",
		TLSCertPath:  "cert.pem",
		TLSKeyPath:   "key.pem",
		DatabaseURL:  postgresURL,
		RedisURL:     getEnv("REDIS_URL", "redis://localhost:6379"),
		Debug:        true,
		LogPath:      "out.log",
	}

	testPushes := make([]*testPush, 0)
	l := newLogger(c)

	p := &testPusher{testPushes}
	s, err := NewServerWithPusher(c, l, p)
	if err != nil {
		return nil, err
	}
	return &testServer{p, s}, nil
}

type client struct {
	t         *testing.T
	conn      *tls.Conn
	digest    [32]byte
	tlsConfig *tls.Config
	port      int
}

func newClient(t *testing.T, port int) *client {
	require := require.New(t)
	priv, err := rsa.GenerateKey(crypto_rand.Reader, 2048)
	if err != nil {
		require.Nil(err)
		return nil
	}

	publicBytesDigest := sha256.Sum256(priv.Public().(*rsa.PublicKey).N.Bytes())
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(now.Unix()),
		NotBefore:             now,
		NotAfter:              now.AddDate(10, 0, 0), // Valid for one day
		SubjectKeyId:          publicBytesDigest[:],
		BasicConstraintsValid: true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		KeyUsage: x509.KeyUsageKeyEncipherment |
			x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
	}

	cert, err := x509.CreateCertificate(crypto_rand.Reader, template, template, priv.Public(), priv)
	if err != nil {
		require.Nil(err)
		return nil
	}
	publicDigest := sha256.Sum256(cert)

	privBytes := x509.MarshalPKCS1PrivateKey(priv)

	publicCert, err := x509.ParseCertificate(cert)
	if err != nil {
		require.Nil(err)
		return nil
	}
	privateKey, err := x509.ParsePKCS1PrivateKey(privBytes)
	if err != nil {
		require.Nil(err)
		return nil
	}
	var outCert tls.Certificate
	outCert.Certificate = append(outCert.Certificate, publicCert.Raw)
	outCert.PrivateKey = privateKey

	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
		Certificates:       []tls.Certificate{outCert},
	}

	return &client{t, nil, publicDigest, tlsConfig, port}
}

func (c *client) dial() {
	c.t.Logf("dialing")
	require := require.New(c.t)
	if c.conn != nil {
		c.t.Error("already a client there")
	}

	conn, err := tls.Dial("tcp", fmt.Sprintf("localhost:%d", c.port), c.tlsConfig)
	require.Nil(err)
	c.conn = conn
}

func (c *client) quit() {
	c.send("QUIT\n")
	c.conn = nil
}

func (c *client) send(tmpl string, args ...interface{}) {
	msg := fmt.Sprintf(tmpl, args...)
	c.t.Logf("sending %s", msg)
	require := require.New(c.t)
	if _, err := c.conn.Write([]byte(msg)); err != nil {
		require.Nil(err)
	}
}

func (c *client) recv(tmpl string, args ...interface{}) {
	msg := fmt.Sprintf(tmpl, args...)
	c.t.Logf("recving %s", msg)
	require := require.New(c.t)
	response := make([]byte, len(msg))
	if _, err := io.ReadFull(c.conn, response); err != nil {
		require.Nil(err)
	}
	require.Equal(msg, string(response))
}

func (c *client) recvStr(l int) (string, error) {
	response := make([]byte, l)
	if _, err := io.ReadFull(c.conn, response); err != nil {
		return "", err
	}
	return string(response), nil
}

func TestMain(m *testing.M) {
	if os.Getenv("RECREATE_DATABASE") != "" {
		conn, err := sql.Open("postgres", postgresURL)
		if err != nil {
			log.Fatal("cannot connect to db:", err)
		}

		db := sqlx.NewDb(conn, "postgres")

		db.MustExec("drop database heya_development")
		db.MustExec("create database heya_development")
		db.MustExec("GRANT ALL PRIVILEGES ON DATABASE \"heya_development\" to heya_development;")
	}

	os.Exit(m.Run())
}

func setup(t *testing.T) {
	require := require.New(t)
	var err error
	ts, err = newServer(10123)
	require.Nil(err)
	err = ts.server.Start()
	require.Nil(err)

	tokenBytes := make([]byte, 32)
	if _, err := crypto_rand.Read(tokenBytes); err != nil {
		require.Nil(err)
	}
	token = tokenBytes[:]
}

func teardown(_ *testing.T) {
	ts.server.Stop()
}

func TestSendWithPush(t *testing.T) {
	require := require.New(t)
	setup(t)
	defer teardown(t)

	require.Nil(ts.server.AddInboxToken(token))
	recvc := newClient(t, 10123)
	recvc.dial()
	recvc.recv("HEYA 0\n")
	recvc.recv("DONE\n")
	recvc.send(fmt.Sprintf("INCO %x\n", token))
	recvc.recv(fmt.Sprintf("INCO %x\n", token))
	recvc.send("AUTH 0 2220385707\n")
	recvc.recv("AUTH ")
	sendToken, err := recvc.recvStr(64)
	require.Nil(err)
	recvc.recv(" 0 2220385707\n")
	sendc := newClient(t, 10123)
	sendc.dial()
	sendc.recv("HEYA 0\n")
	sendc.recv("DONE\n")
	sendc.send("SEND %s 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824 5\nhello\n", sendToken)
	sendc.recv("RECV 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824\n")
	sendc.quit()
	t.Logf("have...")
	recvc.recv("HAVE %s 1\n", sendToken)
	t.Logf("done have...")
	recvc.send("WANT %s 0\n", sendToken)
	recvc.recv("GIVE %s 0 5\nhello\n", sendToken)
	recvc.quit()

}

func TestWantGone(t *testing.T) {
	require := require.New(t)
	setup(t)
	defer teardown(t)
	require.Nil(ts.server.AddInboxToken(token))

	recvc := newClient(t, 10123)

	recvc.dial()
	recvc.recv("HEYA 0\n")
	recvc.recv("DONE\n")
	recvc.send("INCO %x\n", token)
	recvc.recv("INCO %x\n", token)
	recvc.send("WANT %x 0\n", token)
	recvc.recv("GONE %x 0\n", token)
	recvc.quit()
}

func TestPushNotification(t *testing.T) {
	require := require.New(t)
	setup(t)
	defer teardown(t)

	require.Nil(ts.server.AddInboxToken(token))

	recvc := newClient(t, 10123)

	recvc.dial()
	recvc.recv("HEYA 0\n")
	recvc.recv("DONE\n")
	recvc.send(fmt.Sprintf("INCO %x\n", token))
	recvc.recv(fmt.Sprintf("INCO %x\n", token))
	recvc.send("IOSA 1234567812345678123456781234567812345678123456781234567812345678\n")
	recvc.recv("IOSA 1234567812345678123456781234567812345678123456781234567812345678\n")
	recvc.send("AUTH 0 2220385707\n")
	recvc.recv("AUTH ")
	sendToken, err := recvc.recvStr(64)
	require.Nil(err)
	recvc.recv(" 0 2220385707\n")
	recvc.quit()

	sendc := newClient(t, 10123)

	sendc.dial()
	sendc.recv("HEYA 0\n")
	sendc.recv("DONE\n")
	sendc.send("SEND " + sendToken + " 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824 5\nhello\n")
	sendc.recv("RECV 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824\n")
	sendc.quit()

	require.Eventually(func() bool {
		return len(ts.pusher.testPushes) == 1
	}, 2*time.Second, 50*time.Millisecond)
}

func TestPushNotificationDelete(t *testing.T) {
	require := require.New(t)
	setup(t)
	defer teardown(t)

	require.Nil(ts.server.AddInboxToken(token))

	recvc := newClient(t, 10123)

	recvc.dial()
	recvc.recv("HEYA 0\n")
	recvc.recv("DONE\n")
	recvc.send(fmt.Sprintf("INCO %x\n", token))
	recvc.recv(fmt.Sprintf("INCO %x\n", token))
	recvc.send("IOSA 1234567812345678123456781234567812345678123456781234567812345678\n")
	recvc.recv("IOSA 1234567812345678123456781234567812345678123456781234567812345678\n")
	tokens, err := ts.server.iosPushTokens(recvc.digest[:])
	require.Nil(err)
	require.Equal(1, len(tokens))

	recvc.send("IOSD 1234567812345678123456781234567812345678123456781234567812345678\n")
	recvc.recv("IOSD 1234567812345678123456781234567812345678123456781234567812345678\n")
	recvc.quit()

	tokens, err = ts.server.iosPushTokens(recvc.digest[:])
	require.Nil(err)
	require.Equal(0, len(tokens))
}

func TestPushNotificationList(t *testing.T) {
	require := require.New(t)
	setup(t)
	defer teardown(t)

	require.Nil(ts.server.AddInboxToken(token))

	recvc := newClient(t, 10123)

	recvc.dial()
	recvc.recv("HEYA 0\n")
	recvc.recv("DONE\n")
	recvc.send(fmt.Sprintf("INCO %x\n", token))
	recvc.recv(fmt.Sprintf("INCO %x\n", token))
	recvc.send("IOSA 1234567812345678123456781234567812345678123456781234567812345678\n")
	recvc.recv("IOSA 1234567812345678123456781234567812345678123456781234567812345678\n")
	recvc.send("IOSA 2345678123456781234567812345678123456781234567812345678123456781\n")
	recvc.recv("IOSA 2345678123456781234567812345678123456781234567812345678123456781\n")
	recvc.send("IOSA 3456781234567812345678123456781234567812345678123456781234567812\n")
	recvc.recv("IOSA 3456781234567812345678123456781234567812345678123456781234567812\n")
	recvc.send("IOSL\n")
	recvc.recv("IOSL 3\n")
	recvc.recv("1234567812345678123456781234567812345678123456781234567812345678 ")
	_, err := recvc.recvStr(10)
	require.Nil(err)
	recvc.recv("\n2345678123456781234567812345678123456781234567812345678123456781 ")
	_, err = recvc.recvStr(10)
	require.Nil(err)
	recvc.recv("\n3456781234567812345678123456781234567812345678123456781234567812 ")
	_, err = recvc.recvStr(10)
	require.Nil(err)
	recvc.recv("\n")
	recvc.quit()
}

func TestNoPushNotificationWhenConnected(t *testing.T) {
	require := require.New(t)
	setup(t)
	defer teardown(t)
	require.Nil(ts.server.AddInboxToken(token))

	recvc := newClient(t, 10123)

	recvc.dial()
	recvc.recv("HEYA 0\n")
	recvc.recv("DONE\n")
	recvc.send(fmt.Sprintf("INCO %x\n", token))
	recvc.recv(fmt.Sprintf("INCO %x\n", token))
	recvc.send("IOSA 1234567812345678123456781234567812345678123456781234567812345678\n")
	recvc.recv("IOSA 1234567812345678123456781234567812345678123456781234567812345678\n")
	recvc.send("AUTH 0 2220385707\n")
	recvc.recv("AUTH ")
	sendToken, err := recvc.recvStr(64)
	require.Nil(err)
	recvc.recv(" 0 2220385707\n")

	sendc := newClient(t, 10123)

	sendc.dial()
	sendc.recv("HEYA 0\n")
	sendc.recv("DONE\n")
	sendc.send("SEND %s 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824 5\nhello\n", sendToken)
	sendc.recv("RECV 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824\n")
	sendc.quit()

	time.Sleep(1 * time.Second)
	require.Equal(len(ts.pusher.testPushes), 1)
	recvc.quit()
}

func TestDeauthAll(t *testing.T) {
	require := require.New(t)
	setup(t)
	defer teardown(t)
	require.Nil(ts.server.AddInboxToken(token))

	recvc := newClient(t, 10123)

	recvc.dial()
	recvc.recv("HEYA 0\n")
	recvc.recv("DONE\n")
	recvc.send("INCO %x\n", token)
	recvc.recv("INCO %x\n", token)
	recvc.send("DALL\n")
	recvc.recv("DALL\n")
	recvc.quit()
}

func TestDeauthAllWithoutMailbox(t *testing.T) {
	require := require.New(t)
	setup(t)
	defer teardown(t)
	require.Nil(ts.server.AddInboxToken(token))

	recvc := newClient(t, 10123)

	recvc.dial()
	recvc.recv("HEYA 0\n")
	recvc.recv("DONE\n")
	recvc.send("DALL\n")
	_, err := recvc.recvStr(1)
	require.Error(err)
}

func TestPing(t *testing.T) {
	setup(t)
	defer teardown(t)

	recvc := newClient(t, 10123)

	recvc.dial()
	recvc.recv("HEYA 0\n")
	recvc.recv("DONE\n")
	recvc.send("PING\n")
	recvc.recv("PONG\n")
	recvc.quit()
}

func TestTrim(t *testing.T) {
	require := require.New(t)
	setup(t)
	defer teardown(t)

	require.Nil(ts.server.AddInboxToken(token))
	recvc := newClient(t, 10123)
	recvc.dial()
	recvc.recv("HEYA 0\n")
	recvc.recv("DONE\n")
	recvc.send(fmt.Sprintf("INCO %x\n", token))
	recvc.recv(fmt.Sprintf("INCO %x\n", token))
	recvc.send("AUTH 0 2220385707\n")
	recvc.recv("AUTH ")
	sendToken, err := recvc.recvStr(64)
	require.Nil(err)
	recvc.recv(" 0 2220385707\n")
	sendc := newClient(t, 10123)
	sendc.dial()
	sendc.recv("HEYA 0\n")
	sendc.recv("DONE\n")
	sendc.send("SEND %s 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824 5\nhello\n", sendToken)
	sendc.recv("RECV 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824\n")
	sendc.send("SEND %s e244f187f696561d5fd7e00f618e7ba641dc52e3c137380f6fa23a854b773aac 5\nthere\n", sendToken)
	sendc.recv("RECV e244f187f696561d5fd7e00f618e7ba641dc52e3c137380f6fa23a854b773aac\n")
	sendc.send("SEND %s ab3691d8e45c1f50684b2762fc640afbe61266bf49c34e0a5319044da23af364 4\nmaxi\n", sendToken)
	sendc.recv("RECV ab3691d8e45c1f50684b2762fc640afbe61266bf49c34e0a5319044da23af364\n")
	sendc.quit()
	recvc.recv("HAVE %s 1\n", sendToken)
	recvc.recv("HAVE %s 2\n", sendToken)
	recvc.recv("HAVE %s 3\n", sendToken)
	recvc.send("TRIM %s 1\n", sendToken)
	recvc.recv("TRIM %s 1 2\n", sendToken)
	recvc.send("WANT %s 1\n", sendToken)
	recvc.recv("GONE %s 1\n", sendToken)
	recvc.send("WANT %s 2\n", sendToken)
	recvc.recv("GIVE %s 2 4\nmaxi\n", sendToken)
	recvc.quit()
}

func TestSendLast(t *testing.T) {
	require := require.New(t)
	setup(t)
	defer teardown(t)

	require.Nil(ts.server.AddInboxToken(token))
	recvc := newClient(t, 10123)
	recvc.dial()
	recvc.recv("HEYA 0\n")
	recvc.recv("DONE\n")
	recvc.send(fmt.Sprintf("INCO %x\n", token))
	recvc.recv(fmt.Sprintf("INCO %x\n", token))
	recvc.send("AUTH 0 2220385707\n")
	recvc.recv("AUTH ")
	sendToken, err := recvc.recvStr(64)
	require.Nil(err)
	recvc.recv(" 0 2220385707\n")
	recvc.quit()
	recvc.dial()
	recvc.recv("HEYA 0\n")
	recvc.recv("LAST %s 0\n", sendToken)
	recvc.recv("DONE\n")

	sendc := newClient(t, 10123)
	sendc.dial()
	sendc.recv("HEYA 0\n")
	sendc.recv("DONE\n")
	sendc.send("SEND %s 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824 5\nhello\n", sendToken)
	sendc.recv("RECV 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824\n")
	sendc.send("SEND %s e244f187f696561d5fd7e00f618e7ba641dc52e3c137380f6fa23a854b773aac 5\nthere\n", sendToken)
	sendc.recv("RECV e244f187f696561d5fd7e00f618e7ba641dc52e3c137380f6fa23a854b773aac\n")
	sendc.send("SEND %s ab3691d8e45c1f50684b2762fc640afbe61266bf49c34e0a5319044da23af364 4\nmaxi\n", sendToken)
	sendc.recv("RECV ab3691d8e45c1f50684b2762fc640afbe61266bf49c34e0a5319044da23af364\n")
	sendc.quit()
	recvc.quit()
	recvc.dial()
	recvc.recv("HEYA 0\n")
	recvc.recv("LAST %s 3\n", sendToken)
	recvc.recv("DONE\n")
	recvc.send("QUIT\n")
}

func TestListAndDeauth(t *testing.T) {
	require := require.New(t)
	setup(t)
	defer teardown(t)

	require.Nil(ts.server.AddInboxToken(token))
	recvc := newClient(t, 10123)
	recvc.dial()
	recvc.recv("HEYA 0\n")
	recvc.recv("DONE\n")
	recvc.send(fmt.Sprintf("INCO %x\n", token))
	recvc.recv(fmt.Sprintf("INCO %x\n", token))
	recvc.send("AUTH 0 2220385707\n")
	recvc.recv("AUTH ")
	sendToken1, err := recvc.recvStr(64)
	require.Nil(err)
	recvc.recv(" 0 2220385707\n")

	recvc.send("AUTH 1 2220385708\n")
	recvc.recv("AUTH ")
	sendToken2, err := recvc.recvStr(64)
	require.Nil(err)
	recvc.recv(" 1 2220385708\n")

	recvc.send("AUTH 2 2220385709\n")
	recvc.recv("AUTH ")
	sendToken3, err := recvc.recvStr(64)
	require.Nil(err)
	recvc.recv(" 2 2220385709\n")

	recvc.send("LIST\n")
	recvc.recv("LIST 3\n")
	recvc.recv("%s 0 0 2220385707\n", sendToken1)
	recvc.recv("%s 0 1 2220385708\n", sendToken2)
	recvc.recv("%s 0 2 2220385709\n", sendToken3)

	recvc.send("DEAU %s\n", sendToken2)
	recvc.recv("DEAU %s\n", sendToken2)

	recvc.send("LIST\n")
	recvc.recv("LIST 2\n")
	recvc.recv("%s 0 0 2220385707\n", sendToken1)
	recvc.recv("%s 0 2 2220385709\n", sendToken3)

	recvc.send("QUIT\n")
}

func TestExtend(t *testing.T) {
	require := require.New(t)
	setup(t)
	defer teardown(t)

	require.Nil(ts.server.AddInboxToken(token))
	recvc := newClient(t, 10123)
	recvc.dial()
	recvc.recv("HEYA 0\n")
	recvc.recv("DONE\n")
	recvc.send("INCO %x\n", token)
	recvc.recv("INCO %x\n", token)
	recvc.send("AUTH 0 2220385707\n")
	recvc.recv("AUTH ")
	sendToken1, err := recvc.recvStr(64)
	require.Nil(err)
	recvc.recv(" 0 2220385707\n")

	recvc.send("EXTD %s 1000\n", sendToken1)
	recvc.recv("EXTD %s %d\n", sendToken1, 2220386707)
	recvc.send("QUIT\n")
}
