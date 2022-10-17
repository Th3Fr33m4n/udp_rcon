package rcon

import (
	"bytes"
	"fmt"
	"net"
	"sync"
	"time"
)

const RCON_CHALLENGE_RESPONSE_LENGTH = 31
const RCON_CHALLENGE_LENGH = 10

var (
	MissingChallengeResponse = []byte{0xFF, 0xFF, 0xFF, 0xFF, 0x39}
	InvalidPasswordResponse  = []byte{0xFF, 0xFF, 0xFF, 0xFF, 0x6C, 0x42, 0x61, 0x64, 0x20, 0x72, 0x63, 0x6F,
		0x6E, 0x5F, 0x70, 0x61, 0x73, 0x73, 0x77, 0x6F, 0x72, 0x64, 0x2E, 0x0A, 0x00, 0x00}
	AckResponse          = []byte{0xFF, 0xFF, 0xFF, 0xFF, 0x6C, 0x00, 0x00}
	RconCommandHeader    = []byte{0xFF, 0xFF, 0xFF, 0xFF, 0x72, 0x63, 0x6f, 0x6e, 0x20}
	RconChallengeRequest = []byte{0xff, 0xff, 0xff, 0xff, 0x63, 0x68, 0x61, 0x6c, 0x6c, 0x65, 0x6e, 0x67,
		0x65, 0x20, 0x72, 0x63, 0x6f, 0x6e, 0x0a, 0x00}
)

type RemoteConsole struct {
	host         string
	password     string
	conn         net.Conn
	rwlock       sync.Mutex
	challenge    []byte
	useChallenge bool
	connector    Connector
}

type Connector interface {
	Connect(host string, timeout time.Duration) (net.Conn, error)
}

type UdpConnector struct{}

func (cnt UdpConnector) Connect(host string, timeout time.Duration) (net.Conn, error) {
	return net.DialTimeout("udp", host, timeout)
}

func (rc *RemoteConsole) GetChallenge() *[]byte {
	return &rc.challenge
}

func (rc *RemoteConsole) SetPassword(password string) {
	rc.password = password
}

func (rc *RemoteConsole) Connect() error {
	fmt.Println(rc.host)
	conn, err := rc.connector.Connect(rc.host, time.Second)
	rc.conn = conn
	return err
}

func (rc *RemoteConsole) Disconnect() error {
	if rc.conn != nil {
		return rc.conn.Close()
	}
	return nil
}

func (rc *RemoteConsole) ValidateCredentials() error {
	//send a generic command to test challenge and password
	response, err := rc.RunCommand("stats", 2048)

	if err != nil {
		return err
	}

	if bytes.HasPrefix(*response, InvalidPasswordResponse) {
		return ErrInvalidPassword
	} else if bytes.HasPrefix(*response, MissingChallengeResponse) {
		return ErrChallengeRequired
	}

	return nil
}

func (rc *RemoteConsole) buildCommand(cmd string) *[]byte {
	msgLen := len(cmd) + len(RconCommandHeader) + 2

	if rc.useChallenge {
		msgLen += RCON_CHALLENGE_LENGH + 1
	}

	cmdLine := make([]byte, 0, msgLen)
	cmdLine = append(cmdLine, RconCommandHeader...)

	if rc.useChallenge {
		cmdLine = append(cmdLine, rc.challenge...)
		cmdLine = append(cmdLine, ' ')
	}

	cmdLine = append(cmdLine, []byte(rc.password)...)
	cmdLine = append(cmdLine, ' ')
	cmdLine = append(cmdLine, []byte(cmd)...)
	cmdLine = append(cmdLine, 0, 0)
	return &cmdLine
}

func (rc *RemoteConsole) RunCommand(cmd string, maxSize int) (*[]byte, error) {
	cmdLine := rc.buildCommand(cmd)

	rc.rwlock.Lock()
	defer rc.rwlock.Unlock()

	err := rc.Send(cmdLine)

	if err != nil {
		return nil, err
	}

	cmdResponse, err := rc.Receive(maxSize)

	if err != nil {
		return nil, err
	}

	return cmdResponse, nil
}

func (rc *RemoteConsole) NegociateChallenge() error {
	rc.rwlock.Lock()
	defer rc.rwlock.Unlock()

	err := rc.Send(&RconChallengeRequest)
	if err != nil {
		return err
	}

	cmdResponse, err := rc.Receive(RCON_CHALLENGE_RESPONSE_LENGTH)

	if err != nil {
		return err
	}

	if len(*cmdResponse) < 29 {
		return ErrInvalidChallengeResponse
	}

	rc.setupChallenge(cmdResponse)
	return nil
}

func (rc *RemoteConsole) setupChallenge(response *[]byte) {
	rc.challenge = (*response)[19:29]
	rc.useChallenge = true
}

func (rc *RemoteConsole) Send(msg *[]byte) error {
	rc.conn.SetWriteDeadline(time.Now().Add(time.Second * 2))
	_, err := rc.conn.Write(*msg)
	return err
}

func (rc *RemoteConsole) Receive(len int) (*[]byte, error) {
	rc.conn.SetReadDeadline(time.Now().Add(time.Second * 2))

	cmdResponse := make([]byte, len)
	n, err := rc.conn.Read(cmdResponse)

	if err != nil {
		return nil, err
	}
	rp := cmdResponse[:n]
	return &rp, nil
}

func NewRemoteConsole(host, password string, useChallenge bool, connector Connector) (*RemoteConsole, error) {
	rc := RemoteConsole{host: host, password: password, rwlock: sync.Mutex{}, useChallenge: useChallenge, connector: connector}
	rc.Connect()

	if useChallenge {
		rc.NegociateChallenge()
	}

	return &rc, nil
}
