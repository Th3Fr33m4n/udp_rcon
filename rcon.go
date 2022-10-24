package rcon

import (
	"bytes"
	"fmt"
	"net"
	"sync"
	"time"
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
	response, err := rc.RunCommand("stats", 1024)

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
		msgLen += len(rc.challenge) + 1
	}

	cmdLine := make([]byte, 0, msgLen)
	cmdLine = append(cmdLine, RconCommandHeader...)

	if rc.useChallenge {
		cmdLine = append(cmdLine, rc.challenge...)
		cmdLine = append(cmdLine, RconMessageSeparator)
	}

	cmdLine = append(cmdLine, []byte(rc.password)...)
	cmdLine = append(cmdLine, RconMessageSeparator)
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

	responseLen := len(RconChallengeResponseHeader) + RCON_CHALLENGE_LENGTH + RCON_RESPONSE_TRAILING_ZEROES

	cmdResponse, err := rc.Receive(responseLen)

	if err != nil {
		return err
	}

	if !bytes.HasPrefix(*cmdResponse, RconChallengeResponseHeader) {
		return ErrInvalidChallengeResponse
	}

	rc.setupChallenge(cmdResponse)
	return nil
}

func (rc *RemoteConsole) setupChallenge(response *[]byte) {
	idx := bytes.IndexByte(*response, RconStringTerminator)
	rc.challenge = (*response)[19:idx]
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
