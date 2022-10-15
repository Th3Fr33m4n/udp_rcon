package rcon

import (
	"bytes"
	"net"
	"testing"
	"time"

	"github.com/Th3Fr33m4n/udp_rcon/hlds_mock"
)

var server, client net.Conn
const host = "127.0.0.1:27015"
const password = "p455w0rd"

type PipeConnector struct {}

func (cnt PipeConnector) Connect(host string, timeout time.Duration) (net.Conn, error) {
    return client, nil
}

func serverInit() {
    server, client = net.Pipe()
    go hlds_mock.Run(password, server)
}

func serverStop() {
    client.Write(hlds_mock.CommandQuit)
}

func TestChallengeNegociation(t *testing.T) {
    serverInit()
    defer serverStop()

    rcon, err := NewRemoteConsole(host, password, false, PipeConnector{})
    
    if err != nil {
        t.Error(err)
    }
    
    got := *rcon.GetChallenge()
    want := []byte{}
    
    if len(got) > 0 {
        t.Errorf("got %s, want %s", got, want)
    }

    rcon.NegociateChallenge()

    got = *rcon.GetChallenge()
    want = hlds_mock.ChallengeMock
    
    if !bytes.Equal(got, want) {
        t.Errorf("got %s, want %s", got, want)
    }
}

func TestAutoChallengeNegociation(t *testing.T) {
    serverInit()
    defer serverStop()

    rcon, err := NewRemoteConsole(host, password, true, PipeConnector{})
    
    if err != nil {
        t.Error(err)
    }

    got := *rcon.GetChallenge()
    want := hlds_mock.ChallengeMock
    
    if !bytes.Equal(got, want) {
        t.Errorf("got %s, want %s", got, want)
    }
}

func TestCommandExecution(t *testing.T) {
    serverInit()
    defer serverStop()

    rcon, err := NewRemoteConsole(host, password, true, PipeConnector{})
    
    if err != nil {
        t.Error(err)
    }

    got, err := rcon.RunCommand("stats", 2048)
    want := hlds_mock.AckResponse

    if !bytes.Equal(*got, want) {
        t.Errorf("got %s, want %s", *got, want)
    }
}

func TestInvalidPassword(t *testing.T) {
    serverInit()
    defer serverStop()

    rcon, err := NewRemoteConsole(host, "asdasd", true, PipeConnector{})
    
    if err != nil {
        t.Error(err)
    }

    got, err := rcon.RunCommand("stats", 2048)
    want := InvalidPasswordResponse
    
    if !bytes.Equal(*got, want) {
        t.Errorf("got %s, want %s", *got, want)
    }
}

func TestInvalidChallenge(t *testing.T) {
    serverInit()
    defer serverStop()

    rcon, err := NewRemoteConsole(host, password, false, PipeConnector{})
    
    if err != nil {
        t.Error(err)
    }

    got, err := rcon.RunCommand("stats", 2048)
    want := MissingChallengeResponse
    
    if !bytes.HasPrefix(*got, want) {
        t.Errorf("got %s, want %s", *got, want)
    }
}