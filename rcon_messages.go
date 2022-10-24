package rcon

const RCON_CHALLENGE_LENGTH = 10
const RCON_RESPONSE_TRAILING_ZEROES = 2

var (
	MissingChallengeResponse = []byte{0xFF, 0xFF, 0xFF, 0xFF, 0x39}
	InvalidPasswordResponse  = []byte{0xFF, 0xFF, 0xFF, 0xFF, 0x6C, 0x42, 0x61, 0x64, 0x20, 0x72, 0x63, 0x6F,
		0x6E, 0x5F, 0x70, 0x61, 0x73, 0x73, 0x77, 0x6F, 0x72, 0x64, 0x2E, 0x0A, 0x00, 0x00}
	AckResponse          = []byte{0xFF, 0xFF, 0xFF, 0xFF, 0x6C, 0x00, 0x00}
	RconCommandHeader    = []byte{0xFF, 0xFF, 0xFF, 0xFF, 0x72, 0x63, 0x6f, 0x6e, 0x20}
	RconChallengeRequest = []byte{0xff, 0xff, 0xff, 0xff, 0x63, 0x68, 0x61, 0x6c, 0x6c, 0x65, 0x6e, 0x67,
		0x65, 0x20, 0x72, 0x63, 0x6f, 0x6e, 0x0a, 0x00}
	RconChallengeResponseHeader = []byte{0xFF, 0xFF, 0xFF, 0xFF, 0x63, 0x68, 0x61, 0x6C, 0x6C, 0x65, 0x6E,
		0x67, 0x65, 0x20, 0x72, 0x63, 0x6F, 0x6E, 0x20}
	RconStringTerminator byte = 0x0a
	RconMessageSeparator byte = 0x20
)
