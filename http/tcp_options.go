package http

const (
	OptionKindEnd    = 0 // End of option list
	OptionKindNOP    = 1
	OptionKindMSS    = 2
	OptionKindWScale = 3
)

type TCPOptions func(options *[]byte)

func WithMSS(mss uint16) TCPOptions {
	return func(opts *[]byte) {
		// Kind = 1 byte, Length = 1 byte, MSS value = 2 bytes
		mssOption := []byte{OptionKindMSS, 4, byte(mss >> 8), byte(mss)}
		*opts = append(*opts, mssOption...)
	}
}

func WithWScale(wscale uint8) TCPOptions {
	return func(opts *[]byte) {
		// Nop = 1 byte, Kind = 1 byte, Length = 1 byte, Scale = 1 byte
		wScaleOption := []byte{OptionKindNOP, OptionKindWScale, 3, wscale}
		*opts = append(*opts, wScaleOption...)
	}
}
