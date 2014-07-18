package dumpcap

import (
	"bytes"
	"errors"
	"io"
	"regexp"
	"strconv"
)

// used to decode the output of "dumpcap -D -M"
var deviceListRE = regexp.MustCompile(`(?m:^)` +
	`(\d+)\. ` + // the device number
	`([^\t]+)\t` + // the device name
	`([^\t]*)\t` + // the vendor name
	`([^\t]*)\t` + // the human friendly name
	`(\d+)\t` + // the interface type
	`([a-fA-F0-9\.:,]*)\t` + // known addresses
	`(\w+)` + // "loopback" or "network"
	`(?m:$)` + // newline
	``)

// The message headers that might arrive from dumpcap.
// Taken from sync_pipe.h and hopefully not subject to change
const (
	BadFilterMsg   byte = 66 // At least one of the given capture filters is invalid.
	DropCountMsg        = 68 // Dumpcap reports the absolute number of packets dropped.
	ErrMsg              = 69 // Dumcap reports a general error.
	FileMsg             = 70 // Dumcap has started to write captured traffic to a new file.
	PacketCountMsg      = 80 // Dumpap reports the number of packets written to the currently active file.
	QuitMsg             = 81 // TODO Used on windows
	SuccessMsg          = 83 // Dumpcap reports success execution.
)

// PipeMessage represents messages send by dumpcap to inform about various
// events.
type PipeMessage struct {
	Type        byte   // One of BadFilterMsg, ErrMsg, etc.
	DropCount   uint64 // The absolute number of packets dropped. Only filled for DropCountMsg.
	PacketCount uint64 // The number of packets written to the currently active file. Only filled for PacketCountMsg.
	Text        string // Contains the message's text for BadFilterMsg, ErrMsg and SuccessMsg; contains the filename for FileMsg.
}

// DeviceType represents device types like USB or WiFi as reported by dumpcap.
type DeviceType uint8

// Known device types. Taken from capture_ifinfo.h and hopefully not subject to
// change
const (
	AirpcapDevice   DeviceType = 1
	BluetoothDevice            = 4
	DialupDevice               = 6
	PipeDevice                 = 2
	StdinDevice                = 3
	USBDevice                  = 7
	VirtualDevice              = 8
	WiredDevice                = 0
	WirelessDevice             = 5
)

func (dt DeviceType) String() string {
	switch dt {
	case AirpcapDevice:
		return "AIRPCAP"
	case BluetoothDevice:
		return "BLUETOOTH"
	case DialupDevice:
		return "DIALUP"
	case PipeDevice:
		return "PIPE"
	case StdinDevice:
		return "STDIN"
	case USBDevice:
		return "USB"
	case VirtualDevice:
		return "VIRTUAL"
	case WiredDevice:
		return "WIRED"
	case WirelessDevice:
		return "WIRELESS"
	default:
		return "UNKNOWN"
	}
}

// Arguments passed to dumpcap
const (
	autoStopConditionArg  string = "-a"
	bufferedBytesArg             = "-C"
	bufferedPacketsArg           = "-N"
	captureFilterArg             = "-f"
	disablePromiscuousArg        = "-p"
	durationArg                  = "duration"
	enableGroupAccessArg         = "-g"
	enableMonitorModeArg         = "-I"
	filesArg                     = "files"
	filesizeArg                  = "filesize"
	interfaceArg                 = "-i"
	kernelBufferSizeArg          = "-B"
	linkLayerTypeArg             = "-y"
	machineReadableArg           = "-M"
	fileArg                      = "-w"
	packetCountArg               = "-c"
	pipeOutputArg                = "-Z"
	ringbufferArg                = "-b"
	snaplenArg                   = "-s"
	stopPacketCountArg           = "-c"
	usePCAPArg                   = "-P"
	usePCAPNGArg                 = "-n"
	useThreadsArg                = "-t"
	wifiChannelArg               = "-k"
)

// Commands passed to dumpcap
const (
	captureCmd     string = ""
	listDevicesCmd        = "-D"
	listLayersCmd         = "-L"
	statsCmd              = "-S"
	versionCmd            = "-v"
)

// File formats dumpcap can write
const (
	UseDefaultFileFormat = iota
	UsePCAP              // Use PCAP by default
	UsePCAPNG            // Use PCAP-ng by default
)

// The string returned by VersionString() in case Version() reports an error
const UnknownVersion string = "unknown"

// parsePipeMsg reads one message from the given reader and returns it's type
// and it's associated message text.
func parsePipeMsg(input io.Reader) (msgType uint8, msg []byte, err error) {
	// The header is four bytes, one for type of message, three for size of
	// following message text
	var buffer []byte
	buffer = make([]byte, 4)
	_, err = io.ReadFull(input, buffer)
	if err != nil {
		return 0, nil, err
	}

	msgType = buffer[0]
	msgSize := (int(buffer[1]) << 16) | (int(buffer[2]) << 8) | (int(buffer[3]) << 0)
	if msgSize == 0 {
		return msgType, nil, nil
	}
	buffer = make([]byte, msgSize)
	_, err = io.ReadFull(input, buffer)
	if err != nil {
		return 0, nil, err
	}
	if len(buffer) > 0 && buffer[len(buffer)-1] == 0 {
		buffer = buffer[:len(buffer)-1]
	}
	return msgType, buffer, nil
}

// parsePipeErrMsg reads the message text associated with an ErrMsg.
func parsePipeErrMsg(input io.Reader) (string, error) {
	// There will be a primary and a secondary message which we just
	// concatenate
	_, err1, err := parsePipeMsg(input)
	if err != nil {
		return "", err
	}
	_, err2, err := parsePipeMsg(input)
	if err != nil {
		return "", err
	}
	return string(err1) + string(err2), nil
}

// readPipeMsg completely decodes a message sent by dumpcap.
func readPipeMsg(input io.Reader) (msg *PipeMessage, err error) {
	msg = &PipeMessage{}
	msgType, msgBuffer, err := parsePipeMsg(input)
	if err != nil {
		return nil, err
	}
	msg.Type = msgType
	msg.Text = string(msgBuffer)

	if msgType == DropCountMsg {
		i, err := strconv.ParseUint(msg.Text, 10, 0)
		if err != nil {
			return nil, err
		}
		msg.DropCount = i
	} else if msgType == ErrMsg {
		errmsg, err := parsePipeErrMsg(bytes.NewReader(msgBuffer))
		if err != nil {
			return nil, err
		}
		msg.Text = errmsg
	} else if msgType == PacketCountMsg {
		i, err := strconv.ParseUint(msg.Text, 10, 0)
		if err != nil {
			return nil, err
		}
		msg.PacketCount = i
	}
	return msg, nil
}

// waitForSuccessMsg calls readPipeMsg and returns nil if and only if a
// success-message is decoded.
func waitForSuccessMsg(input io.Reader) error {
	msg, err := readPipeMsg(input)
	if err != nil {
		return err
	}
	if msg.Type != SuccessMsg {
		return errors.New("Unexpected message from dumpcap: " + string(msg.Type))
	}
	return nil
}
