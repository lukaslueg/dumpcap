package dumpcap

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
)

const (
	successText          string = "This is a huge success"
	errText1                    = "Not so much"
	errText2                    = "Something is wrong"
	mockFailStartArg            = "--FAIL_START"
	mockFailExitArg             = "--FAIL_EXIT"
	mockFailFilterArg           = "--FAIL_FILTER"
	mockFailSilenceArg          = "--FAIL_OUPUT"
	mockIllegalOutputArg        = "--ILLEGAL_OUTPUT"
	statsOutput                 = "devX\t123\t456\n"
	interfacesOutput            = "1. em1\t\t\t0\t\tnetwork\n" +
		"2. lo\t\tLoopback\t0\t127.0.0.1,::1\tloopback\n"
	layersOutput = "1\n1\tEN10MB\tEthernet\n143\tDOCSIS\tDOCSIS\n"
	gibberish    = "foobar\n"
)

var failStartErr = errors.New("Some error while starting the subprocess")
var failExitErr = errors.New("Dumpcap returned nonzero exit status")

func generateMsg(msgType uint8, msgText string) []byte {
	msgText += "\x00"
	msgLen := len(msgText)
	var b bytes.Buffer
	b.Write([]byte{byte(msgType), byte(msgLen >> 16), byte(msgLen >> 8), byte(msgLen)})
	b.Write([]byte(msgText))
	return b.Bytes()
}

func generateErrorMsg(msgText1 string, msgText2 string) []byte {
	msg := generateMsg(ErrMsg, msgText1)
	msg = append(msg, generateMsg(ErrMsg, msgText2)...)
	return generateMsg(ErrMsg, string(msg))
}

// Testing the dumpcap tool without actually calling a subprocess.
type mockCommand struct {
	stdout      mockPipe
	stderr      mockPipe
	commandfunc func()
	failStart   bool
	failExit    bool
	failOutput  string
	quit        chan int
}

func writePipe(p chan byte, buf []byte) {
	for _, b := range buf {
		p <- b
	}
}

func (c *mockCommand) mockedVersionCmd() {
	writePipe(c.stdout.pipe, []byte(successText))
}

func (c *mockCommand) mockedDevicesCmd() {
	writePipe(c.stdout.pipe, []byte(interfacesOutput))
}

func (c *mockCommand) mockedCapabilitiesCmd() {
	writePipe(c.stderr.pipe, generateMsg(SuccessMsg, successText))
	writePipe(c.stdout.pipe, []byte(layersOutput))
}

func (c *mockCommand) mockedStatsCmd() {
	if c.failOutput == mockIllegalOutputArg {
		writePipe(c.stdout.pipe, []byte(gibberish))
	} else {
		for {
			writePipe(c.stdout.pipe, []byte(statsOutput))
		}
	}
}

func (c *mockCommand) mockedCaptureCmd() {
	if c.failOutput == mockFailFilterArg {
		writePipe(c.stderr.pipe, generateMsg(BadFilterMsg, errText1))
	} else {
		writePipe(c.stderr.pipe, generateMsg(FileMsg, "foobar"))
		writePipe(c.stderr.pipe, generateMsg(PacketCountMsg, "123"))
		writePipe(c.stderr.pipe, generateMsg(DropCountMsg, "456"))
	}
}

// Start starts the process
func (c *mockCommand) Start() error {
	if c.failStart {
		close(c.stdout.pipe)
		close(c.stderr.pipe)
		return failStartErr
	}

	go func() {
		c.commandfunc()
		close(c.stdout.pipe)
		close(c.stderr.pipe)
	}()

	return nil
}

// Run Starts the process and then Waits
func (c *mockCommand) Run() error {
	if err := c.Start(); err != nil {
		return err
	}
	return c.Wait()
}

func (c *mockCommand) StdoutPipe() (io.ReadCloser, error) {
	return c.stdout, nil
}

func (c *mockCommand) StderrPipe() (io.ReadCloser, error) {
	return c.stderr, nil
}

func (c *mockCommand) Wait() error {
	if c.failExit {
		return failExitErr
	}
	return nil
}

func (c *mockCommand) Output() ([]byte, error) {
	err := c.Run()
	if err != nil {
		return nil, err
	}

	var buf bytes.Buffer
	io.Copy(&buf, c.stdout)

	return buf.Bytes(), nil
}

func (c *mockCommand) kill() error {
	return nil
}

type mockPipe struct {
	pipe       chan byte
	readError  error // error the pipe should return on Read
	closeError error // error the pipe should return on Close
}

func newMockPipe() mockPipe {
	m := mockPipe{}
	m.pipe = make(chan byte)
	return m
}

func (p mockPipe) Read(dest []byte) (int, error) {
	var i int
	for i = 0; i < len(dest); i++ {
		b, ok := <-p.pipe
		if !ok {
			if i == 0 {
				return 0, io.EOF
			}
			break
		}
		dest[i] = b
	}
	return i, nil
}

func (p mockPipe) Close() error {
	return p.closeError
}

func newMockCommand(name string, arg ...string) commander {
	var c mockCommand
	c.commandfunc = c.mockedCaptureCmd
	c.quit = make(chan int)
	c.stdout = newMockPipe()
	c.stderr = newMockPipe()

	// Setup the test by interpreting the arguments given by the test functions
	// as if they were calling dumpcap itself
	for _, a := range arg {
		switch a {
		case versionCmd:
			c.commandfunc = c.mockedVersionCmd
		case statsCmd:
			c.commandfunc = c.mockedStatsCmd
		case listDevicesCmd:
			c.commandfunc = c.mockedDevicesCmd
		case listLayersCmd:
			c.commandfunc = c.mockedCapabilitiesCmd
		case mockFailStartArg:
			c.failStart = true
		case mockFailExitArg:
			c.failExit = true
		case mockIllegalOutputArg, mockFailSilenceArg, mockFailFilterArg:
			c.failOutput = a
		}
	}
	return &c
}

func newMockcap(testArg ...string) Dumpcap {
	d := Dumpcap{}
	d.newCommand = func(name string, arg ...string) commander {
		finalArg := append(arg, testArg...)
		return newMockCommand(name, finalArg...)
	}
	return d
}

func TestVersion(t *testing.T) {
	d := newMockcap()
	if v, err := d.Version(); v != successText || err != nil {
		t.Error(v, err)
	}
}

func TestVersionFailsToStart(t *testing.T) {
	d := newMockcap(mockFailStartArg)
	if v, err := d.Version(); v != "" || err != failStartErr {
		t.Error(v, err)
	}
}

func TestVersionFails(t *testing.T) {
	d := newMockcap(mockFailExitArg)
	if _, err := d.Version(); err != failExitErr {
		t.Error(err)
	}
}

func TestVersionString(t *testing.T) {
	d := newMockcap()
	if v := d.VersionString(); v != successText {
		t.Error(v)
	}
}

func TestVersionStringFails(t *testing.T) {
	d := newMockcap(mockFailExitArg)
	if v := d.VersionString(); v != UnknownVersion {
		t.Error(v)
	}
}

func TestCapture(t *testing.T) {
	d := newMockcap()
	var c *Capture
	var err error
	var msg PipeMessage
	if c, err = d.NewCapture(Arguments{}); err != nil {
		t.Fatal(err)
	}

	msg = <-c.Messages
	if msg.Type != FileMsg || msg.Text != "foobar" {
		t.Error(msg.Type, msg.Text)
	}
	msg = <-c.Messages
	if msg.Type != PacketCountMsg || msg.PacketCount != 123 {
		t.Error(msg.Type, msg.PacketCount)
	}
	msg = <-c.Messages
	if msg.Type != DropCountMsg || msg.DropCount != 456 {
		t.Error(msg.Type, msg.DropCount)
	}

	if err = c.Wait(); err != nil {
		t.Error(err)
	}
}

func TestCaptureBadFilter(t *testing.T) {
	d := newMockcap(mockFailFilterArg)
	var c *Capture
	var err error
	if c, err = d.NewCapture(Arguments{}); err != nil {
		t.Fatal(err)
	}

	msg := <-c.Messages
	if msg.Type != BadFilterMsg || msg.Text != errText1 {
		t.Error(msg.Type, msg.Text)
	}
}

func TestStatisticsFailsStart(t *testing.T) {
	d := newMockcap(mockFailStartArg)
	if _, err := d.NewStatistics(); err != failStartErr {
		t.Error(err)
	}
}

func TestStatistics(t *testing.T) {
	d := newMockcap()
	var s *Statistics
	var err error
	if s, err = d.NewStatistics(); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		ds, ok := <-s.Stats
		if !ok {
			t.Fatal(ds, ok)
		}
		if ds.Name != "devX" {
			t.Error(ds.Name)
			break
		}
		if ds.PacketCount != 123 {
			t.Error(ds.PacketCount)
			break
		}
		if ds.DropCount != 456 {
			t.Error(ds.DropCount)
			break
		}
	}

	s.Close()
	if err = s.Wait(); err != nil {
		t.Error(err)
	}
}

func TestStatisticsIllegalOutput(t *testing.T) {
	d := newMockcap(mockIllegalOutputArg)
	var s *Statistics
	var err error
	if s, err = d.NewStatistics(); err != nil {
		t.Fatal(err)
	}
	ds, ok := <-s.Stats
	if ok {
		t.Fatal(ds, ok)
	}

	s.Close()
	if err = s.Wait(); err == nil {
		t.Error(err)
	}
}

func TestDevicesFailsStart(t *testing.T) {
	d := newMockcap(mockFailStartArg)
	if _, err := d.Devices(false); err != failStartErr {
		t.Error(err)
	}
}

func TestDevices(t *testing.T) {
	d := newMockcap()
	var devices []Device
	var err error
	if devices, err = d.Devices(false); err != nil {
		t.Fatal(devices, err)
	}

	if len(devices) != 2 {
		t.Error(devices)
	}
	dev := devices[0]
	if dev.Name != "em1" || dev.Number != 1 || dev.DevType != WiredDevice ||
		dev.CanRFMon || len(dev.LLTs) > 0 || dev.Loopback || len(dev.Addresses) > 0 ||
		dev.VendorName != "" || dev.FriendlyName != "" || dev.String() != "em1" {
		t.Errorf("%#v\n", dev)
	}
	dev = devices[1]
	if dev.Name != "lo" || dev.Number != 2 || dev.DevType != WiredDevice ||
		dev.CanRFMon || len(dev.LLTs) > 0 || !dev.Loopback || len(dev.Addresses) != 2 ||
		dev.Addresses[0] != "127.0.0.1" || dev.Addresses[1] != "::1" || dev.VendorName != "" ||
		dev.FriendlyName != "Loopback" || dev.String() != "lo" {
		t.Errorf("%#v\n", dev)
	}
}

func TestCapabilitiesFailsStart(t *testing.T) {
	d := newMockcap(mockFailStartArg)
	dev := Device{Name: "devX"}
	if err := d.Capabilities(&dev, false); err != failStartErr {
		t.Error(err)
	}
}

func TestCapabilities(t *testing.T) {
	d := newMockcap()
	dev := Device{Name: "em1"}
	if err := d.Capabilities(&dev, false); err != nil {
		t.Fatal(err)
	}

	if !dev.CanRFMon {
		t.Error("CanRFMon should be true")
	}
	if len(dev.LLTs) != 2 {
		t.Fatal("Number of LLTs should be 2, is ", len(dev.LLTs))
	}
	llt := dev.LLTs[0]
	if llt.DLT != 1 || llt.Name != "EN10MB" || llt.Description != "Ethernet" {
		t.Error(llt)
	}
	llt = dev.LLTs[1]
	if llt.DLT != 143 || llt.Name != "DOCSIS" || llt.Description != "DOCSIS" {
		t.Error(llt)
	}

}

func TestReadPipeMessage(t *testing.T) {

	// Empty reads results in EOF error
	_, err := readPipeMsg(bytes.NewReader([]byte{}))
	if err != io.EOF {
		t.Error(err)
	}

	// Message texts should come out unchanged
	msg, err := readPipeMsg(bytes.NewReader(generateMsg(SuccessMsg, successText)))
	if err != nil {
		t.Error(err)
	}
	if msg.Type != SuccessMsg {
		t.Error(msg.Type)
	}
	if msg.Text != successText {
		t.Error(msg)
	}

	// Error sub-message should get extracted
	msg, err = readPipeMsg(bytes.NewReader(generateErrorMsg(errText1, errText2)))
	if msg.Type != ErrMsg {
		t.Error(msg.Type)
	}
	if msg.Text != errText1+errText2 {
		t.Error(msg.Text)
	}

	// Packetcount is converted and filled
	msg, err = readPipeMsg(bytes.NewReader(generateMsg(PacketCountMsg, "123")))
	if msg.Type != PacketCountMsg {
		t.Error(msg.Type)
	}
	if msg.PacketCount != 123 {
		t.Error(msg.PacketCount)
	}

	// Dropcount is converted and filled
	msg, err = readPipeMsg(bytes.NewReader(generateMsg(DropCountMsg, "456")))
	if msg.Type != DropCountMsg {
		t.Error(msg.Type)
	}
	if msg.DropCount != 456 {
		t.Error(msg.DropCount)
	}
}

func TestBuildArgs(t *testing.T) {
	args := Arguments{}
	if strings.Join(args.buildArgs(), ",") != "" {
		t.Error("Empty arguments should result in empty string")
	}
	args = Arguments{command: statsCmd, BufferedBytes: 123, CaptureFilter: "foobar",
		EnableMonitorMode: true, FileFormat: UsePCAPNG,
		StopOnDuration: 60, SwitchOnFiles: 5,
		DeviceArgs: []DeviceArgument{{CaptureFilter: "barfoo",
			DisablePromiscuousMode: true, KernelBufferSize: 456,
			LinkLayerType: "llt", Name: "dev1"}}}
	arg_string := strings.Join(args.buildArgs(), " ")
	if arg_string != "-S -C 123 -f foobar -I -n -a duration:60 -b files:5 -i dev1 -p -B 456 -y llt" {
		t.Error(arg_string)
	}

}
