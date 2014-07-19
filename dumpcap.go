/* Dumpcap interface for golang
Copyright (C) 2014 Lukas Lueg, lukas.lueg@gmail.com

This program is free software; you can redistribute it and/or modify it under
the terms of the GNU General Public License as published by the Free Software
Foundation; either version 3 of the License, or (at your option) any later
version.
This program is distributed in the hope that it will be useful, but WITHOUT ANY
WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
PARTICULAR PURPOSE.  See the GNU General Public License for more details.
You should have received a copy of the GNU General Public License along with
this program; if not, write to the Free Software Foundation, Inc., 51 Franklin
Street, Fifth Floor, Boston, MA 02110-1301  USA
*/

/*Package dumpcap provides an interface to Wireshark's dumpcap tool.
You can use dumpcap to find out about available network devices and their
capabilities, receive live statistics about the number of packets seen on each
device and capture traffic using various options. On most BSD/Linux
distributions dumpcap is suid'd so one can avoid root credibilities while
processing captured traffic, possibly using packages like gopackets.
*/
package dumpcap

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

var pipeName = "none" // TODO Windows uses a named pipe

// Interface to control the dumpcap process.
type commander interface {
	Start() error
	Run() error
	StdoutPipe() (io.ReadCloser, error)
	StderrPipe() (io.ReadCloser, error)
	Wait() error
	Output() ([]byte, error)
	kill() error
}

// osCommand implements the commander interface via os.Exec and such
type osCommand struct {
	*exec.Cmd
}

func (o osCommand) kill() error {
	return o.Process.Kill()
}

func newOSCommand(name string, arg ...string) commander {
	return osCommand{Cmd: exec.Command(name, arg...)}
}

// Dumpcap allows calls to Wireshark's dumpcap tool.
type Dumpcap struct {
	newCommand func(string, ...string) commander
	Executable string // The name (and possibly full path) of the dumpcap-executable
}

// NewDumpcap creates a new Dumpcap-struct with the Executable set to
// "dumpcap".
func NewDumpcap() *Dumpcap {
	d := Dumpcap{}
	d.newCommand = newOSCommand
	d.Executable = "dumpcap"
	return &d
}

// LinkLayerType represents the link layer a device may capture on.
type LinkLayerType struct {
	DLT         uint
	Name        string
	Description string
}

// String returns the LLT's Name
func (llt LinkLayerType) String() string {
	return llt.Name
}

// Device represents an interface capable of capturing network traffic
type Device struct {
	DevType      DeviceType // e.g. WiredDevice or BluetoothDevice
	Name         string     // The system-wide name e.g. "eth0"
	Number       uint       // A unique number  // TODO Used on windows as Name can be empty there
	VendorName   string
	FriendlyName string
	Addresses    []string        // Addresses the device is currently bound to
	Loopback     bool            // True if the device is a loopback interface
	CanRFMon     bool            // True if the device supports monitor-mode
	LLTs         []LinkLayerType // A slice of supported link-layer types
}

// String returns the Device's name
func (d Device) String() string {
	return d.Name
}

// DeviceArgument represents device-specific arguments passed to dumpcap.
type DeviceArgument struct {
	CaptureFilter          string // Packet filter in libpcap filter syntax
	DisablePromiscuousMode bool   // Don't capture in promiscuous mode
	EnableMonitorMode      bool   // Capture in monitor mode, if available. The device may lose all connections.
	KernelBufferSize       uint64 // Size of kernel buffer in MiB
	LinkLayerType          string // Link layer to capture traffic on
	Name                   string // The name of the interface
	SnapshotLength         uint64 // Packet snapshot length
	WiFiChannel            string // Set channel on Wifi device. Given as "<freq>,[<type>]"
}

// Arguments represents global arguments passed to dumpcap for capturing
// traffic
type Arguments struct {
	BufferedBytes          uint64           // Maximum number of bytes used for buffering packets within dumpcap
	BufferedPackets        uint64           // Maximum number of packets buffered within dumpcap
	CaptureFilter          string           // Default packet filter for all devices
	DeviceArgs             []DeviceArgument // Device specific arguments. Notice that dumpcap will always write PCAP-ng if more than one device is used.
	DisablePromiscuousMode bool             // Don't capture in promiscuous mode
	EnableGroupAccess      bool             // Enable group read access on the output file(s)
	EnableMonitorMode      bool             // Capture in monitor mode, if available. The device may lose all connections.
	FileFormat             uint8            // Use PCAP or PCAP-ng when writing files by default (See PCAPFormat, PCAPNGFormat).
	FileName               string           // Name of the file to save
	KernelBufferSize       uint64           // Default size of kernel buffer in MiB
	LinkLayerType          string           // Default link layer name to capture traffic on
	SnapshotLength         uint64           // Default packet snapshot length
	StopOnDuration         uint64           // Stop after this number of seconds
	StopOnFiles            uint64           // Stop after this number of files
	StopOnFilesize         uint64           // Stop after this number of KB written
	StopOnPacketCount      uint64           // Stop capturing after this number of packets
	SwitchOnDuration       uint64           // Switch to next file after this number of seconds
	SwitchOnFiles          uint64           // Replace after this number of files
	SwitchOnFilesize       uint64           // Switch to next file after this number of KB written
	UseThreads             bool             // Tell dumpcap to use a separate thread per interface
	WiFiChannel            string           // Set default channel on Wifi device. Given as "<freq>,[<type>]"
	command                string           // The command to execute
	childMode              bool             // Execute in child-mode
}

// buildArgs serializes a struct of Arguments into a []string ready to be
// passed as commandline arguments to dumpcap.
func (a Arguments) buildArgs() []string {
	r := []string{a.command}

	intArg := func(v uint64, a string) {
		if v != 0 {
			r = append(r, a, strconv.FormatUint(v, 10))
		}
	}
	prefixedIntArg := func(v uint64, a, prefix string) {
		if v != 0 {
			r = append(r, a, fmt.Sprintf(prefix+":%d", v))
		}
	}
	boolArg := func(v bool, a string) {
		if v {
			r = append(r, a)
		}
	}
	stringArg := func(s, a string) {
		if s != "" {
			r = append(r, a, s)
		}
	}

	if a.childMode {
		stringArg(pipeName, pipeOutputArg)
	}

	// Serialize global und default arguments first
	intArg(a.BufferedBytes, bufferedBytesArg)
	intArg(a.BufferedPackets, bufferedPacketsArg)
	stringArg(a.CaptureFilter, captureFilterArg)
	boolArg(a.DisablePromiscuousMode, disablePromiscuousArg)
	boolArg(a.EnableGroupAccess, enableGroupAccessArg)
	boolArg(a.EnableMonitorMode, enableMonitorModeArg)
	if a.FileFormat == UsePCAP {
		r = append(r, usePCAPArg)
	} else if a.FileFormat == UsePCAPNG {
		r = append(r, usePCAPNGArg)
	}
	stringArg(a.FileName, fileArg)
	intArg(a.KernelBufferSize, kernelBufferSizeArg)
	stringArg(a.LinkLayerType, linkLayerTypeArg)
	intArg(a.SnapshotLength, snaplenArg)
	prefixedIntArg(a.StopOnDuration, autoStopConditionArg, durationArg)
	prefixedIntArg(a.StopOnFiles, autoStopConditionArg, filesArg)
	prefixedIntArg(a.StopOnFilesize, autoStopConditionArg, filesizeArg)
	intArg(a.StopOnPacketCount, packetCountArg)
	prefixedIntArg(a.SwitchOnDuration, ringbufferArg, durationArg)
	prefixedIntArg(a.SwitchOnFiles, ringbufferArg, filesArg)
	prefixedIntArg(a.SwitchOnFilesize, ringbufferArg, filesizeArg)
	boolArg(a.UseThreads, useThreadsArg)
	stringArg(a.WiFiChannel, wifiChannelArg)

	// Device specific arguments come second
	for _, da := range a.DeviceArgs {
		if da.Name == "" {
			continue
		}
		// TODO name can be nil on windows, use number from Device instead ?!
		stringArg(da.Name, interfaceArg)
		boolArg(da.DisablePromiscuousMode, disablePromiscuousArg)
		boolArg(da.EnableMonitorMode, enableMonitorModeArg)
		intArg(da.KernelBufferSize, kernelBufferSizeArg)
		stringArg(da.LinkLayerType, linkLayerTypeArg)
		intArg(da.SnapshotLength, snaplenArg)
		stringArg(da.WiFiChannel, wifiChannelArg)
	}

	return r
}

// Version returns the first line "dumpcap -v" gives.
// The line usually takes the form "Dumpcap X.Y.Z (Git ...)".
func (d *Dumpcap) Version() (string, error) {
	buf, err := d.newCommand(d.Executable, versionCmd).Output()
	if err != nil {
		return "", err
	}
	return strings.SplitN(string(buf), "\n", 2)[0], nil
}

// VersionString returns the result of Version() or "unknown" in case of an
// error.
func (d *Dumpcap) VersionString() string {
	v, err := d.Version()
	if err != nil {
		return UnknownVersion
	}
	return v
}

// Capture represents a dumpcap subprocess capturing live traffic from a
// network device.
type Capture struct {
	child      commander
	stderr     io.ReadCloser
	Messages   chan PipeMessage
	exitStatus chan error
	quit       chan int
}

// NewCapture calls dumpcap to capture network data according to the given
// Arguments struct. Dumpcap is started immediatly, events are reported on
// Capture.Messages.
func (d *Dumpcap) NewCapture(args Arguments) (*Capture, error) {
	var err error
	args.command = captureCmd
	args.childMode = true

	c := Capture{}
	c.child = d.newCommand(d.Executable, args.buildArgs()...)
	c.stderr, err = c.child.StderrPipe()
	if err != nil {
		return nil, err
	}
	c.Messages = make(chan PipeMessage)
	c.exitStatus = make(chan error, 1)
	c.quit = make(chan int)

	if err = c.child.Start(); err != nil {
		return nil, err
	}

	go func() {
		defer close(c.Messages)
		defer close(c.exitStatus)

		for {
			msg, err := readPipeMsg(c.stderr)
			if err != nil {
				if _, ok := err.(*os.PathError); !ok && err != io.EOF {
					// os.PathError caused by us closing the pipe while reading
					// from it. This is not an error, dumpcap is about to exit.
					// EOF means pipe was closed by dumpcap, also not an error.
					c.exitStatus <- err
				}
				return
			}
			select {
			case c.Messages <- *msg:
			case <-c.quit:
				return
			}
		}
	}()

	return &c, nil
}

// Kill the dumpcap-process.
func (c Capture) Kill() error {
	return c.child.kill()
}

// Wait until dumpcap has stopped capturing network traffic and exited on
// it's own. Returns nil if and only if neither dumpcap nor the goroutine
// parsing it's output reported an error.
func (c Capture) Wait() error {
	err := c.child.Wait()
	if err != nil {
		return err
	}
	close(c.quit)
	return <-c.exitStatus
}

// Close the pipe receiving messages from dumpcap and causes it to quit.
func (c Capture) Close() {
	_ = c.stderr.Close()
}

// DeviceStatistics represents one line of statistics as reported by dumpcap.
type DeviceStatistics struct {
	Name        string // The name of the device reported on
	PacketCount uint64 // The number of packets seen on the device
	DropCount   uint64 // The number of packets dropped
}

func (ds DeviceStatistics) String() string {
	return fmt.Sprintf("%s\t%d\t%d", ds.Name, ds.PacketCount, ds.DropCount)
}

// Statistics reads the number of packets seen by dumpcap about once per second.
type Statistics struct {
	child      commander
	stdout     io.ReadCloser
	Stats      chan DeviceStatistics
	exitStatus chan error
	quit       chan int
}

func parseStatisticsLine(line string) (devname string, packetcount, dropcount uint64, err error) {
	cols := strings.SplitN(line, "\t", 3)
	if len(cols) != 3 {
		return "", 0, 0, errors.New("illegal output from dumpcap")
	}
	devname = cols[0]
	packetcount, err = strconv.ParseUint(cols[1], 10, 64)
	if err != nil {
		return "", 0, 0, err
	}
	dropcount, err = strconv.ParseUint(cols[2], 10, 64)
	return devname, packetcount, dropcount, err
}

// NewStatistics calls dumpcap to periodically report the number of packets
// seen on all known devices. Dumpcap starts immediatly, callers should receive
// from the returned Statistis.Stats-channel as soon as possible in order to
// avoid blocking dumpcap trying to write new data.
func (d *Dumpcap) NewStatistics() (*Statistics, error) {
	var err error
	stats := Statistics{}
	stats.child = d.newCommand(
		d.Executable,
		Arguments{command: statsCmd, childMode: true}.buildArgs()...)
	stats.stdout, err = stats.child.StdoutPipe()
	if err != nil {
		return nil, err
	}
	stats.Stats = make(chan DeviceStatistics)
	stats.exitStatus = make(chan error, 1)
	stats.quit = make(chan int)

	if err = stats.child.Start(); err != nil {
		return nil, err
	}

	go func() {
		defer close(stats.Stats)
		defer close(stats.exitStatus)
		scanner := bufio.NewScanner(stats.stdout)
		for scanner.Scan() {
			devname, packetcount, dropcount, err := parseStatisticsLine(scanner.Text())
			if err != nil {
				stats.exitStatus <- err
				return
			}
			ds := DeviceStatistics{devname, packetcount, dropcount}
			select {
			case stats.Stats <- ds:
			case <-stats.quit:
				return
			}

		}
		if err = scanner.Err(); err != nil {
			// os.PathError occurs if the pipe was Close()d while the scanner
			// is blocking. This is not an error if we closed it ourselves,
			// dumpcap will exit with process status 0
			_, ok := err.(*os.PathError)
			if !ok {
				stats.exitStatus <- err
			}
		}
	}()

	return &stats, nil
}

// Kill the dumpcap-process.
func (s Statistics) Kill() error {
	return s.child.kill()
}

// Wait until dumpcap has stopped reporting device statistics and exited on
// it's own. Returns nil if and only if neither dumpcap nor the goroutine
// parsing it's output reported an error.
func (s Statistics) Wait() error {
	err := s.child.Wait()
	if err != nil {
		return err
	}
	close(s.quit)
	return <-s.exitStatus
}

// Close the pipe receiving statistics from dumpcap and causes it to quit.
func (s Statistics) Close() {
	_ = s.stdout.Close()
}

// parseDeviceLine creates a Device struct from the []string produces by
// deviceListRE
func parseDevicesLine(fields []string) (dev *Device, err error) {
	dev = &Device{}
	if len(fields) != 8 {
		return nil, errors.New("illegal output from dumpcap")
	}

	i, err := strconv.ParseUint(fields[1], 10, 0)
	if err != nil {
		return nil, err
	}
	dev.Number = uint(i)

	dev.Name = fields[2]
	dev.VendorName = fields[3]
	dev.FriendlyName = fields[4]

	i, err = strconv.ParseUint(fields[5], 10, 8)
	if err != nil {
		return nil, err
	}
	dev.DevType = DeviceType(i)

	if fields[6] != "" {
		dev.Addresses = strings.Split(fields[6], ",")
	}
	dev.Loopback = fields[7] == "loopback"

	return dev, nil
}

// Devices calls dumpcap to receive a list of all devices capable of
// capturing network traffic.
// If getCapabilities is true, a second call to dumpcap is made for each device
// to find out about supported link-layer types (without trying to put the
// device into monitor-mode). If getCapabilities is false, the fields CanRFMon
// and LLTs on all returned Device structs will be empty.
func (d *Dumpcap) Devices(getCapabilities bool) ([]Device, error) {
	buf, err := d.newCommand(d.Executable, machineReadableArg, listDevicesCmd).Output()
	if err != nil {
		return nil, err
	}

	var devices []Device
	for _, fields := range deviceListRE.FindAllStringSubmatch(string(buf), -1) {
		dev, err := parseDevicesLine(fields)
		if err != nil {
			return nil, err
		}
		if getCapabilities {
			if err = d.Capabilities(dev, false); err != nil {
				return nil, err
			}
		}
		devices = append(devices, *dev)
	}
	return devices, nil
}

// parseCapabilities reads "dumpcap -L -Z"'s output from a Reader and
// constructs LinkLayerType structs from it.
func parseCapabilities(pipe io.Reader) (canRFMon bool, llts []LinkLayerType, err error) {
	scanner := bufio.NewScanner(pipe)

	if !scanner.Scan() {
		return canRFMon, nil, scanner.Err()
	}
	canRFMon = scanner.Text() == "1"

	for scanner.Scan() {
		cols := strings.SplitN(scanner.Text(), "\t", 3)
		if len(cols) != 3 {
			return canRFMon, nil, errors.New("illegal output from dumcap")
		}
		llt := LinkLayerType{}
		i, err := strconv.ParseUint(cols[0], 10, 0)
		if err != nil {
			return canRFMon, nil, err
		}
		llt.DLT = uint(i)
		llt.Name = cols[1]
		llt.Description = cols[2]
		llts = append(llts, llt)
	}
	return canRFMon, llts, scanner.Err()

}

// Capabilities makes a call to dumpcap to query the given device for supported
// link-layer types and support for capturing in monitor-mode. The results are
// written to the given Device struct.
// Dumpcap will try to put the device into monitor-mode if monitorMode is true;
// this may cause the device to lose all currently active connections.
func (d *Dumpcap) Capabilities(dev *Device, monitorMode bool) error {
	child := d.newCommand(d.Executable,
		Arguments{command: listLayersCmd, childMode: true,
			DeviceArgs: []DeviceArgument{{Name: dev.String(),
				EnableMonitorMode: monitorMode}}}.buildArgs()...)

	stdout, err := child.StdoutPipe()
	if err != nil {
		return err
	}
	stderr, err := child.StderrPipe()
	if err != nil {
		return err
	}
	if err = child.Start(); err != nil {
		return err
	}

	if err = waitForSuccessMsg(stderr); err != nil {
		return err
	}

	canRFMon, llts, err := parseCapabilities(stdout)
	if err != nil {
		return err
	}

	dev.CanRFMon = canRFMon
	dev.LLTs = llts

	return nil
}

// Version is a Convenience-function to execute Version() on a new Dumpcap-struct
func Version() (string, error) {
	return NewDumpcap().Version()
}

// VersionString is a convenience-function to execute VersionString() on a new Dumpcap-struct
func VersionString() string {
	return NewDumpcap().VersionString()
}

// NewCapture is a convenience-function to execute NewCapture() on a new Dumpcap-struct
func NewCapture(args Arguments) (*Capture, error) {
	return NewDumpcap().NewCapture(args)
}

// Capabilities is a convenience-function to execute Capabilities() on a new Dumpcap-struct
func Capabilities(dev *Device, monitorMode bool) error {
	return NewDumpcap().Capabilities(dev, monitorMode)
}

// NewStatistics is a convenience-function to execute NewStatistics() on a new Dumpcap-struct
func NewStatistics() (*Statistics, error) {
	return NewDumpcap().NewStatistics()
}

// Devices is a convenience-function to execute Devices() on a new Dumpcap-struct
func Devices(getCapabilities bool) ([]Device, error) {
	return NewDumpcap().Devices(getCapabilities)
}
