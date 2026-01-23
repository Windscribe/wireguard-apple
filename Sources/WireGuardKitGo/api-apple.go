/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2018-2019 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

package main

// #include <stdlib.h>
// #include <sys/types.h>
// static void callLogger(void *func, void *ctx, int level, const char *msg)
// {
// 	((void(*)(void *, int, const char *))func)(ctx, level, msg);
// }
import "C"

import (
	"fmt"
	"io"
	"math"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"runtime"
	"runtime/debug"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

var loggerFunc unsafe.Pointer
var loggerCtx unsafe.Pointer

type CLogger int

func cstring(s string) *C.char {
	b, err := unix.BytePtrFromString(s)
	if err != nil {
		b := [1]C.char{}
		return &b[0]
	}
	return (*C.char)(unsafe.Pointer(b))
}

func (l CLogger) Printf(format string, args ...interface{}) {
	if uintptr(loggerFunc) == 0 {
		return
	}
	C.callLogger(loggerFunc, loggerCtx, C.int(l), cstring(fmt.Sprintf(format, args...)))
}

type tunnelHandle struct {
	*device.Device
	*device.Logger
}

var tunnelHandles = make(map[int32]tunnelHandle)

var checkIPClient *http.Client
var checkIPDevice *device.Device
var checkIPLogger *device.Logger

func init() {
	signals := make(chan os.Signal)
	signal.Notify(signals, unix.SIGUSR2)
	go func() {
		buf := make([]byte, os.Getpagesize())
		for {
			select {
			case <-signals:
				n := runtime.Stack(buf, true)
				buf[n] = 0
				if uintptr(loggerFunc) != 0 {
					C.callLogger(loggerFunc, loggerCtx, 0, (*C.char)(unsafe.Pointer(&buf[0])))
				}
			}
		}
	}()
}

//export wgSetLogger
func wgSetLogger(context, loggerFn uintptr) {
	loggerCtx = unsafe.Pointer(context)
	loggerFunc = unsafe.Pointer(loggerFn)
}

//export wgTurnOn
func wgTurnOn(settings *C.char, tunFd int32) int32 {
	logger := &device.Logger{
		Verbosef: CLogger(0).Printf,
		Errorf:   CLogger(1).Printf,
	}
	dupTunFd, err := unix.Dup(int(tunFd))
	if err != nil {
		logger.Errorf("Unable to dup tun fd: %v", err)
		return -1
	}

	err = unix.SetNonblock(dupTunFd, true)
	if err != nil {
		logger.Errorf("Unable to set tun fd as non blocking: %v", err)
		unix.Close(dupTunFd)
		return -1
	}
	tun, err := tun.CreateTUNFromFile(os.NewFile(uintptr(dupTunFd), "/dev/tun"), 0)
	if err != nil {
		logger.Errorf("Unable to create new tun device from fd: %v", err)
		unix.Close(dupTunFd)
		return -1
	}
	logger.Verbosef("Attaching to interface")
	dev := device.NewDevice(tun, conn.NewStdNetBind(), logger)

	err = dev.IpcSet(C.GoString(settings))
	if err != nil {
		logger.Errorf("Unable to set IPC settings: %v", err)
		unix.Close(dupTunFd)
		return -1
	}

	dev.Up()
	logger.Verbosef("Device started")

	var i int32
	for i = 0; i < math.MaxInt32; i++ {
		if _, exists := tunnelHandles[i]; !exists {
			break
		}
	}
	if i == math.MaxInt32 {
		unix.Close(dupTunFd)
		return -1
	}
	tunnelHandles[i] = tunnelHandle{dev, logger}
	return i
}

//export wgTurnOff
func wgTurnOff(tunnelHandle int32) {
	dev, ok := tunnelHandles[tunnelHandle]
	if !ok {
		return
	}
	delete(tunnelHandles, tunnelHandle)
	dev.Close()
}

//export wgSetConfig
func wgSetConfig(tunnelHandle int32, settings *C.char) int64 {
	dev, ok := tunnelHandles[tunnelHandle]
	if !ok {
		return 0
	}
	err := dev.IpcSet(C.GoString(settings))
	if err != nil {
		dev.Errorf("Unable to set IPC settings: %v", err)
		if ipcErr, ok := err.(*device.IPCError); ok {
			return ipcErr.ErrorCode()
		}
		return -1
	}
	return 0
}

//export wgGetConfig
func wgGetConfig(tunnelHandle int32) *C.char {
	device, ok := tunnelHandles[tunnelHandle]
	if !ok {
		return nil
	}
	settings, err := device.IpcGet()
	if err != nil {
		return nil
	}
	return C.CString(settings)
}

//export wgBumpSockets
func wgBumpSockets(tunnelHandle int32) {
	dev, ok := tunnelHandles[tunnelHandle]
	if !ok {
		return
	}
	go func() {
		for i := 0; i < 10; i++ {
			err := dev.BindUpdate()
			if err == nil {
				dev.SendKeepalivesToPeersWithCurrentKeypair()
				return
			}
			dev.Errorf("Unable to update bind, try %d: %v", i+1, err)
			time.Sleep(time.Second / 2)
		}
		dev.Errorf("Gave up trying to update bind; tunnel is likely dysfunctional")
	}()
}

//export wgDisableSomeRoamingForBrokenMobileSemantics
func wgDisableSomeRoamingForBrokenMobileSemantics(tunnelHandle int32) {
	dev, ok := tunnelHandles[tunnelHandle]
	if !ok {
		return
	}
	dev.DisableSomeRoamingForBrokenMobileSemantics()
}

//export wgVersion
func wgVersion() *C.char {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return C.CString("unknown")
	}
	for _, dep := range info.Deps {
		if dep.Path == "golang.zx2c4.com/wireguard" {
			parts := strings.Split(dep.Version, "-")
			if len(parts) == 3 && len(parts[2]) == 12 {
				return C.CString(parts[2][:7])
			}
			return C.CString(dep.Version)
		}
	}
	return C.CString("unknown")
}

//export wgSetupCheckIPTunnel
func wgSetupCheckIPTunnel(localIP *C.char, dnsServer *C.char, settings *C.char) int32 {
	// Create logger that uses the existing global logger
	checkIPLogger = &device.Logger{
		Verbosef: CLogger(0).Printf,
		Errorf:   CLogger(1).Printf,
	}

	checkIPLogger.Verbosef("[CheckIP] Starting setup...")

	localIPStr := C.GoString(localIP)
	dnsStr := C.GoString(dnsServer)
	settingsStr := C.GoString(settings)

	checkIPLogger.Verbosef("[CheckIP] Local IP: %s", localIPStr)
	checkIPLogger.Verbosef("[CheckIP] DNS Server: %s", dnsStr)
	checkIPLogger.Verbosef("[CheckIP] Config length: %d bytes", len(settingsStr))

	// Parse IP addresses
	localAddr, err := netip.ParseAddr(localIPStr)
	if err != nil {
		checkIPLogger.Errorf("[CheckIP] Invalid local IP: %v", err)
		return -1
	}
	checkIPLogger.Verbosef("[CheckIP] Parsed local IP successfully")

	dnsAddr, err := netip.ParseAddr(dnsStr)
	if err != nil {
		checkIPLogger.Errorf("[CheckIP] Invalid DNS IP: %v", err)
		return -2
	}
	checkIPLogger.Verbosef("[CheckIP] Parsed DNS IP successfully")

	// Create netstack TUN
	checkIPLogger.Verbosef("[CheckIP] Creating netstack TUN device...")
	tun, tnet, err := netstack.CreateNetTUN(
		[]netip.Addr{localAddr},
		[]netip.Addr{dnsAddr},
		1420)
	if err != nil {
		checkIPLogger.Errorf("[CheckIP] Failed to create netstack TUN: %v", err)
		return -3
	}
	checkIPLogger.Verbosef("[CheckIP] Netstack TUN created successfully")

	// Create WireGuard device
	checkIPLogger.Verbosef("[CheckIP] Creating WireGuard device...")
	checkIPDevice = device.NewDevice(tun, conn.NewDefaultBind(), checkIPLogger)
	checkIPLogger.Verbosef("[CheckIP] WireGuard device created")

	// Set configuration
	checkIPLogger.Verbosef("[CheckIP] Setting WireGuard configuration...")
	err = checkIPDevice.IpcSet(settingsStr)
	if err != nil {
		checkIPLogger.Errorf("[CheckIP] Unable to set IPC settings: %v", err)
		return -4
	}
	checkIPLogger.Verbosef("[CheckIP] Configuration set successfully")

	// Bring device up
	checkIPLogger.Verbosef("[CheckIP] Bringing device up...")
	err = checkIPDevice.Up()
	if err != nil {
		checkIPLogger.Errorf("[CheckIP] Unable to bring device up: %v", err)
		return -5
	}
	checkIPLogger.Verbosef("[CheckIP] Device is UP")

	// Create HTTP client using netstack
	checkIPLogger.Verbosef("[CheckIP] Creating HTTP client with netstack...")
	checkIPClient = &http.Client{
		Transport: &http.Transport{
			DialContext: tnet.DialContext,
		},
		Timeout: 30 * time.Second, // Increased timeout
	}
	checkIPLogger.Verbosef("[CheckIP] HTTP client created")

	checkIPLogger.Verbosef("[CheckIP] Setup complete, waiting 2s for initial handshake...")
	// Give the device a moment to complete handshake
	time.Sleep(2 * time.Second)
	checkIPLogger.Verbosef("[CheckIP] Ready for requests")

	return 0
}

//export wgCheckIP
func wgCheckIP() *C.char {
	if checkIPLogger == nil {
		checkIPLogger = &device.Logger{
			Verbosef: CLogger(0).Printf,
			Errorf:   CLogger(1).Printf,
		}
	}

	checkIPLogger.Verbosef("[CheckIP] Request started")

	if checkIPClient == nil {
		checkIPLogger.Errorf("[CheckIP] ERROR: HTTP client not initialized")
		return C.CString("error: tunnel not initialized")
	}
	checkIPLogger.Verbosef("[CheckIP] HTTP client OK")

	if checkIPDevice == nil {
		checkIPLogger.Errorf("[CheckIP] ERROR: Device not initialized")
		return C.CString("error: device not initialized")
	}
	checkIPLogger.Verbosef("[CheckIP] Device OK")

	// The device is automatically brought up during setup, so we don't need to check
	// We can verify by trying to get the config (which will fail if device is not ready)
	checkIPLogger.Verbosef("[CheckIP] Device is ready")

	// Get device status
	if config, err := checkIPDevice.IpcGet(); err == nil {
		if strings.Contains(config, "last_handshake_time_sec") {
			checkIPLogger.Verbosef("[CheckIP] Handshake status found in config")
		} else {
			checkIPLogger.Verbosef("[CheckIP] WARNING: No handshake timestamp in config yet")
		}
	}

	checkIPLogger.Verbosef("[CheckIP] Initiating HTTP GET to https://checkip.windscribe.com")

	resp, err := checkIPClient.Get("https://checkip.windscribe.com")
	if err != nil {
		checkIPLogger.Errorf("[CheckIP] HTTP request FAILED: %v", err)
		return C.CString(fmt.Sprintf("error: %v", err))
	}
	defer resp.Body.Close()

	checkIPLogger.Verbosef("[CheckIP] HTTP response received!")
	checkIPLogger.Verbosef("[CheckIP] Status: %s", resp.Status)
	checkIPLogger.Verbosef("[CheckIP] Status Code: %d", resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		checkIPLogger.Errorf("[CheckIP] Failed to read response body: %v", err)
		return C.CString(fmt.Sprintf("error reading response: %v", err))
	}

	checkIPLogger.Verbosef("[CheckIP] Response body length: %d bytes", len(body))

	// Return the IP address as a string
	ip := strings.TrimSpace(string(body))
	checkIPLogger.Verbosef("[CheckIP] ✅ SUCCESS! Received IP: %s", ip)
	return C.CString(ip)
}

//export wgCheckIPWaitForHandshake
func wgCheckIPWaitForHandshake(timeoutSecs int32) int32 {
	if checkIPLogger == nil {
		checkIPLogger = &device.Logger{
			Verbosef: CLogger(0).Printf,
			Errorf:   CLogger(1).Printf,
		}
	}

	if checkIPDevice == nil {
		checkIPLogger.Errorf("[CheckIP] ERROR: Cannot wait for handshake, device is nil")
		return -1
	}

	timeout := time.Duration(timeoutSecs) * time.Second
	deadline := time.Now().Add(timeout)

	checkIPLogger.Verbosef("[CheckIP] Waiting for handshake completion (timeout: %d seconds)", timeoutSecs)

	attempt := 0
	for time.Now().Before(deadline) {
		attempt++
		checkIPLogger.Verbosef("[CheckIP] Handshake check attempt %d", attempt)

		// Try to get config to see if handshake completed
		config, err := checkIPDevice.IpcGet()
		if err != nil {
			checkIPLogger.Verbosef("[CheckIP] Could not get config: %v", err)
		} else {
			checkIPLogger.Verbosef("[CheckIP] Got config, length: %d bytes", len(config))

			if strings.Contains(config, "last_handshake_time_sec") {
				// Extract the handshake time for logging
				lines := strings.Split(config, "\n")
				for _, line := range lines {
					if strings.Contains(line, "last_handshake_time_sec") {
						checkIPLogger.Verbosef("[CheckIP] Found: %s", line)
					}
				}
				checkIPLogger.Verbosef("[CheckIP] ✅ Handshake completed!")
				return 0
			} else {
				checkIPLogger.Verbosef("[CheckIP] No handshake timestamp found yet, waiting...")
			}
		}

		time.Sleep(500 * time.Millisecond)
	}

	checkIPLogger.Errorf("[CheckIP] ❌ Handshake TIMEOUT after %d seconds (%d attempts)", timeoutSecs, attempt)
	return -2
}

//export wgCleanupCheckIPTunnel
func wgCleanupCheckIPTunnel() {
	if checkIPLogger != nil {
		checkIPLogger.Verbosef("[CheckIP] Cleanup started")
	}

	if checkIPDevice != nil {
		if checkIPLogger != nil {
			checkIPLogger.Verbosef("[CheckIP] Closing WireGuard device...")
		}
		checkIPDevice.Close()
		if checkIPLogger != nil {
			checkIPLogger.Verbosef("[CheckIP] Device closed")
		}
		checkIPDevice = nil
	}

	if checkIPClient != nil {
		if checkIPLogger != nil {
			checkIPLogger.Verbosef("[CheckIP] Cleaning up HTTP client")
		}
		checkIPClient = nil
	}

	if checkIPLogger != nil {
		checkIPLogger.Verbosef("[CheckIP] ✅ Cleanup complete")
		checkIPLogger = nil
	}
}

func main() {}
