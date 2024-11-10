package main

import "C"
import (
	"github.com/Control-D-Inc/ctrld/cmd/cli"
	"sync"
)

var (
	controller  *Controller
	hostName    *string
	lanIp       *string
	macAddress  *string
	metaDataMux sync.Mutex // Mutex for thread safety
)

// Controller holds global state
type Controller struct {
	stopCh chan struct{}
	Config cli.AppConfig
}

// NewController provides reference to global state to be managed by android vpn service and iOS network extension.
// reference is not safe for concurrent use.
func NewController() *Controller {
	return &Controller{}
}

//export SetMetaData
func SetMetaData(newHostName, newLanIp, newMacAddress string) {
	metaDataMux.Lock()
	defer metaDataMux.Unlock()

	hostName = &newHostName
	lanIp = &newLanIp
	macAddress = &newMacAddress
}

func safeString(s *string) string {
	metaDataMux.Lock()
	defer metaDataMux.Unlock()
	if s == nil {
		return ""
	}
	return *s
}

//export StartCd
func StartCd(CdUID, HomeDir, UpstreamProto string, logLevel int, logPath string) {
	if controller != nil {
		return
	}
	controller = NewController()
	callback := cli.AppCallback{
		HostName: func() string {
			return safeString(hostName)
		},
		LanIp: func() string {
			return safeString(lanIp)
		},
		MacAddress: func() string {
			return safeString(macAddress)
		},
		Exit: func(err string) {
			// Handle exit callback if needed
		},
	}
	if controller.stopCh == nil {
		controller.stopCh = make(chan struct{})
		controller.Config = cli.AppConfig{
			CdUID:         CdUID,
			HomeDir:       HomeDir,
			UpstreamProto: UpstreamProto,
			Verbose:       logLevel,
			LogPath:       logPath,
		}
		cli.RunMobile(&controller.Config, &callback, controller.stopCh)
	}
}

//export StopCd
func StopCd(restart bool, pin int64) int {
	if controller == nil {
		return 0
	}
	var errorCode = 0
	// Force disconnect without checking pin.
	// In iOS restart is required if vpn detects no connectivity after network change.
	if !restart {
		errorCode = cli.CheckDeactivationPin(pin, controller.stopCh)
	}
	if errorCode == 0 && controller.stopCh != nil {
		close(controller.stopCh)
		controller.stopCh = nil
	}
	controller = nil
	return errorCode
}

//export IsCdRunning
func IsCdRunning() bool {
	return controller != nil && controller.stopCh != nil
}
