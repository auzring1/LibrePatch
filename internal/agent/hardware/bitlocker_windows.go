//go:build windows

package hardware

import (
	"runtime"
	"strings"
	"time"

	"github.com/go-ole/go-ole"
	"github.com/go-ole/go-ole/oleutil"
)

const bitlockerNamespace = `root\CIMV2\Security\MicrosoftVolumeEncryption`

// bitlockerStatus returns BitLocker state by drive ("C:"). ok is false when
// BitLocker management is unavailable (e.g. Windows Home) or WMI timed out.
// Values: protected | unprotected | encrypting | decrypting | unknown.
func bitlockerStatus() (map[string]string, bool) {
	type result struct {
		m  map[string]string
		ok bool
	}
	ch := make(chan result, 1)
	go func() {
		m, ok := queryBitlocker()
		ch <- result{m, ok}
	}()
	select {
	case r := <-ch:
		return r.m, r.ok
	case <-time.After(20 * time.Second):
		return nil, false
	}
}

func queryBitlocker() (map[string]string, bool) {
	// COM objects must be created and used on one OS thread.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if err := ole.CoInitializeEx(0, ole.COINIT_MULTITHREADED); err != nil {
		// S_FALSE (already initialized) is reported as an error by go-ole; carry on.
		if oe, isOle := err.(*ole.OleError); !isOle || oe.Code() != 1 {
			return nil, false
		}
	}
	defer ole.CoUninitialize()

	unknown, err := oleutil.CreateObject("WbemScripting.SWbemLocator")
	if err != nil {
		return nil, false
	}
	defer unknown.Release()
	locator, err := unknown.QueryInterface(ole.IID_IDispatch)
	if err != nil {
		return nil, false
	}
	defer locator.Release()
	svcV, err := oleutil.CallMethod(locator, "ConnectServer", nil, bitlockerNamespace)
	if err != nil {
		return nil, false // namespace missing: BitLocker not supported on this edition
	}
	svc := svcV.ToIDispatch()
	defer svc.Release()
	resV, err := oleutil.CallMethod(svc, "ExecQuery", "SELECT DriveLetter, ProtectionStatus, ConversionStatus FROM Win32_EncryptableVolume")
	if err != nil {
		return nil, false
	}
	res := resV.ToIDispatch()
	defer res.Release()
	countV, err := oleutil.GetProperty(res, "Count")
	if err != nil {
		return nil, false
	}
	out := map[string]string{}
	n := int(countV.Val)
	for i := 0; i < n && i < 64; i++ {
		itemV, err := oleutil.CallMethod(res, "ItemIndex", i)
		if err != nil {
			continue
		}
		item := itemV.ToIDispatch()
		letter := propString(item, "DriveLetter")
		prot := propInt(item, "ProtectionStatus")
		conv := propInt(item, "ConversionStatus")
		item.Release()
		if letter == "" {
			continue
		}
		out[strings.ToUpper(letter)] = classify(prot, conv)
	}
	return out, true
}

func classify(protection, conversion int64) string {
	switch {
	case conversion == 2 || conversion == 4:
		return "encrypting"
	case conversion == 3 || conversion == 5:
		return "decrypting"
	case protection == 1:
		return "protected"
	case protection == 0:
		return "unprotected"
	}
	return "unknown"
}

func propString(d *ole.IDispatch, name string) string {
	v, err := oleutil.GetProperty(d, name)
	if err != nil || v.Value() == nil {
		return ""
	}
	s, _ := v.Value().(string)
	return s
}

func propInt(d *ole.IDispatch, name string) int64 {
	v, err := oleutil.GetProperty(d, name)
	if err != nil {
		return -1
	}
	switch x := v.Value().(type) {
	case int32:
		return int64(x)
	case int64:
		return x
	case uint32:
		return int64(x)
	case int8:
		return int64(x)
	case uint8:
		return int64(x)
	case int16:
		return int64(x)
	}
	return -1
}
