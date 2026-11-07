//go:build windows

package wu

import (
	"context"
	"fmt"
	"github.com/auzring1/librepatch/internal/shared/brand"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/go-ole/go-ole"
	"github.com/go-ole/go-ole/oleutil"

	agentv1 "github.com/auzring1/librepatch/gen/proto/librepatch/agent/v1"
)

// Windows Update Agent over COM (https://learn.microsoft.com/windows/win32/wua_sdk/). COM objects
// are created and used on one locked OS thread per operation, in the multithreaded apartment.

const (
	ssDefault       = 0 // ServerSelection: the machine's configured source (WSUS when policy sets one)
	ssWindowsUpdate = 2
	ssOthers        = 3 // with ServiceID

	microsoftUpdateServiceID = "7971f918-a847-4430-9279-4a52d1efe18d"

	orcSucceeded           = 2
	orcSucceededWithErrors = 3
)

// New returns the Windows implementation. dataDir is unused here (kept so both builds share a signature).
func NewClient(string) Client { return &wuaClient{} }

type wuaClient struct{ mu sync.Mutex } // WUA operations are serialized

// com runs f on a dedicated COM thread and returns when it finishes or ctx ends. A WUA call that
// is already running cannot be interrupted; on cancellation it finishes in the background.
func com(ctx context.Context, f func() error) error {
	done := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		if err := ole.CoInitializeEx(0, ole.COINIT_MULTITHREADED); err != nil {
			if oe, ok := err.(*ole.OleError); !ok || oe.Code() != 1 { // S_FALSE: already initialized
				done <- fmt.Errorf("%w: COM initialization failed: %v", ErrUnavailable, err)
				return
			}
		}
		defer ole.CoUninitialize()
		done <- f()
	}()
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

// disp is a COM dispatch object that remembers what to release.
type disp struct{ rel []*ole.IDispatch }

func (d *disp) release() {
	for i := len(d.rel) - 1; i >= 0; i-- {
		d.rel[i].Release()
	}
}

func (d *disp) create(prog string) (*ole.IDispatch, error) {
	u, err := oleutil.CreateObject(prog)
	if err != nil {
		return nil, fmt.Errorf("%w: cannot create %s: %v", ErrUnavailable, prog, err)
	}
	defer u.Release()
	x, err := u.QueryInterface(ole.IID_IDispatch)
	if err != nil {
		return nil, err
	}
	d.rel = append(d.rel, x)
	return x, nil
}

func (d *disp) call(o *ole.IDispatch, method string, args ...any) (*ole.IDispatch, error) {
	v, err := oleutil.CallMethod(o, method, args...)
	if err != nil {
		return nil, err
	}
	if v.VT != ole.VT_DISPATCH || v.Val == 0 {
		return nil, nil
	}
	x := v.ToIDispatch()
	d.rel = append(d.rel, x)
	return x, nil
}

func (d *disp) prop(o *ole.IDispatch, name string, args ...any) (*ole.IDispatch, error) {
	v, err := oleutil.GetProperty(o, name, args...)
	if err != nil {
		return nil, err
	}
	if v.VT != ole.VT_DISPATCH || v.Val == 0 {
		return nil, nil
	}
	x := v.ToIDispatch()
	d.rel = append(d.rel, x)
	return x, nil
}

func str(o *ole.IDispatch, name string) string {
	v, err := oleutil.GetProperty(o, name)
	if err != nil {
		return ""
	}
	defer v.Clear()
	if s, ok := v.Value().(string); ok {
		return s
	}
	return ""
}

func boolean(o *ole.IDispatch, name string) bool {
	v, err := oleutil.GetProperty(o, name)
	if err != nil {
		return false
	}
	defer v.Clear()
	b, _ := v.Value().(bool)
	return b
}

func integer(o *ole.IDispatch, name string) int64 {
	v, err := oleutil.GetProperty(o, name)
	if err != nil {
		return 0
	}
	defer v.Clear()
	return v.Val
}

func count(o *ole.IDispatch) int {
	if o == nil {
		return 0
	}
	return int(integer(o, "Count"))
}

func (c *wuaClient) searcher(d *disp, session *ole.IDispatch, o Options) (*ole.IDispatch, error) {
	s, err := d.call(session, "CreateUpdateSearcher")
	if err != nil || s == nil {
		return nil, fmt.Errorf("%w: cannot create the update searcher: %v", ErrUnavailable, err)
	}
	switch o.Service {
	case agentv1.WuService_WU_SERVICE_WINDOWS_UPDATE:
		_, err = oleutil.PutProperty(s, "ServerSelection", ssWindowsUpdate)
	case agentv1.WuService_WU_SERVICE_MICROSOFT_UPDATE:
		if err = registerMicrosoftUpdate(d); err == nil {
			if _, err = oleutil.PutProperty(s, "ServerSelection", ssOthers); err == nil {
				_, err = oleutil.PutProperty(s, "ServiceID", microsoftUpdateServiceID)
			}
		}
	default:
		_, err = oleutil.PutProperty(s, "ServerSelection", ssDefault)
	}
	if err != nil {
		return nil, fmt.Errorf("%w: cannot select the update service: %v", ErrUnavailable, err)
	}
	return s, nil
}

// registerMicrosoftUpdate makes sure the Microsoft Update service is known to the machine.
func registerMicrosoftUpdate(d *disp) error {
	mgr, err := d.create("Microsoft.Update.ServiceManager")
	if err != nil {
		return err
	}
	svcs, err := d.prop(mgr, "Services")
	if err != nil {
		return err
	}
	for i := 0; i < count(svcs); i++ {
		it, err := d.prop(svcs, "Item", i)
		if err == nil && it != nil && strings.EqualFold(str(it, "ServiceID"), microsoftUpdateServiceID) {
			return nil
		}
	}
	// asfAllowPendingRegistration | asfAllowOnlineRegistration | asfRegisterServiceWithAU
	_, err = d.call(mgr, "AddService2", microsoftUpdateServiceID, 7, "")
	return err
}

func (c *wuaClient) search(d *disp, s *ole.IDispatch, criteria string) (*ole.IDispatch, error) {
	r, err := d.call(s, "Search", criteria)
	if err != nil || r == nil {
		return nil, fmt.Errorf("%w: update search failed: %v", ErrUnavailable, err)
	}
	return d.prop(r, "Updates")
}

func stringsOf(d *disp, o *ole.IDispatch, prop string) []string {
	col, err := d.prop(o, prop)
	if err != nil || col == nil {
		return nil
	}
	var out []string
	for i := 0; i < count(col) && i < 32; i++ {
		v, err := oleutil.GetProperty(col, "Item", i)
		if err != nil {
			continue
		}
		if s, ok := v.Value().(string); ok {
			out = append(out, s)
		}
		_ = v.Clear() // release only; nothing to recover from
	}
	return out
}

func toProto(d *disp, u *ole.IDispatch, state agentv1.WuUpdateState) *agentv1.WuUpdate {
	out := &agentv1.WuUpdate{Title: bound(str(u, "Title"), 512), State: state, Severity: normSeverity(str(u, "MsrcSeverity")),
		SupportUrl: bound(str(u, "SupportUrl"), 512), Kb: stringsOf(d, u, "KBArticleIDs")}
	if id, err := d.prop(u, "Identity"); err == nil && id != nil {
		out.UpdateId = strings.ToLower(str(id, "UpdateID"))
		out.Revision = int32(integer(id, "RevisionNumber")) // #nosec G115 -- small
	}
	if v, err := oleutil.GetProperty(u, "LastDeploymentChangeTime"); err == nil {
		if t, ok := v.Value().(time.Time); ok {
			out.ReleaseDate = t.Unix()
		}
		_ = v.Clear() // release only; nothing to recover from
	}
	out.IsDriver = integer(u, "Type") == 2
	out.RebootRequired = integer(u, "RebootBehavior") != 0
	if cats, err := d.prop(u, "Categories"); err == nil && cats != nil {
		for i := 0; i < count(cats) && i < 32; i++ {
			c, err := d.prop(cats, "Item", i)
			if err != nil || c == nil {
				continue
			}
			switch str(c, "Type") {
			case "UpdateClassification":
				if out.Classification == "" {
					out.Classification = str(c, "Name")
				}
			case "Product":
				out.Products = append(out.Products, str(c, "Name"))
			}
		}
	}
	if out.IsDriver {
		out.DriverClass = str(u, "DriverClass")
		out.DriverHwid = str(u, "DriverHardwareID")
		out.DriverVersion = bound(str(u, "DriverModel"), 128)
		if out.Classification == "" {
			out.Classification = "Drivers"
		}
	}
	return out
}

func normSeverity(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical":
		return "Critical"
	case "important":
		return "Important"
	case "moderate":
		return "Moderate"
	case "low":
		return "Low"
	}
	return ""
}

func (c *wuaClient) Scan(ctx context.Context, o Options) ([]*agentv1.WuUpdate, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []*agentv1.WuUpdate
	err := com(ctx, func() error {
		d := &disp{}
		defer d.release()
		session, err := d.create("Microsoft.Update.Session")
		if err != nil {
			return err
		}
		_, _ = oleutil.PutProperty(session, "ClientApplicationID", brand.Name)
		s, err := c.searcher(d, session, o)
		if err != nil {
			return err
		}
		seen := map[string]bool{}
		collect := func(criteria string, state func(*ole.IDispatch) agentv1.WuUpdateState) error {
			col, err := c.search(d, s, criteria)
			if err != nil {
				return err
			}
			for i := 0; i < count(col) && len(out) < MaxUpdates+1; i++ {
				u, err := d.prop(col, "Item", i)
				if err != nil || u == nil {
					continue
				}
				p := toProto(d, u, state(u))
				if p.UpdateId == "" || seen[p.UpdateId] || (p.IsDriver && !o.IncludeDrivers) {
					continue
				}
				seen[p.UpdateId] = true
				out = append(out, p)
			}
			return nil
		}
		missing := func(u *ole.IDispatch) agentv1.WuUpdateState {
			if boolean(u, "IsDownloaded") {
				return agentv1.WuUpdateState_WU_UPDATE_STATE_DOWNLOADED
			}
			return agentv1.WuUpdateState_WU_UPDATE_STATE_MISSING
		}
		if err := collect("IsInstalled=0 and IsHidden=0 and Type='Software'", missing); err != nil {
			return err
		}
		if o.IncludeDrivers {
			if err := collect("IsInstalled=0 and IsHidden=0 and Type='Driver'", missing); err != nil {
				return err
			}
		}
		// Secondary queries are best effort: a failure here must not hide the main result.
		_ = collect("IsInstalled=0 and IsHidden=1", func(*ole.IDispatch) agentv1.WuUpdateState { return agentv1.WuUpdateState_WU_UPDATE_STATE_HIDDEN })
		_ = collect("IsInstalled=1 and RebootRequired=1", func(*ole.IDispatch) agentv1.WuUpdateState {
			return agentv1.WuUpdateState_WU_UPDATE_STATE_PENDING_REBOOT
		})
		return nil
	})
	return out, err
}

// find returns the scan results for the wanted update IDs (software and, if allowed, drivers).
func (c *wuaClient) find(d *disp, session *ole.IDispatch, o Options, want map[string]int32) (map[string]*ole.IDispatch, error) {
	s, err := c.searcher(d, session, o)
	if err != nil {
		return nil, err
	}
	found := map[string]*ole.IDispatch{}
	crit := []string{"IsInstalled=0 and IsHidden=0 and Type='Software'"}
	if o.IncludeDrivers {
		crit = append(crit, "IsInstalled=0 and IsHidden=0 and Type='Driver'")
	}
	for _, cr := range crit {
		col, err := c.search(d, s, cr)
		if err != nil {
			return nil, err
		}
		for i := 0; i < count(col); i++ {
			u, err := d.prop(col, "Item", i)
			if err != nil || u == nil {
				continue
			}
			id, err := d.prop(u, "Identity")
			if err != nil || id == nil {
				continue
			}
			uid := strings.ToLower(str(id, "UpdateID"))
			if rev, ok := want[uid]; ok && (rev == 0 || rev == int32(integer(id, "RevisionNumber"))) { // #nosec G115 -- small
				found[uid] = u
			}
		}
	}
	return found, nil
}

func (c *wuaClient) Install(ctx context.Context, o Options, refs []*agentv1.WuUpdateRef) (*InstallResult, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	res := &InstallResult{}
	err := com(ctx, func() error {
		d := &disp{}
		defer d.release()
		session, err := d.create("Microsoft.Update.Session")
		if err != nil {
			return err
		}
		_, _ = oleutil.PutProperty(session, "ClientApplicationID", brand.Name)
		want := map[string]int32{}
		for _, r := range refs {
			want[strings.ToLower(r.UpdateId)] = r.Revision
		}
		found, err := c.find(d, session, o, want)
		if err != nil {
			return err
		}
		coll, err := d.create("Microsoft.Update.UpdateColl")
		if err != nil {
			return err
		}
		order := []string{}
		for _, r := range refs {
			uid := strings.ToLower(r.UpdateId)
			u := found[uid]
			if u == nil {
				res.Results = append(res.Results, &agentv1.WuUpdateResult{UpdateId: r.UpdateId, Revision: r.Revision, Result: agentv1.WuResult_WU_RESULT_NOT_APPLICABLE})
				continue
			}
			if !boolean(u, "EulaAccepted") {
				_, _ = oleutil.CallMethod(u, "AcceptEula")
			}
			if _, err := oleutil.CallMethod(coll, "Add", u); err != nil {
				return fmt.Errorf("cannot queue update %s: %v", r.UpdateId, err)
			}
			order = append(order, uid)
		}
		if len(order) == 0 {
			return nil
		}
		res.Log = fmt.Sprintf("%d update(s) found", len(order))
		// Download.
		dl, err := d.call(session, "CreateUpdateDownloader")
		if err != nil || dl == nil {
			return fmt.Errorf("%w: cannot create the downloader: %v", ErrUnavailable, err)
		}
		if _, err := oleutil.PutProperty(dl, "Updates", coll); err != nil {
			return err
		}
		dres, err := d.call(dl, "Download")
		if err != nil {
			return fmt.Errorf("download failed: %v", err)
		}
		downloaded, err := d.create("Microsoft.Update.UpdateColl")
		if err != nil {
			return err
		}
		okIdx := map[int]bool{}
		for i, uid := range order {
			ur, err := d.call(dres, "GetUpdateResult", i)
			code, hr := int64(0), int32(0)
			if err == nil && ur != nil {
				code, hr = integer(ur, "ResultCode"), int32(integer(ur, "HResult")) // #nosec G115 -- HRESULT wraps
			}
			if code == orcSucceeded || code == orcSucceededWithErrors {
				u, _ := d.prop(coll, "Item", i)
				if u != nil {
					_, _ = oleutil.CallMethod(downloaded, "Add", u)
					okIdx[i] = true
				}
				continue
			}
			res.Results = append(res.Results, &agentv1.WuUpdateResult{UpdateId: uid, Revision: want[uid], Result: agentv1.WuResult_WU_RESULT_DOWNLOAD_FAILED, Hresult: hr})
		}
		if len(okIdx) == 0 {
			return nil
		}
		// Install.
		inst, err := d.call(session, "CreateUpdateInstaller")
		if err != nil || inst == nil {
			return fmt.Errorf("%w: cannot create the installer: %v", ErrUnavailable, err)
		}
		_, _ = oleutil.PutProperty(inst, "ForceQuiet", true)
		_, _ = oleutil.PutProperty(inst, "AllowSourcePrompts", false)
		if _, err := oleutil.PutProperty(inst, "Updates", downloaded); err != nil {
			return err
		}
		ires, err := d.call(inst, "Install")
		if err != nil {
			return fmt.Errorf("install failed: %v", err)
		}
		res.RebootRequired = boolean(ires, "RebootRequired")
		n := 0
		for i, uid := range order {
			if !okIdx[i] {
				continue
			}
			ur, err := d.call(ires, "GetUpdateResult", n)
			n++
			r := &agentv1.WuUpdateResult{UpdateId: uid, Revision: want[uid], Result: agentv1.WuResult_WU_RESULT_FAILED}
			if err == nil && ur != nil {
				r.Hresult = int32(integer(ur, "HResult")) // #nosec G115 -- HRESULT wraps
				if code := integer(ur, "ResultCode"); code == orcSucceeded || code == orcSucceededWithErrors {
					r.Result = agentv1.WuResult_WU_RESULT_INSTALLED
					if boolean(ur, "RebootRequired") {
						r.Result = agentv1.WuResult_WU_RESULT_INSTALLED_REBOOT
					}
				}
			}
			res.Results = append(res.Results, r)
		}
		return nil
	})
	return res, err
}

func (c *wuaClient) Hide(ctx context.Context, o Options, refs []*agentv1.WuUpdateRef, hide bool) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return com(ctx, func() error {
		d := &disp{}
		defer d.release()
		session, err := d.create("Microsoft.Update.Session")
		if err != nil {
			return err
		}
		s, err := c.searcher(d, session, o)
		if err != nil {
			return err
		}
		criteria := "IsInstalled=0 and IsHidden=0"
		if !hide {
			criteria = "IsInstalled=0 and IsHidden=1"
		}
		col, err := c.search(d, s, criteria)
		if err != nil {
			return err
		}
		want := map[string]bool{}
		for _, r := range refs {
			want[strings.ToLower(r.UpdateId)] = true
		}
		for i := 0; i < count(col); i++ {
			u, err := d.prop(col, "Item", i)
			if err != nil || u == nil {
				continue
			}
			id, err := d.prop(u, "Identity")
			if err != nil || id == nil || !want[strings.ToLower(str(id, "UpdateID"))] {
				continue
			}
			if _, err := oleutil.PutProperty(u, "IsHidden", hide); err != nil {
				return fmt.Errorf("cannot change visibility: %v", err)
			}
		}
		return nil
	})
}
