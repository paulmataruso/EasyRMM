package meshcentral

import "net/http"

// SpoilSession replaces the cached MeshCentral web session with one
// MeshCentral will not accept, as after a MeshCentral restart.
func (f *Files) SpoilSession() {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.cookies != nil {
		f.cookies = []*http.Cookie{{Name: f.cookies[0].Name, Value: "expired"}}
	}
}
