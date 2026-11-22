// Command eptest-engine is a stand-in for the patching engine, for the
// browser tests only (make e2e): eptest's server in a process of its own,
// which EasyRMM calls as it calls the engine, with statements signed with
// the key in EASYRMM_PATCHING_KEY. It is not the engine, and nothing but
// the tests runs it.
//
// Under /__eptest/ it answers the tests, as an agent's reports would change
// the engine:
//
//	POST /__eptest/endpoints       add an endpoint to the organization named
//	                               organization: {organization, hostname,
//	                               windows, server, rebootPending, updates:
//	                               [{title, category, state, excluded}]};
//	                               404 until EasyRMM has created it
//	GET  /__eptest/jobs            every job, oldest first
//	POST /__eptest/jobs/{id}       {status, rebootRequired}
package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/paulmataruso/easyrmm/server/internal/easypatch/eptest"
)

func main() {
	listen := flag.String("listen", "127.0.0.1:18193", "the address to listen on (loopback)")
	flag.Parse()
	key, err := base64.StdEncoding.DecodeString(os.Getenv("EASYRMM_PATCHING_KEY"))
	if err != nil || len(key) < 32 {
		log.Fatal("eptest-engine: EASYRMM_PATCHING_KEY must be at least 32 bytes, base64-encoded")
	}
	s := eptest.NewStandIn(key)
	mux := http.NewServeMux()
	mux.Handle("/", s.Handler())
	mux.HandleFunc("POST /__eptest/endpoints", func(w http.ResponseWriter, r *http.Request) { addEndpoint(s, w, r) })
	mux.HandleFunc("GET /__eptest/jobs", func(w http.ResponseWriter, _ *http.Request) { reply(w, http.StatusOK, s.Jobs()) })
	mux.HandleFunc("POST /__eptest/jobs/{id}", func(w http.ResponseWriter, r *http.Request) { setJob(s, w, r) })
	srv := &http.Server{Addr: *listen, Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	log.Printf("eptest-engine: the patching engine's stand-in, on %s", *listen)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
}

type update struct {
	Title, Category, State string
	Excluded               bool
}

func addEndpoint(s *eptest.Server, w http.ResponseWriter, r *http.Request) {
	var in struct {
		Organization, Hostname string
		Windows, Server        bool
		RebootPending          bool
		Updates                []update
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil || in.Hostname == "" {
		http.Error(w, "an organization and a hostname", http.StatusBadRequest)
		return
	}
	org := uuid.Nil
	for _, o := range s.Organizations() {
		if strings.EqualFold(o.Name, in.Organization) {
			org = o.ID
		}
	}
	if org == uuid.Nil {
		http.Error(w, "EasyRMM has not created the organization yet", http.StatusNotFound)
		return
	}
	fingerprint := strings.ToUpper(uuid.NewString()[:9])
	e := s.AddEndpoint(org, in.Hostname, "", fingerprint)
	s.Set(func() {
		e.Windows, e.IsServer, e.RebootPending = in.Windows, in.Server, in.RebootPending
		if in.Updates != nil {
			e.Updates = nil
			for _, u := range in.Updates {
				m := eptest.NewUpdate(u.Title, u.Category, u.State)
				m["isExcluded"] = u.Excluded
				e.Updates = append(e.Updates, m)
			}
		}
	})
	reply(w, http.StatusCreated, map[string]string{"endpointId": e.ID.String(), "keyFingerprint": fingerprint})
}

func setJob(s *eptest.Server, w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	var in struct {
		Status         string
		RebootRequired bool
	}
	if err != nil || json.NewDecoder(r.Body).Decode(&in) != nil || in.Status == "" {
		http.Error(w, "a job and its status", http.StatusBadRequest)
		return
	}
	s.SetJobRebootRequired(id, in.RebootRequired)
	s.SetJobStatus(id, in.Status)
	w.WriteHeader(http.StatusNoContent)
}

func reply(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		fmt.Fprintln(os.Stderr, err)
	}
}
