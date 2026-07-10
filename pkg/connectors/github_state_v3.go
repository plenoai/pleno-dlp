package connectors

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
	"time"
)

func githubScopeFingerprint(cfg Config) string {
	h := sha256.New()
	for _, k := range []string{"org", "repo", "include_repo_globs", "exclude_repo_globs", "include_forks", "include_archived", "expand_members"} {
		fmt.Fprintf(h, "%s=%s\x00", k, cfg[k])
	}
	return hex.EncodeToString(h.Sum(nil))
}

func githubRetention(cfg Config) (time.Duration, int, error) {
	days := 30
	runs := 3
	var err error
	if raw := cfg["state_retention_days"]; raw != "" {
		days, err = strconv.Atoi(raw)
		if err != nil || days < 1 {
			return 0, 0, fmt.Errorf("github: state_retention_days must be positive")
		}
	}
	if raw := cfg["state_retention_runs"]; raw != "" {
		runs, err = strconv.Atoi(raw)
		if err != nil || runs < 1 {
			return 0, 0, fmt.Errorf("github: state_retention_runs must be positive")
		}
	}
	return time.Duration(days) * 24 * time.Hour, runs, nil
}

func prepareGitHubStateV3(state *githubIncrementalState, repos []githubRepoRef, cfg Config, now time.Time) (int, error) {
	age, minRuns, err := githubRetention(cfg)
	if err != nil {
		return 0, err
	}
	scope := githubScopeFingerprint(cfg)
	same := state.ScopeFingerprint == scope
	state.Version = 3
	state.ScopeFingerprint = scope
	if same {
		state.CompleteRuns++
	} else {
		state.CompleteRuns = 1
	}
	if state.Tombstones == nil {
		state.Tombstones = map[string]githubStateTombstone{}
	}
	observed := map[string]githubRepoRef{}
	for _, r := range repos {
		key := r.Owner.Login + "/" + r.Name
		observed[key] = r
		stable := githubStableRepoID(r, key)
		for _, surface := range []string{"repository-history", "repository-wiki"} {
			m := state.Surfaces[surface]
			if m == nil {
				m = map[string]githubRepoIncrementalState{}
				state.Surfaces[surface] = m
			}
			if _, ok := m[key]; !ok {
				for old, s := range m {
					if s.StableID != "" && s.StableID == stable {
						delete(m, old)
						m[key] = s
						break
					}
				}
			}
		}
	}
	pruned := 0
	for _, surface := range []string{"repository-history", "repository-wiki"} {
		m := state.Surfaces[surface]
		for key, s := range m {
			if r, ok := observed[key]; ok {
				s.StableID = githubStableRepoID(r, key)
				s.LastSeen = now.UTC().Format(time.RFC3339)
				s.UnobservedRuns = 0
				s.UnobservedSince = ""
				m[key] = s
				delete(state.Tombstones, surface+":"+key)
				continue
			}
			if !same {
				continue
			}
			s.UnobservedRuns++
			if s.UnobservedSince == "" {
				s.UnobservedSince = now.UTC().Format(time.RFC3339)
			}
			m[key] = s
			state.Tombstones[surface+":"+key] = githubStateTombstone{StableID: s.StableID, LastName: key, FirstUnobserved: s.UnobservedSince, CompleteRuns: s.UnobservedRuns}
			since, _ := time.Parse(time.RFC3339, s.UnobservedSince)
			if s.UnobservedRuns >= minRuns && now.Sub(since) >= age {
				delete(m, key)
				delete(state.Tombstones, surface+":"+key)
				pruned++
			}
		}
	}
	return pruned, nil
}
func githubStableRepoID(r githubRepoRef, fallback string) string {
	if r.ID > 0 {
		return strconv.FormatInt(r.ID, 10)
	}
	return "name:" + fallback
}
