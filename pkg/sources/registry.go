package sources

import (
	"sort"
	"sync"
)

type Factory func() Source

var (
	mu       sync.RWMutex
	registry = map[SourceType]Factory{}
)

func Register(t SourceType, f Factory) {
	mu.Lock()
	defer mu.Unlock()
	if _, exists := registry[t]; exists {
		panic("sources: duplicate registration for type " + t.String())
	}
	registry[t] = f
}

func New(t SourceType) Source {
	mu.RLock()
	defer mu.RUnlock()
	if f, ok := registry[t]; ok {
		return f()
	}
	return nil
}

// Registered returns every SourceType with a self-registered core Source
// factory, sorted by type value — the detectors.All() analogue for core
// sources. pkg/sources/catalog.All() layers pkg/connectors' SaaS registry
// on top to cover the full CLI surface.
func Registered() []SourceType {
	mu.RLock()
	defer mu.RUnlock()
	out := make([]SourceType, 0, len(registry))
	for t := range registry {
		out = append(out, t)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func (t SourceType) String() string {
	switch t {
	case SourceFilesystem:
		return "filesystem"
	case SourceGit:
		return "git"
	case SourceGitHub:
		return "github"
	case SourceGitLab:
		return "gitlab"
	case SourceS3:
		return "s3"
	case SourceGCS:
		return "gcs"
	case SourceSlack:
		return "slack"
	case SourceJira:
		return "jira"
	case SourceConfluence:
		return "confluence"
	case SourceAzureBlob:
		return "azure-blob"
	case SourceBitbucket:
		return "bitbucket"
	case SourceNotion:
		return "notion"
	case SourceStdin:
		return "stdin"
	case SourceForgejo:
		return "forgejo"
	case SourceGitea:
		return "gitea"
	case SourceGogs:
		return "gogs"
	case SourceGitbucket:
		return "gitbucket"
	case SourceCodeberg:
		return "codeberg"
	case SourceOneDev:
		return "onedev"
	case SourceCodebase:
		return "codebase"
	case SourcePagure:
		return "pagure"
	case SourceDatadog:
		return "datadog"
	case SourceSplunk:
		return "splunk"
	case SourceBigQuery:
		return "bigquery"
	case SourceRedash:
		return "redash"
	case SourceSQLDump:
		return "sqldump"
	case SourceDockerImage:
		return "docker-image"
	case SourceElasticsearch:
		return "elasticsearch"
	case SourceJenkins:
		return "jenkins"
	case SourcePostman:
		return "postman"
	case SourceHuggingFace:
		return "huggingface"
	case SourceCircleCI:
		return "circleci"
	default:
		return "unknown"
	}
}
