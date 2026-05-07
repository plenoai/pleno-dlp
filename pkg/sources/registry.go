package sources

import "sync"

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
	default:
		return "unknown"
	}
}
