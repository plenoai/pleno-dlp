//go:build !unix

package git

import "os"

func mmapFile(path string) ([]byte, func() error, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	return b, func() error { return nil }, nil
}
