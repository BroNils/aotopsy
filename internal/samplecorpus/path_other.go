//go:build !windows

package samplecorpus

import (
	"io/fs"
	"os"
)

func statCorpusPath(path string) (string, fs.FileInfo, error) {
	fi, err := os.Stat(path)
	return path, fi, err
}
