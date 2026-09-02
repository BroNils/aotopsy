package analysis

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
)

// ProvenanceFileName is the artifact recording which binary an output
// directory was produced from.
const ProvenanceFileName = "snapshot.json"

// Provenance ties an output directory to the binary it came from.
//
// Nothing recorded this. The signal stage read a "meta.json" from the
// PARENT of the output directory for exactly this information -- one
// reader, zero writers, so the lookup always failed and the HTML report
// fell back to naming the output directory after itself. The SARIF report
// hardcoded "libapp.so", which every Flutter app ships.
//
// Without it, `aotopsy signal --in <dir>` and `--from-dir` cannot say
// which binary they are describing, and neither can anyone reading the
// output later.
type Provenance struct {
	Source             string `json:"source"`
	SourceName         string `json:"source_name"`
	SHA256             string `json:"sha256"`
	Size               int64  `json:"size"`
	Arch               string `json:"arch"`
	DartVersion        string `json:"dart_version,omitempty"`
	CompressedPointers bool   `json:"compressed_pointers"`
}

// WriteProvenance records the analysed binary in outDir.
func WriteProvenance(outDir, libPath, dartVersion string, isARM64, compressedPtrs bool) error {
	p := Provenance{
		Source:             libPath,
		SourceName:         filepath.Base(libPath),
		Arch:               "x64",
		DartVersion:        dartVersion,
		CompressedPointers: compressedPtrs,
	}
	if isARM64 {
		p.Arch = "arm64"
	}
	if fi, err := os.Stat(libPath); err == nil {
		p.Size = fi.Size()
	}
	if f, err := os.Open(libPath); err == nil {
		h := sha256.New()
		if _, err := io.Copy(h, f); err == nil {
			p.SHA256 = hex.EncodeToString(h.Sum(nil))
		}
		_ = f.Close()
	}
	data, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(outDir, ProvenanceFileName), append(data, '\n'), 0o644)
}

// ReadProvenance loads the provenance record from an output directory,
// reporting ok=false when there is none -- which is the honest answer for
// a directory produced before this existed, or by a path that never had
// the binary to record.
func ReadProvenance(dir string) (Provenance, bool) {
	data, err := os.ReadFile(filepath.Join(dir, ProvenanceFileName))
	if err != nil {
		return Provenance{}, false
	}
	var p Provenance
	if err := json.Unmarshal(data, &p); err != nil {
		return Provenance{}, false
	}
	return p, p.SourceName != ""
}
