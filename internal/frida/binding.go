package frida

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"aotopsy/internal/snapshot"
)

const (
	BindingSchemaVersion = 2
	BindingFileName      = "frida_binding.json"

	maxFunctionMapEntries  = 500
	maxInstalledFunctions  = 50
	maxInstalledCallProbes = 100
)

var generationArtifactNames = [...]string{
	"provenance.json",
	"functions.jsonl",
	"call_edges.jsonl",
	"dispatch_table.jsonl",
	"string_refs.jsonl",
	"evidence.jsonl",
}

type ArtifactDigest struct {
	Name    string `json:"name"`
	Present bool   `json:"present"`
	Size    int64  `json:"size"`
	SHA256  string `json:"sha256"`
}

// FridaBinding is the compact trust-boundary manifest shared by export, the
// generated runtime script, and import. It binds the script to one exact static
// artifact generation and records precisely which function/indirect-call sites
// the stock script can observe.
type FridaBinding struct {
	SchemaVersion       int                   `json:"schema_version"`
	MetadataSchema      int                   `json:"metadata_schema"`
	AnalyzerVersion     string                `json:"analyzer_version"`
	AnalyzerCommit      string                `json:"analyzer_commit"`
	GenerationID        string                `json:"generation_id"`
	SourceSHA256        string                `json:"source_sha256"`
	SourceSize          int64                 `json:"source_size"`
	ModuleName          string                `json:"module_name"`
	RuntimeIdentity     []RuntimeRegionDigest `json:"runtime_identity"`
	DartVersion         string                `json:"dart_version"`
	Architecture        string                `json:"architecture"`
	Artifacts           []ArtifactDigest      `json:"artifacts"`
	InstalledFunctions  []FridaFunction       `json:"installed_functions"`
	InstalledCallProbes []FridaCallProbe      `json:"installed_call_probes"`
}

func GenerationArtifactNames() []string {
	out := make([]string, len(generationArtifactNames))
	copy(out, generationArtifactNames[:])
	return out
}

func DigestArtifact(name string, data []byte, present bool) ArtifactDigest {
	if !present {
		return ArtifactDigest{Name: name}
	}
	sum := sha256.Sum256(data)
	return ArtifactDigest{Name: name, Present: true, Size: int64(len(data)), SHA256: hex.EncodeToString(sum[:])}
}

// DispatchClassIDRegister returns a register only when the raw class ID is
// still live at the indirect-call instruction. ARM64 Dart before 2.13 reused
// cid_reg while adding the selector offset, so recording x0 there would label a
// dispatch-table index as a class ID. x64 keeps RCX as the raw CID.
func DispatchClassIDRegister(architecture, dartVersion string) string {
	switch architecture {
	case "x64":
		return "rcx"
	case "arm64":
		if snapshot.VersionAtLeast(dartVersion, "2.13.0") {
			return "x0"
		}
	}
	return ""
}

func FinalizeMetadata(meta *FridaMetadata) error {
	if meta == nil {
		return fmt.Errorf("frida metadata: nil metadata")
	}
	meta.InstalledFunctions = installedFunctions(meta.Functions)
	meta.InstalledCallProbes = installedCallProbes(meta.CallProbes)
	binding := BindingFromMetadata(*meta)
	id, err := ComputeGenerationID(binding)
	if err != nil {
		return err
	}
	meta.GenerationID = id
	return ValidateMetadata(*meta)
}

func BindingFromMetadata(meta FridaMetadata) FridaBinding {
	return FridaBinding{
		SchemaVersion:       BindingSchemaVersion,
		MetadataSchema:      meta.SchemaVersion,
		AnalyzerVersion:     meta.AnalyzerVersion,
		AnalyzerCommit:      meta.AnalyzerCommit,
		GenerationID:        meta.GenerationID,
		SourceSHA256:        meta.SourceSHA256,
		SourceSize:          meta.SourceSize,
		ModuleName:          meta.ModuleName,
		RuntimeIdentity:     append([]RuntimeRegionDigest(nil), meta.RuntimeIdentity...),
		DartVersion:         meta.DartVersion,
		Architecture:        meta.Architecture,
		Artifacts:           append([]ArtifactDigest(nil), meta.Artifacts...),
		InstalledFunctions:  append([]FridaFunction(nil), meta.InstalledFunctions...),
		InstalledCallProbes: append([]FridaCallProbe(nil), meta.InstalledCallProbes...),
	}
}

func ComputeGenerationID(binding FridaBinding) (string, error) {
	binding.GenerationID = ""
	b, err := json.Marshal(binding)
	if err != nil {
		return "", fmt.Errorf("frida binding: encode generation material: %w", err)
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

func ValidateBinding(binding FridaBinding) error {
	if binding.SchemaVersion != BindingSchemaVersion {
		return fmt.Errorf("frida binding: unsupported schema %d", binding.SchemaVersion)
	}
	if binding.MetadataSchema != MetadataSchemaVersion {
		return fmt.Errorf("frida binding: metadata schema %d, want %d", binding.MetadataSchema, MetadataSchemaVersion)
	}
	if strings.TrimSpace(binding.AnalyzerVersion) == "" || strings.TrimSpace(binding.AnalyzerCommit) == "" {
		return fmt.Errorf("frida binding: missing analyzer identity")
	}
	if len(binding.GenerationID) != 64 {
		return fmt.Errorf("frida binding: invalid generation id")
	}
	if _, err := hex.DecodeString(binding.GenerationID); err != nil {
		return fmt.Errorf("frida binding: invalid generation id: %w", err)
	}
	if len(binding.SourceSHA256) != 64 {
		return fmt.Errorf("frida binding: invalid source sha256")
	}
	if _, err := hex.DecodeString(binding.SourceSHA256); err != nil {
		return fmt.Errorf("frida binding: invalid source sha256: %w", err)
	}
	if binding.SourceSize <= 0 || strings.TrimSpace(binding.ModuleName) == "" || strings.TrimSpace(binding.DartVersion) == "" {
		return fmt.Errorf("frida binding: incomplete source identity")
	}
	if uint64(binding.SourceSize) > maxSafeJSInteger {
		return fmt.Errorf("frida binding: source size %d exceeds exact JavaScript integer range", binding.SourceSize)
	}
	if strings.ContainsAny(binding.ModuleName, `/\\`) {
		return fmt.Errorf("frida binding: invalid module name %q", binding.ModuleName)
	}
	if len(binding.RuntimeIdentity) == 0 {
		return fmt.Errorf("frida binding: no runtime identity regions")
	}
	for i, region := range binding.RuntimeIdentity {
		if region.Kind == "" || region.Size <= 0 || len(region.SHA256) != 64 {
			return fmt.Errorf("frida binding: runtime identity region %d invalid", i)
		}
		if err := validateJSOffset(region.Offset); err != nil {
			return fmt.Errorf("frida binding: runtime identity region %d: %w", i, err)
		}
		if _, err := hex.DecodeString(region.SHA256); err != nil {
			return fmt.Errorf("frida binding: runtime identity region %d invalid sha256: %w", i, err)
		}
		if uint64(region.Size) > maxSafeJSInteger {
			return fmt.Errorf("frida binding: runtime identity region %d exceeds JavaScript exact integer range", i)
		}
	}
	if binding.Architecture != "arm64" && binding.Architecture != "x64" {
		return fmt.Errorf("frida binding: unsupported architecture %q", binding.Architecture)
	}
	if err := validateArtifactDigests(binding.Artifacts); err != nil {
		return err
	}
	for i, f := range binding.InstalledFunctions {
		if strings.TrimSpace(f.Name) == "" || f.Size < 0 {
			return fmt.Errorf("frida binding: installed function %d invalid", i)
		}
		if err := validateJSOffset(f.VA); err != nil {
			return fmt.Errorf("frida binding: installed function %d: %w", i, err)
		}
	}
	for i, p := range binding.InstalledCallProbes {
		if err := validateJSOffset(p.VA); err != nil {
			return fmt.Errorf("frida binding: installed probe %d: %w", i, err)
		}
		if p.ClassIDReg != "" && (p.Via != "dispatch_table" || !isContextRegisterForArch(binding.Architecture, p.ClassIDReg)) {
			return fmt.Errorf("frida binding: installed probe %d has invalid class-id register %q", i, p.ClassIDReg)
		}
	}
	want, err := ComputeGenerationID(binding)
	if err != nil {
		return err
	}
	if !strings.EqualFold(binding.GenerationID, want) {
		return fmt.Errorf("frida binding: generation id does not match manifest contents")
	}
	return nil
}

func validateArtifactDigests(digests []ArtifactDigest) error {
	if len(digests) != len(generationArtifactNames) {
		return fmt.Errorf("frida binding: artifact manifest has %d entries, want %d", len(digests), len(generationArtifactNames))
	}
	for i, want := range generationArtifactNames {
		d := digests[i]
		if d.Name != want {
			return fmt.Errorf("frida binding: artifact %d is %q, want %q", i, d.Name, want)
		}
		required := i < 3
		if required && !d.Present {
			return fmt.Errorf("frida binding: required artifact %s is absent", d.Name)
		}
		if !d.Present {
			if d.Size != 0 || d.SHA256 != "" {
				return fmt.Errorf("frida binding: absent artifact %s carries digest metadata", d.Name)
			}
			continue
		}
		if d.Size < 0 || len(d.SHA256) != 64 {
			return fmt.Errorf("frida binding: artifact %s has invalid digest metadata", d.Name)
		}
		if _, err := hex.DecodeString(d.SHA256); err != nil {
			return fmt.Errorf("frida binding: artifact %s has invalid sha256: %w", d.Name, err)
		}
	}
	return nil
}

func scriptFunctionMap(functions []FridaFunction) []FridaFunction {
	if len(functions) <= maxFunctionMapEntries {
		return append([]FridaFunction(nil), functions...)
	}
	out := make([]FridaFunction, 0, maxFunctionMapEntries)
	for _, f := range functions {
		if strings.HasPrefix(f.Name, "sub_") || strings.HasPrefix(f.Name, "stub_") {
			continue
		}
		out = append(out, f)
		if len(out) == maxFunctionMapEntries {
			break
		}
	}
	return out
}

func installedFunctions(functions []FridaFunction) []FridaFunction {
	funcMap := scriptFunctionMap(functions)
	if len(funcMap) > maxInstalledFunctions {
		funcMap = funcMap[:maxInstalledFunctions]
	}
	return append([]FridaFunction(nil), funcMap...)
}

func installedCallProbes(probes []FridaCallProbe) []FridaCallProbe {
	if len(probes) > maxInstalledCallProbes {
		probes = probes[:maxInstalledCallProbes]
	}
	return append([]FridaCallProbe(nil), probes...)
}

func sameInstalledFunctions(a, b []FridaFunction) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func sameInstalledCallProbes(a, b []FridaCallProbe) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
