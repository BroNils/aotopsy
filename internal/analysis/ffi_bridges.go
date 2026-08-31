package analysis

import (
	"aotopsy/internal/cluster"
	"aotopsy/internal/naming"
)

// FfiBridgeRecord represents one decoded Dart FFI trampoline connecting to
// native C function pointers, dynamic library lookups, or native callbacks.
type FfiBridgeRecord struct {
	RefID          int    `json:"ref_id"`
	Kind           string `json:"kind"` // "sync", "async", "leaf", "callback"
	DartSignature  string `json:"dart_signature,omitempty"`
	CSignature     string `json:"c_signature,omitempty"`
	CallbackTarget string `json:"callback_target,omitempty"`
	CallbackID     int32  `json:"callback_id,omitempty"`
}

// BuildFfiBridges builds FfiBridgeRecord slice from cluster.Result.
func BuildFfiBridges(cl *cluster.Result, pl *naming.PoolLookups) []FfiBridgeRecord {
	if cl == nil || len(cl.FfiTrampolines) == 0 {
		return nil
	}

	records := make([]FfiBridgeRecord, 0, len(cl.FfiTrampolines))
	for _, info := range cl.FfiTrampolines {
		rec := FfiBridgeRecord{
			RefID:      info.RefID,
			Kind:       cluster.FfiKindString(info.FfiFunctionKind),
			CallbackID: info.CallbackID,
		}

		if pl != nil {
			if info.SignatureTypeRef >= 0 {
				rec.DartSignature = resolveRefName(pl, info.SignatureTypeRef)
			}
			if info.CSignatureRef >= 0 {
				rec.CSignature = resolveRefName(pl, info.CSignatureRef)
			}
			if info.CallbackTargetRef >= 0 {
				rec.CallbackTarget = resolveRefName(pl, info.CallbackTargetRef)
			}
		}

		records = append(records, rec)
	}

	return records
}

func resolveRefName(pl *naming.PoolLookups, ref int) string {
	if pl == nil || ref < 0 {
		return ""
	}
	if str, ok := pl.RefToStr[ref]; ok && str != "" {
		return str
	}
	if str, ok := pl.VmRefToStr[ref]; ok && str != "" {
		return str
	}
	if no, ok := pl.RefToNamed[ref]; ok && no != nil {
		if name := pl.ResolveName(no); name != "" {
			return name
		}
		if name := pl.ResolveVMName(no); name != "" {
			return name
		}
	}
	if no, ok := pl.VmRefToNamed[ref]; ok && no != nil {
		if name := pl.ResolveName(no); name != "" {
			return name
		}
		if name := pl.ResolveVMName(no); name != "" {
			return name
		}
	}
	return ""
}
