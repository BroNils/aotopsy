package analysis

import (
	"aotopsy/internal/cluster"
	"aotopsy/internal/naming"
)

// FfiBridgeRecord represents one decoded FfiTrampolineData object. Direction
// is explicit because the same object represented both outbound calls and
// native-to-Dart callbacks before Dart 3.3, while 3.3+ trampolines are
// callback-only.
type FfiBridgeRecord struct {
	RefID          int                  `json:"ref_id"`
	Direction      cluster.FfiDirection `json:"direction"`
	FfiKindRaw     uint8                `json:"ffi_kind_raw"`
	DartSignature  string               `json:"dart_signature,omitempty"`
	CSignature     string               `json:"c_signature,omitempty"`
	CallbackTarget string               `json:"callback_target,omitempty"`
	CallbackID     int32                `json:"callback_id"`
}

// BuildFfiBridges builds FfiBridgeRecord slice from cluster.Result.
func BuildFfiBridges(dartVersion string, cl *cluster.Result, pl *naming.PoolLookups) []FfiBridgeRecord {
	if cl == nil || len(cl.FfiTrampolines) == 0 {
		return nil
	}

	records := make([]FfiBridgeRecord, 0, len(cl.FfiTrampolines))
	for _, info := range cl.FfiTrampolines {
		rec := FfiBridgeRecord{
			RefID:      info.RefID,
			Direction:  cluster.ClassifyFfiTrampolineDirection(dartVersion, info),
			FfiKindRaw: info.FfiKindRaw,
			CallbackID: info.CallbackID,
		}

		if pl != nil {
			if info.SignatureTypeRef >= 0 {
				rec.DartSignature = resolveRefName(pl, info.SignatureTypeRef)
			}
			if info.CSignatureRef >= 0 {
				rec.CSignature = resolveRefName(pl, info.CSignatureRef)
			}
			if rec.Direction == cluster.FfiDirectionCallback && info.CallbackTargetRef > cluster.RefNull {
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
