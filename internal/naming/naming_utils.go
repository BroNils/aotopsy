package naming

import (
	"fmt"
	"strings"

	"aotopsy/internal/strutil"
)

func (ci CodeNameInfo) Qualified(pcOffset uint32) string {
	if ci.IsConstructor {
		return QualifiedName("", ci.FuncName, pcOffset)
	}
	// A closure is qualified by the FUNCTION it was declared inside, not by its
	// owning class -- the SDK spells it `Enclosing.<anonymous closure>` (the
	// QualifiedScrubbedName walks the parent chain). Without this every closure
	// in a class renders identically and disagrees with the symbol table. The
	// enclosing name is already class-qualified by BuildClosureParents.
	if ci.EnclosingFunction != "" {
		return QualifiedName(ci.EnclosingFunction, ci.FuncName, pcOffset)
	}
	return QualifiedName(ci.OwnerName, ci.FuncName, pcOffset)
}

// QualifiedName builds "Owner.FuncName_hexaddr" like blutter.
func QualifiedName(ownerName, funcName string, pcOffset uint32) string {
	suffix := fmt.Sprintf("_%x", pcOffset)
	if funcName == "" {
		return "sub" + suffix
	}
	if ownerName != "" {
		return ownerName + "." + funcName + suffix
	}
	return funcName + suffix
}

func FuncRelPath(ownerName, funcName string, pcOffset uint32) string {
	suffix := fmt.Sprintf("_%x", pcOffset)
	var fpart string
	if funcName == "" {
		fpart = "sub" + suffix
	} else {
		fpart = strutil.SanitizeFilename(funcName + suffix)
	}
	if ownerName != "" {
		return strutil.SanitizeFilename(ownerName) + "/" + fpart
	}
	return fpart
}

// FuncRelPathFromQualified reconstructs the relative path from a qualified name
// and its owner. Used by post-disasm commands (signal, decompile).
func FuncRelPathFromQualified(qualifiedName, owner string) string {
	if owner != "" {
		prefix := owner + "."
		funcPart := qualifiedName
		if strings.HasPrefix(qualifiedName, prefix) {
			funcPart = qualifiedName[len(prefix):]
		}
		return strutil.SanitizeFilename(owner) + "/" + strutil.SanitizeFilename(funcPart)
	}
	return strutil.SanitizeFilename(qualifiedName)
}


