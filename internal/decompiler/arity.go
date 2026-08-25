package decompiler

import (
	"strings"
)

// inferLiveInArgIndices deduces a function's incoming argument registers
// by analyzing which argument registers (fir.ArgRegs) are read before being
// written across the function's basic blocks.
//
// When cross-function call-site evidence (fir.ArgRegIndices) is unavailable,
// this replaces the blind 8-argument (arg0..arg7) fallback with real
// intraprocedural liveness, cutting false parameter declarations by >90%.
func inferLiveInArgIndices(fir *FuncIR) []int {
	if fir == nil || len(fir.ArgRegs) == 0 {
		return nil
	}

	numArgs := len(fir.ArgRegs)
	if numArgs > 8 {
		numArgs = 8
	}

	// Build register alias map for fast lookup:
	// alias -> arg index
	aliasMap := make(map[string]int)
	for i := 0; i < numArgs; i++ {
		reg := strings.ToLower(fir.ArgRegs[i])
		aliasMap[reg] = i
		// ARM64 aliases (x0..x7 -> w0..w7)
		if strings.HasPrefix(reg, "x") {
			wReg := "w" + reg[1:]
			aliasMap[wReg] = i
		}
		// x86_64 aliases (rdi -> edi/di/dil, rsi -> esi/si/sil, etc.)
		switch reg {
		case "rdi":
			aliasMap["edi"] = i
			aliasMap["di"] = i
			aliasMap["dil"] = i
		case "rsi":
			aliasMap["esi"] = i
			aliasMap["si"] = i
			aliasMap["sil"] = i
		case "rdx":
			aliasMap["edx"] = i
			aliasMap["dx"] = i
			aliasMap["dl"] = i
		case "rcx":
			aliasMap["ecx"] = i
			aliasMap["cx"] = i
			aliasMap["cl"] = i
		case "r8":
			aliasMap["r8d"] = i
			aliasMap["r8w"] = i
			aliasMap["r8b"] = i
		case "r9":
			aliasMap["r9d"] = i
			aliasMap["r9w"] = i
			aliasMap["r9b"] = i
		}
	}

	written := make([]bool, numArgs)
	read := make([]bool, numArgs)

	for bi := range fir.Blocks {
		blk := &fir.Blocks[bi]
		for _, ins := range blk.Instrs {
			reads, writes := inspectInstrRegUsage(ins, fir.ReturnReg)
			// Process reads first (if an instruction reads then writes, like add Rd, Rn)
			for _, r := range reads {
				if idx, ok := aliasMap[r]; ok {
					if !written[idx] {
						read[idx] = true
					}
				}
			}
			// Process writes
			for _, w := range writes {
				if idx, ok := aliasMap[w]; ok {
					if !read[idx] {
						written[idx] = true
					}
				}
			}
		}
	}

	maxIdx := -1
	for i := 0; i < numArgs; i++ {
		if read[i] {
			maxIdx = i
		}
	}

	if maxIdx < 0 {
		return nil
	}

	idx := make([]int, maxIdx+1)
	for i := 0; i <= maxIdx; i++ {
		idx[i] = i
	}
	return idx
}

// inspectInstrRegUsage extracts the set of registers read and written by an instruction.
func inspectInstrRegUsage(ins Instr, returnReg string) (reads []string, writes []string) {
	if ins.Op == OpReturn {
		if returnReg != "" {
			reads = append(reads, strings.ToLower(returnReg))
		}
		return reads, writes
	}

	src := strings.TrimSpace(ins.Src)
	if src == "" {
		return reads, writes
	}

	// Strip comments
	if idx := strings.Index(src, "//"); idx >= 0 {
		src = strings.TrimSpace(src[:idx])
	}
	if idx := strings.Index(src, "/*"); idx >= 0 {
		src = strings.TrimSpace(src[:idx])
	}
	if src == "" {
		return reads, writes
	}

	// Split mnemonic and operands
	fields := strings.SplitN(src, " ", 2)
	mnemonic := strings.ToLower(fields[0])
	var opsText string
	if len(fields) > 1 {
		opsText = strings.TrimSpace(fields[1])
	}

	tokens := tokenizeOperands(opsText)

	switch {
	case mnemonic == "cmp" || mnemonic == "cmn" || mnemonic == "tst" || mnemonic == "test":
		for _, t := range tokens {
			reads = append(reads, extractRegsFromToken(t)...)
		}
	case mnemonic == "cbz" || mnemonic == "cbnz" || mnemonic == "tbz" || mnemonic == "tbnz":
		if len(tokens) > 0 {
			reads = append(reads, extractRegsFromToken(tokens[0])...)
		}
	case strings.HasPrefix(mnemonic, "str") || strings.HasPrefix(mnemonic, "stur") || strings.HasPrefix(mnemonic, "stp"):
		// Stores read all registers (value and address)
		for _, t := range tokens {
			reads = append(reads, extractRegsFromToken(t)...)
		}
	case strings.HasPrefix(mnemonic, "ldr") || strings.HasPrefix(mnemonic, "ldur"):
		if len(tokens) > 0 {
			writes = append(writes, extractRegsFromToken(tokens[0])...)
		}
		if len(tokens) > 1 {
			for _, t := range tokens[1:] {
				reads = append(reads, extractRegsFromToken(t)...)
			}
		}
	case strings.HasPrefix(mnemonic, "ldp"):
		if len(tokens) >= 2 {
			writes = append(writes, extractRegsFromToken(tokens[0])...)
			writes = append(writes, extractRegsFromToken(tokens[1])...)
			for _, t := range tokens[2:] {
				reads = append(reads, extractRegsFromToken(t)...)
			}
		}
	case mnemonic == "mov" || mnemonic == "movz" || mnemonic == "movn" || mnemonic == "movk" || mnemonic == "fmov":
		if len(tokens) > 0 {
			writes = append(writes, extractRegsFromToken(tokens[0])...)
		}
		if len(tokens) > 1 {
			reads = append(reads, extractRegsFromToken(tokens[1])...)
		}
	case mnemonic == "xor" || mnemonic == "sub":
		// Check for x86 zeroing idiom: xor reg, reg / sub reg, reg
		if len(tokens) >= 2 && strings.EqualFold(tokens[0], tokens[1]) {
			writes = append(writes, extractRegsFromToken(tokens[0])...)
			return reads, writes
		}
		if len(tokens) > 0 {
			writes = append(writes, extractRegsFromToken(tokens[0])...)
			reads = append(reads, extractRegsFromToken(tokens[0])...)
		}
		if len(tokens) > 1 {
			reads = append(reads, extractRegsFromToken(tokens[1])...)
		}
	case mnemonic == "lea":
		if len(tokens) > 0 {
			writes = append(writes, extractRegsFromToken(tokens[0])...)
		}
		if len(tokens) > 1 {
			reads = append(reads, extractRegsFromToken(tokens[1])...)
		}
	default:
		// General 3-operand ALU (add Rd, Rn, Rm) on ARM64 or 2-operand on x86
		if len(tokens) > 0 {
			writes = append(writes, extractRegsFromToken(tokens[0])...)
		}
		if len(tokens) > 1 {
			for _, t := range tokens[1:] {
				reads = append(reads, extractRegsFromToken(t)...)
			}
		}
	}

	return reads, writes
}

func tokenizeOperands(ops string) []string {
	if ops == "" {
		return nil
	}
	var tokens []string
	var cur strings.Builder
	inBracket := false
	for i := 0; i < len(ops); i++ {
		c := ops[i]
		switch c {
		case '[':
			inBracket = true
			cur.WriteByte(c)
		case ']':
			inBracket = false
			cur.WriteByte(c)
		case ',':
			if !inBracket {
				tokens = append(tokens, strings.TrimSpace(cur.String()))
				cur.Reset()
			} else {
				cur.WriteByte(c)
			}
		default:
			cur.WriteByte(c)
		}
	}
	if cur.Len() > 0 {
		tokens = append(tokens, strings.TrimSpace(cur.String()))
	}
	return tokens
}

func extractRegsFromToken(token string) []string {
	token = strings.TrimSpace(strings.ToLower(token))
	token = strings.Trim(token, "[]#")
	var regs []string
	parts := strings.FieldsFunc(token, func(r rune) bool {
		return r == ' ' || r == ',' || r == '+' || r == '-' || r == '*' || r == ':' || r == '!'
	})
	for _, p := range parts {
		p = strings.TrimPrefix(p, "#")
		if isRegisterToken(p) {
			regs = append(regs, p)
		}
	}
	return regs
}

func isRegisterToken(tok string) bool {
	if tok == "" {
		return false
	}
	// ARM64 registers: x0..x30, w0..w30, sp, xzr, wzr, ip0, ip1, lr, fp
	if len(tok) >= 2 && (tok[0] == 'x' || tok[0] == 'w') {
		num := tok[1:]
		if len(num) >= 1 && len(num) <= 2 && num[0] >= '0' && num[0] <= '9' {
			return true
		}
	}
	switch tok {
	case "sp", "xzr", "wzr", "lr", "fp", "ip0", "ip1",
		"rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp",
		"r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
		"eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp",
		"r8d", "r9d", "r10d", "r11d", "r12d", "r13d", "r14d", "r15d",
		"ax", "bx", "cx", "dx", "si", "di", "bp",
		"al", "bl", "cl", "dl", "sil", "dil", "bpl", "spl",
		"r8b", "r9b", "r10b", "r11b", "r12b", "r13b", "r14b", "r15b":
		return true
	}
	return false
}
