#include "pch.h"
#include "CDistorm.h"
#include <sstream>
#include <iomanip>
#include "Util.h"

extern "C" {
#include "distorm/include/mnemonics.h"
#include "distorm/src/prefix.h"			// prefixes_decode
}

CDistorm::CDistorm() : codeOffset(0), prefixSize(0), opcodeSize(0), valueSize(0), disasm()
{
	memset(&di, 0, sizeof(di));
	memset(code, 0, sizeof(code));
	di.flags = FLAG_NOT_DECODABLE;
}


CDistorm::CDistorm(uintptr_t codeOffset) : codeOffset(0), prefixSize(0), opcodeSize(0), valueSize(0), disasm()
{
	memset(&di, 0, sizeof(di));
	memset(code, 0, sizeof(code));

	Decode(codeOffset);
}


bool CDistorm::Decode(uintptr_t codeOffset)
{
	BASIC_INSTRUCTION_INFO basicinfo;
	DbgDisasmFastAt(codeOffset, &basicinfo);
	int codeLen = basicinfo.size;
	if (codeLen >= sizeof(code)) {
		return false;
	}
	if (!DbgMemRead(codeOffset, code, codeLen)) {
		return false;
	}
	disasm = basicinfo.instruction;

#ifdef _WIN64
	_CodeInfo ci = { codeOffset, 0, code, codeLen, Decode64Bits, DF_NONE };
#else
	_CodeInfo ci = { codeOffset, 0, code, codeLen, Decode32Bits, DF_NONE };
#endif

	unsigned int instructionCount = 0;
	_DecodeResult decodeResult = distorm_decompose(&ci, &di, codeLen, &instructionCount);
	if (decodeResult != DECRES_SUCCESS) {
		di.size = 0;
		di.flags = FLAG_NOT_DECODABLE;
		return false;
	}
	if (instructionCount != 1) {
		di.size = 0;
		di.flags = FLAG_NOT_DECODABLE;
		return false;
	}
	if (codeLen != di.size) {
		di.size = 0;
		di.flags = FLAG_NOT_DECODABLE;
		return false;
	}


	//
	// calc value size
	//
	ci.codeOffset = di.addr;
	ci.code = code;
	ci.codeLen = di.size;

	valueSize = 0;
	for (unsigned int i = 0; i < OPERANDS_NO; ++i) {
		const _Operand& op = di.ops[i];

		switch (op.type) {
		case O_NONE: //operand is to be ignored.
		case O_REG: //index holds global register index.
			break;
		case O_IMM: //instruction.imm.
		case O_IMM1: //instruction.imm.ex.i1.
		case O_IMM2: //instruction.imm.ex.i2.
		case O_PC: //the relative address of a branch instruction(instruction.imm.addr).
		case O_PTR: //the absolute target address of a far branch instruction(instruction.imm.ptr.seg / off).
			valueSize += op.size;
			break;
		case O_DISP: //memory dereference with displacement only, instruction.disp.
		case O_SMEM: //simple memory dereference with optional displacement(a single register memory dereference).
		case O_MEM: //complex memory dereference(optional fields : s / i / b / disp).
			valueSize += di.dispSize;
			break;
		}
	}
	valueSize >>= 3;	// bit to byte

	//
	// calc prefix size
	//
	_PrefixState ps;
	memset(&ps, 0, (size_t)((char*)&ps.pfxIndexer[0] - (char*)&ps));
	memset(ps.pfxIndexer, PFXIDX_NONE, sizeof(int) * PFXIDX_MAX);
	ps.start = code;
	ps.last = code;

	prefixSize = 0;
	if (prefixes_is_valid(*code, ci.dt)) {
		prefixes_decode(code, di.size, &ps, ci.dt);
		prefixSize = (unsigned int)(ps.last - ps.start);
	}

	//
	// calc opcode size
	//
	opcodeSize = di.size - prefixSize - valueSize;

	return true;
}

bool CDistorm::GetDump(std::string& dump, bool wildcard) const
{
	std::ostringstream hexDump;

	const uint8_t* p = code;
	if (prefixSize > 0) {
		for (const uint8_t* end = p + prefixSize; p < end; ++p) {
			hexDump << std::hex << std::uppercase << std::setfill('0') << std::setw(2) << (int)*p;
		}
		hexDump << ':';
	}

	for (const uint8_t* end = p + opcodeSize; p < end; ++p) {
		hexDump << std::hex << std::uppercase << std::setfill('0') << std::setw(2) << (int)*p;
	}

	for (unsigned int i = 0; i < OPERANDS_NO; ++i) {
		const _Operand& op = di.ops[i];
		int size = 0;

		switch (op.type) {
		case O_NONE: //operand is to be ignored.
		case O_REG: //index holds global register index.
			break;
		case O_IMM: //instruction.imm.
		case O_IMM1: //instruction.imm.ex.i1.
		case O_IMM2: //instruction.imm.ex.i2.
		case O_PC: //the relative address of a branch instruction(instruction.imm.addr).
		case O_PTR: //the absolute target address of a far branch instruction(instruction.imm.ptr.seg / off).
			size = (op.size >> 3);
			break;
		case O_DISP: //memory dereference with displacement only, instruction.disp.
		case O_SMEM: //simple memory dereference with optional displacement(a single register memory dereference).
		case O_MEM: //complex memory dereference(optional fields : s / i / b / disp).
			size = (di.dispSize >> 3);
			break;
		}
		if (size > 0) {
			hexDump << " ";
			if (wildcard) {
				for (const uint8_t* end = p + size; p < end; ++p) {
					hexDump << "??";
				}
			}
			else {
				for (const uint8_t* end = p + size; p < end; ++p) {
					hexDump << std::hex << std::uppercase << std::setfill('0') << std::setw(2) << (int)*p;
				}
			}
		}
	}

	dump = hexDump.str();
	
	return true;
}


bool CDistorm::ContainsAddress(uintptr_t& outAddr) const
{
	uintptr_t nextOp = CodeOffset() + di.size;	// next instruction address
	bool result = false;
	for (unsigned int i = 0; i < OPERANDS_NO; ++i) {
		const _Operand& op = di.ops[i];

		switch (op.type) {
		case O_DISP:
		{
			int64_t disp = (int64_t)di.disp;
			if (di.dispSize > 0) {
				outAddr = nextOp + disp;
				result = true;
			}
			break;
		}
		case O_SMEM:
		{
			int64_t disp = (int64_t)di.disp;
			if (di.dispSize > 0 && op.index == R_RIP) {
				outAddr = nextOp + disp;
				result = true;
			}
			break;
		}
		case O_MEM:
		{
			int64_t disp = (int64_t)di.disp;
			if (di.dispSize > 0 && di.base == R_RIP) {
				outAddr = nextOp + disp;
				result = true;
			}
			break;
		}
		case O_PC:
			outAddr = nextOp + di.imm.addr;
			result = true;
			break;
		case O_PTR:
			outAddr = di.imm.ptr.off;
			result = true;
			break;
		}

		if (result) {
			break;
		}
	}

	return result;
}

bool CDistorm::ContainsAddress() const
{
	uintptr_t dummy;
	return ContainsAddress(dummy);
}


bool CDistorm::ContainsLabel(std::string& outLabel) const
{
	uintptr_t addr;
	if (ContainsAddress(addr)) {
		if (addr && Util::HasLabel(addr)) {
			Util::GetLabel(addr, outLabel);
			return true;
		}
	}

	return false;
}
