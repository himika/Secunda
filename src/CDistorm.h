#pragma once

#include <string>

extern "C" {
#include "distorm/include/distorm.h"	// distorm_decompose
}


class CDistorm
{
public:
	CDistorm();
	explicit CDistorm::CDistorm(uintptr_t codeOffset);

	bool Decode(uintptr_t codeOffset);

	inline size_t Size() const {
		return di.size;
	}
	inline uintptr_t CodeOffset() const {
		return di.addr;
	}
	inline int PrefixSize() const {
		return prefixSize;
	}
	inline int OpcodeSize() const {
		return opcodeSize;
	}
	inline int ValueSize() const {
		return valueSize;
	}
	inline uintptr_t addr() const {
		return Script::Module::GetMainModuleBase() + di.addr;
	}

	// 逆アセンブルしたコードのニーモニックを返す
	inline const std::string& str() const {
		return disasm;
	}

	// 16進ダンプを文字列で返す
	bool GetDump(std::string& dump, bool wildcard) const;

	// オペコードにアドレスを含んでいればtrueを返し、outAddrにアドレスを代入する
	bool ContainsAddress(uintptr_t& outAddr) const;

	// オペコードにアドレスを含んでいるか調べる
	bool ContainsAddress() const;

	// オペコードにラベルを含んでいればtrueを返し、outLabelにラベルを代入する
	bool ContainsLabel(std::string& outLabel) const;

private:
	uintptr_t codeOffset;
	_DInst di;
	int prefixSize;
	int opcodeSize;
	int valueSize;
	uint8_t code[24];
	std::string disasm;
};

