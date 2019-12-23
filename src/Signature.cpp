#include "pch.h"
#include "Signature.h"
#include "Util.h"
#include "CDistorm.h"
#include <sstream>
#include <unordered_map>

static std::unordered_map<std::string, std::string> s_signatureMap;


namespace Signature
{
	bool Get(const std::string& label)
	{
		auto it = s_signatureMap.find(label);
		return (it != s_signatureMap.end());
	}


	bool Get(const std::string& label, std::string& signature)
	{
		auto it = s_signatureMap.find(label);
		if (it == s_signatureMap.end()) {
			return false;
		}

		signature = it->second;
		return true;
	}


	void Set(const std::string& label, const std::string& signature)
	{
		s_signatureMap.insert_or_assign(label, signature);
	}


	void Remove(const std::string& label)
	{
		s_signatureMap.erase(label);
	}

	size_t Size() {
		return s_signatureMap.size();
	}

	void Clear()
	{
		s_signatureMap.clear();
	}


	void ForEach(std::function<void(const std::string & label, const std::string & signature)> callback)
	{
		for (auto& kv : s_signatureMap) {
			callback(kv.first, kv.second);
		}
	}


	void Show()
	{
		GuiReferenceInitialize("Signatures");
		GuiReferenceAddColumn(16, GuiTranslateText("Address"));
		GuiReferenceAddColumn(40, GuiTranslateText("Disassembly"));
		GuiReferenceAddColumn(50, GuiTranslateText("Label"));
		GuiReferenceAddColumn(50, "Signature");
		GuiReferenceSetRowCount(s_signatureMap.size());
		GuiReferenceSetProgress(0);

		int idx = 0;
		for (auto& kv : s_signatureMap) {
			const std::string& label = kv.first;
			const std::string& signature = kv.second;
			duint addr = 0;
			if (Script::Label::FromString(label.c_str(), &addr)) {
				char temp[32];
				sprintf_s(temp, "%p", (PVOID)addr);
				GuiReferenceSetCellContent(idx, 0, temp);

				DISASM_INSTR inst;
				DbgDisasmAt(addr, &inst);
				GuiReferenceSetCellContent(idx, 1, inst.instruction);
			}
			else {
				GuiReferenceSetCellContent(idx, 0, "<missing>");
				GuiReferenceSetCellContent(idx, 1, "");
			}

			GuiReferenceSetCellContent(idx, 2, label.c_str());
			GuiReferenceSetCellContent(idx, 3, signature.c_str());

			++idx;
		}

		_plugin_logprintf("%d signature(s) listed in Reference View\n", idx);
		GuiReferenceSetProgress(100);
		GuiUpdateAllViews();
	}

	bool MakePatternFromSignature(const std::string& signature, std::string& pattern, size_t& index)
	{
		std::ostringstream oss;

		// 必要のない文字を除去
		index = 0;
		int markbit = 0;
		for (char c : signature) {
			if (c == '*') {
				index = (markbit >> 3);		// bit to byte
				continue;
			}
			if (c != '?' && !std::isxdigit(c)) {
				continue;
			}
			markbit += 4;
			oss << c;
		}

		pattern = oss.str();

		return true;
	}

	bool Find(const std::string& signature, std::vector<duint>& result, size_t max)
	{
		std::string pattern;
		size_t idx;

		if (!MakePatternFromSignature(signature, pattern, idx)) {
			_plugin_logprint("invalid signature\n");
			return false;
		}

		duint addr;
		duint size;
		if (!Util::GetMainModuleCodeInfo(addr, size)) {
			_plugin_logprint("maybe fatal error\n");
			return false;
		}

		std::vector<duint> match = Util::FindMemAll(addr, size, pattern.c_str(), max);
		for (duint start : match) {
			size_t pos = idx;

			duint ptr = start;
			duint label_addr = 0;
			for (;;) {
				CDistorm distorm(ptr);
				size_t size = distorm.Size();
				if (size == 0) {
					// 逆アセンブル失敗
					_plugin_logprint("disasemble error\n");
					break;
				}
				if (pos == 0) {
					label_addr = ptr;
					break;
				}
				if (pos < size) {
					if (size - distorm.ValueSize() != pos) {
						// 逆アセンブル失敗
						_plugin_logprint("disasemble error\n");
					}
					else if (!distorm.ContainsAddress(label_addr)) {
						// アドレスを含んでいなかった
						_plugin_logprint("disasemble error\n");
					}
					break;
				}
				pos -= size;
				ptr += size;
			}

			if (label_addr) {
				result.push_back(label_addr);
			}
		}
		
		return true;
	}

}
