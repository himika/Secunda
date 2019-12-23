#pragma once

#include "pluginmain.h"
#include <string>

namespace Util
{
	bool DeleteLabel(const char* name);
	inline bool DeleteLabel(const std::string& name) {
		return DeleteLabel(name.c_str());
	}
	inline bool HasLabel(duint addr) {
		return Script::Label::Get(addr, nullptr);
	}
	std::string GetLabel(duint addr);
	bool GetLabel(duint addr, std::string& label);
	bool SetLabel(const char* name, duint addr, bool manual = false);
	inline bool SetLabel(const std::string& name, duint addr, bool manual = false) {
		return SetLabel(name.c_str(), addr, manual);
	}

	std::string GetModName(duint moduleAddr);
	bool GetMainModuleSection(const char* name, size_t strlenName, Script::Module::ModuleSectionInfo& info);
	bool GetMainModuleCodeInfo(duint& addr, duint& size);

	std::vector<duint> FindMemAll(duint start, duint size, const char* pattern, size_t max = 0);

	bool OpenSelectionDialog(const char* Title, const char* Filter, bool Save, bool(*Callback)(char*));
}
