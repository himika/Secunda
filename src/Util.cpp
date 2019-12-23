#include "pch.h"
#include "Util.h"
#include <memory>

namespace
{
	struct BridgeMemoryDeleter
	{
		inline void operator()(void* p) const noexcept {
			BridgeFree(p);
		}
	};

	template <typename Ty, typename D = BridgeMemoryDeleter>
	using b_unique_ptr = std::unique_ptr<Ty, D>;
}


namespace Util {

	bool DeleteLabel(const char* name)
	{
		duint addr = 0;
		if (!Script::Label::FromString(name, &addr)) {
			return false;
		}
		return Script::Label::Delete(addr);
	}

	bool GetLabel(duint addr, std::string& label)
	{
		if (!Script::Label::Get(addr, nullptr)) {
			return false;
		}

		char buffer[MAX_LABEL_SIZE];
		memset(buffer, 0, sizeof(MAX_LABEL_SIZE));
		Script::Label::Get(addr, buffer);
		label = buffer;
		return true;
	}

	std::string GetLabel(duint addr)
	{
		std::string result;
		Util::GetLabel(addr, result);
		return result;
	}

	bool SetLabel(const char* name, duint addr, bool manual)
	{
		duint old_addr = 0;
		if (Script::Label::FromString(name, &old_addr) && old_addr != addr) {
			Script::Label::Delete(old_addr);
		}
		return Script::Label::Set(addr, name, manual);
	}

	std::string GetModName(duint moduleAddr)
	{
		std::string result;

		if (moduleAddr >= 0) {
			char buffer[MAX_MODULE_SIZE];
			memset(buffer, 0, sizeof(MAX_MODULE_SIZE));
			if (!Script::Module::NameFromAddr(moduleAddr, buffer)) {
				return false;
			}
			result = buffer;
		}

		return result;
	}


	bool GetMainModuleSection(const char* name, size_t strlenName, Script::Module::ModuleSectionInfo& info)
	{
		using Script::Module::ModuleSectionInfo;

		ListInfo listInfo;
		if (!Script::Module::GetMainModuleSectionList(&listInfo)) {
			return false;
		}
		b_unique_ptr<ModuleSectionInfo[]> sectionInfo(static_cast<ModuleSectionInfo*>(listInfo.data));

		for (int i = 0; i < listInfo.count; ++i) {
			auto& elem = sectionInfo[i];
			if (std::memcmp(elem.name, name, strlenName) == 0) {
				memcpy(&info, &elem, sizeof(ModuleSectionInfo));
				return true;
			}
		}
		return false;
	}


	bool GetMainModuleCodeInfo(duint& addr, duint& size)
	{
		using Script::Module::ModuleSectionInfo;

		ModuleSectionInfo info;
		if (!GetMainModuleSection(".text", 6, info)) {
			return false;
		}
		addr = info.addr;
		size = info.size;
		return true;
	}


	bool GetMainModuleRDataInfo(duint& addr, duint& size)
	{
		using Script::Module::ModuleSectionInfo;

		ModuleSectionInfo info;
		if (!GetMainModuleSection(".rdata", 7, info)) {
			return false;
		}
		addr = info.addr;
		size = info.size;
		return true;
	}


	bool GetMainModuleDataInfo(duint& addr, duint& size)
	{
		using Script::Module::ModuleSectionInfo;

		ModuleSectionInfo info;
		if (!GetMainModuleSection(".data", 6, info)) {
			return false;
		}
		addr = info.addr;
		size = info.size;
		return true;
	}


	std::vector<duint> FindMemAll(duint start, duint size, const char* pattern, size_t max)
	{
		std::vector<duint> result;
		duint pattern_size = std::strlen(pattern);
		if (pattern_size > size) {
			return result;
		}

		const duint end = start + size;
		const duint last = end - pattern_size;

		duint rest = size;
		duint ptr = start;
		size_t hit = 0;
		while (ptr <= last) {
			duint p = Script::Pattern::FindMem(ptr, rest, pattern);
			if (p == 0) {
				break;
			}
			result.push_back(p);
			hit++;
			ptr = p + 1;
			rest = end - ptr;

			if (max != 0 && hit >= max) {
				break;
			}
		}

		return result;
	}


	bool OpenSelectionDialog(const char* Title, const char* Filter, bool Save, bool(*Callback)(char*))
	{
		// Open a file dialog to select the map or sig
		char buffer[MAX_PATH];
		memset(buffer, 0, sizeof(buffer));

		OPENFILENAMEA ofn;
		memset(&ofn, 0, sizeof(OPENFILENAMEA));

		ofn.lStructSize = sizeof(OPENFILENAMEA);
		ofn.hwndOwner = GuiGetWindowHandle();
		ofn.lpstrFilter = Filter;
		ofn.lpstrFile = buffer;
		ofn.nMaxFile = ARRAYSIZE(buffer);
		ofn.lpstrTitle = Title;
		ofn.Flags = OFN_FILEMUSTEXIST;

		if (Save)
		{
			ofn.lpstrDefExt = strchr(Filter, '\0') + 3;
			ofn.Flags = OFN_OVERWRITEPROMPT;

			if (!GetSaveFileNameA(&ofn))
				return false;
		}
		else
		{
			if (!GetOpenFileNameA(&ofn))
				return false;
		}

		if (!Callback(buffer))
		{
			_plugin_logprintf("An error occurred while applying the file\n");
			return false;
		}

		return true;
	}

} // Util