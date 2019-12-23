#include "pch.h"
#include "MSPE.h"
#include <vector>
#include <algorithm>	// min
#include <cctype>		// tolower
#include <cassert>
#include <Windows.h>
//#include <libloaderapi.h>		// GetModuleHandle

namespace MSPE
{
	uintptr_t Module::base()
	{
		return Script::Module::GetMainModuleBase();
	}

	size_t Module::size()
	{
		return Script::Module::GetMainModuleSize();
	}


	const Section& Section::Get(ID a_id)
	{
		assert(a_id < ID::kTotal);

		static std::vector<Section> sections = {
			Section{".text"},	// ER--- executable code
			Section{".rdata"},	// -R--- read-only initialized data 
			Section{".data"}	// -RW-- initialized data
		};

		if (sections[0]._base == 0) {
			ListInfo listInfo;
			Script::Module::GetMainModuleSectionList(&listInfo);
			Script::Module::ModuleSectionInfo* sectionInfo(static_cast<Script::Module::ModuleSectionInfo*>(listInfo.data));

			uintptr_t moduleBase = Module::base();

			for (auto& section : sections) {
				for (int i = 0; i < listInfo.count; ++i) {
					auto& elem = sectionInfo[i];
					auto length = std::min<size_t>(std::strlen(section._name) + 1, sizeof(elem.name));
					if (std::memcmp(elem.name, section._name, length) == 0) {
						section._base = elem.addr;
						section._size = elem.size;
						section._rva = elem.addr - moduleBase;
						break;
					}
				}
			}

			BridgeFree(sectionInfo);
		}

		return sections[(std::ptrdiff_t)a_id];
	}
}