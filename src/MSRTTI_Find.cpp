#include "pch.h"
#include "MSRTTI.h"
#include "Util.h"
#include <functional>	// boyer_moore_searcher
#include <sstream>
#include <memory>
#include <DbgHelp.h>
#pragma comment(lib, "DbgHelp")

using MSPE::Module;
using MSPE::Section;

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




namespace MSRTTI
{
	static const VTable* FindVTable(const std::basic_string_view<uint8_t>& view, duint a_colAddr)
	{
		auto& section = Section::Get(VTable::kBelongID);

		const uintptr_t* begin = reinterpret_cast<const uintptr_t*>(view.data());
		const uintptr_t* end = reinterpret_cast<const uintptr_t*>(view.data() + view.size());
		for (auto iter = begin; iter < end; ++iter) {
			if (*iter == a_colAddr) {
				const VTable* vtable = reinterpret_cast<const VTable*>(iter + 1);
				if ((duint(vtable) & 0x07) == 0) {
					return vtable;
				}
			}
		}
		return nullptr;
	}


	static const CompleteObjectLocator* FindCompleteObjectLocator(const std::basic_string_view<uint8_t>& view, duint a_typeDescAddr)
	{
		auto& section = Section::Get(CompleteObjectLocator::kBelongID);
		auto rva = Module::rva(a_typeDescAddr);

		const uint32_t* begin = reinterpret_cast<const uint32_t*>(view.data());
		const uint32_t* end = reinterpret_cast<const uint32_t*>(view.data() + view.size());
		for (auto iter = begin; iter < end; ++iter) {
			if (*iter == rva) {
				if (iter[1] < section.rva()) {
					continue;
				}

				auto addr = reinterpret_cast<uintptr_t>(iter);
				auto col = reinterpret_cast<CompleteObjectLocator*>(addr - offsetof(CompleteObjectLocator, typeDescriptor));
				if (col->offset != 0) {
					continue;
				}

				return col;
			}
		}

		return nullptr;
	}


	static bool FindTypeDescriptors(const std::basic_string_view<uint8_t>& view, std::deque<TypeDescriptor*>& result)
	{
		bool is_ok[256];
		for (unsigned i = 0; i < 256u; ++i) {
			is_ok[i] = false;
		}
		for (unsigned i = '0'; i <= '9'; ++i) {
			is_ok[i] = true;
		}
		for (unsigned i = 'A'; i <= 'Z'; ++i) {
			is_ok[i] = true;
		}
		for (unsigned i = 'a'; i <= 'z'; ++i) {
			is_ok[i] = true;
		}
		is_ok['_'] = true;
		is_ok['@'] = true;
		is_ok['.'] = true;
		is_ok['?'] = true;
		is_ok['$'] = true;

		duint typeinfo_vtable = 0;
		size_t pos = 0;
		size_t i = 0;
		size_t len = 0;
		while (i < view.length()) {
			if (is_ok[view[i]]) {
				++i;
				++len;
			}
			else {
				if (view[i] == 0 && len >= 4 && view[pos] == '.' && view[pos+1] == '?') {
					const char* name = reinterpret_cast<const char*>(&view[pos]);

					auto* typeDesc = reinterpret_cast<TypeDescriptor*>(reinterpret_cast<uintptr_t>(name) - offsetof(TypeDescriptor, decorated_name));
					duint vtableAddr = (duint)typeDesc->vtable;

					if (vtableAddr && Section::Get(VTable::kBelongID).contains(vtableAddr)) {
						if (!typeinfo_vtable) {
							duint colAddr = Script::Memory::ReadPtr(vtableAddr - sizeof(uintptr_t));
							if (colAddr && Section::Get(CompleteObjectLocator::kBelongID).contains(colAddr)) {
								CompleteObjectLocator col;
								duint readSize = 0;
								if (!Script::Memory::Read(colAddr, &col, sizeof(col), &readSize)) {
									_plugin_logprintf("col(%p) read error\n", colAddr);
									return false;
								}
								const TypeDescriptor* td = col.typeDescriptor;
								if (td && td->IsValid()) {
									duint vt = Script::Memory::ReadPtr((duint)&td->vtable);
									if (vt == vtableAddr) {
										typeinfo_vtable = vtableAddr;
									}
								}
							}
						}

						if (vtableAddr == typeinfo_vtable) {
							result.push_back(typeDesc);
						}
					}
				}

				i += 8;
				i &= 0xFFFFFFF8;
				pos = i;
				len = 0;
			}
		}

		return true;
	}


	bool Find(std::deque<std::tuple<std::string, duint, duint>>& result)
	{
		duint sizeRead;

		//
		// メモリ確保
		//
		auto& dataSection = Section::Get(Section::ID::kData);
		b_unique_ptr<uint8_t[]> data(static_cast<uint8_t*>(BridgeAlloc(dataSection.size())));
		sizeRead = 0;
		if (!Script::Memory::Read(dataSection.base(), data.get(), dataSection.size(), &sizeRead)) {
			_plugin_logprint(".data read error\n");
			return false;
		}
		std::basic_string_view<uint8_t> dataView(data.get(), dataSection.size());

		auto& rdataSection = Section::Get(Section::ID::kRData);
		sizeRead = 0;
		b_unique_ptr<uint8_t[]> rdata(static_cast<uint8_t*>(BridgeAlloc(rdataSection.size())));
		if (!Script::Memory::Read(rdataSection.base(), rdata.get(), rdataSection.size(), &sizeRead)) {
			_plugin_logprint(".rdata read error\n");
			return false;
		}
		std::basic_string_view<uint8_t> rdataView(rdata.get(), rdataSection.size());

		_plugin_logprint("start analysis\n");

		//
		// TypeDescriptor検索
		//
		std::deque<TypeDescriptor*> typeDescroptors;
		if (!FindTypeDescriptors(dataView, typeDescroptors)) {
			_plugin_logprint("TypeDescriptor find error\n");
			return false;
		}

		//
		// RTTI検索
		//
		for (TypeDescriptor* typeDesc : typeDescroptors) {
			duint typeDescOffset = (duint)typeDesc - (duint)data.get();
			duint typeDescAddr = dataSection.base() + typeDescOffset;

			const CompleteObjectLocator* col = FindCompleteObjectLocator(rdataView, typeDescAddr);
			if (!col) {
				continue;
			}
			duint colOffset = (duint)col - (duint)rdata.get();
			duint colAddr = rdataSection.base() + colOffset;

			const VTable* vtable = FindVTable(rdataView, colAddr);
			if (!vtable) {
				continue;
			}
			duint vtableOffset = (duint)vtable - (duint)rdata.get();
			duint vtableAddr = rdataSection.base() + vtableOffset;

			const char* name = typeDesc->name();
			if (!name) {
				continue;
			}

			//
			// デマングル
			//
			char buff[4096];
			std::ostringstream oss;
			oss << "?g@@3" << &typeDesc->decorated_name[3] << "A";
			auto nameLen = UnDecorateSymbolName(oss.str().c_str(), buff, sizeof(buff), UNDNAME_COMPLETE);
			std::string demangledName;
			if (std::memcmp("class ", buff, 6) == 0) {
				demangledName = &buff[6];
			}
			else if (std::memcmp("struct ", buff, 7) == 0) {
				demangledName = &buff[7];
			}
			demangledName.pop_back();
			demangledName.pop_back();

			result.push_back({ demangledName, typeDescAddr, vtableAddr });
		}

		return true;
	}


	void Analyse()
	{
		std::deque<std::tuple<std::string, duint, duint>> rttis;
		if (MSRTTI::Find(rttis)) {

			GuiReferenceInitialize("RTTI");
			GuiReferenceAddColumn(16, GuiTranslateText("Address"));
			GuiReferenceAddColumn(60, GuiTranslateText("Name"));
			GuiReferenceSetRowCount(rttis.size() * 2);
			GuiReferenceSetProgress(0);

			char temp[32];
			duint idx = 0;
			for (auto& tpl : rttis) {
				const std::string& name = std::get<0>(tpl);
				duint typeDesc = std::get<1>(tpl);
				duint vtable = std::get<2>(tpl);

				std::string typeDescName = name + "::type_info";
				std::string vtableName = name + "::vtable";

				//Util::SetLabel(typeDescName, typeDesc);
				//Util::SetLabel(vtableName, vtable);

				sprintf_s(temp, "%p", (PVOID)typeDesc);
				GuiReferenceSetCellContent(idx, 0, temp);
				GuiReferenceSetCellContent(idx, 1, typeDescName.c_str());
				idx++;
				sprintf_s(temp, "%p", (PVOID)vtable);
				GuiReferenceSetCellContent(idx, 0, temp);
				GuiReferenceSetCellContent(idx, 1, vtableName.c_str());
				idx++;
			}

			GuiReferenceSetProgress(100);
			GuiUpdateAllViews();
		}
	}
}