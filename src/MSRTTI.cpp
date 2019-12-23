#include "pch.h"
#include "MSRTTI.h"
#include <typeinfo>
#include <cassert>

using MSPE::Module;
using MSPE::Section;


namespace MSRTTI
{
	const char* TypeDescriptor::name() const noexcept {
		auto* info = reinterpret_cast<const std::type_info*>(this);
		return info->name();
	}

	uintptr_t RVABase::Get() const
	{
		return is_good() ? Module::addr(_rva) : 0;
	}

	bool TypeDescriptor::IsValid() const
	{
		uintptr_t addr = reinterpret_cast<uintptr_t>(this);
		return (addr & 0x07) == 0 && Section::Get(kBelongID).contains(addr);
	}

	bool BaseClassArray::IsValid() const
	{
		uintptr_t addr = reinterpret_cast<uintptr_t>(this);
		return (addr & 0x03) == 0 && Section::Get(kBelongID).contains(addr);
	}

	bool BaseClassDescriptor::IsValid() const
	{
		uintptr_t addr = reinterpret_cast<uintptr_t>(this);
		return (addr & 0x03) == 0 && Section::Get(kBelongID).contains(addr);
	}

	bool ClassHierarchyDescriptor::IsValid() const
	{
		uintptr_t addr = reinterpret_cast<uintptr_t>(this);
		return (addr & 0x03) == 0 && Section::Get(kBelongID).contains(addr);
	}

	bool CompleteObjectLocator::IsValid() const
	{
		uintptr_t addr = reinterpret_cast<uintptr_t>(this);
		return (addr & 0x03) == 0 && Section::Get(kBelongID).contains(addr);
	}

	bool VTable::IsValid() const
	{
		uintptr_t addr = reinterpret_cast<uintptr_t>(this);
		return (addr & 0x07) == 0 && Section::Get(kBelongID).contains(addr);
	}

	CompleteObjectLocator* VTable::GetCompleteObjectLocator() const
	{
		auto addr = reinterpret_cast<uintptr_t>(this);
		CompleteObjectLocator* col = *reinterpret_cast<CompleteObjectLocator**>(addr - sizeof(uintptr_t));
		auto& section = Section::Get(CompleteObjectLocator::kBelongID);
		if (!section.contains(col)) {
			return nullptr;
		}

		return col;
	}
}
