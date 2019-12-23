#pragma once

#include "MSPE.h"
#include <string>
#include <string_view>
#include <deque>

namespace MSRTTI
{
	bool Find(std::deque<std::tuple<std::string, duint, duint>>& result);
	void Analyse();

	class RVABase;
	template <class> class RVA;
	struct TypeDescriptor;
	struct BaseClassDescriptor;
	struct ClassHierarchyDescriptor;
	struct CompleteObjectLocator;
	class VTable;

	// relative virtual address
	class RVABase
	{
	public:
		constexpr RVABase() : _rva(0) {}
		constexpr RVABase(std::uint32_t a_rva) : _rva(a_rva) {}
		~RVABase() = default;

		explicit inline operator bool() const {
			return is_good();
		}
		inline size_t offset() const {
			return _rva;
		}
		inline size_t rva() const {
			return _rva;
		}

		uintptr_t Get() const;

	protected:
		bool is_good() const {
			return _rva != 0;
		}

		// members
		std::uint32_t _rva;		// 00
	};


	template <class T>
	class RVA : public RVABase
	{
	public:
		constexpr RVA() : RVABase() {}
		constexpr RVA(std::uint32_t a_rva) : RVABase(a_rva) {}
		~RVA() = default;

		inline T* Get() const {
			return reinterpret_cast<T*>(RVABase::Get());
		}
		inline operator T* () const {
			return Get();
		}
		inline T& operator*() const {
			return *Get();
		}
		inline T* operator->() const {
			return Get();
		}
		inline T* operator[](std::ptrdiff_t a_idx) const {
			return Get() + a_idx;
		}
	};
	static_assert(sizeof(RVA<void*>) == 0x4);


	// RTTI 0
	// (same as std::type_info)
	struct TypeDescriptor
	{
		static constexpr auto kBelongID = MSPE::Section::ID::kData;

		bool IsValid() const;

		const char* name() const noexcept;
		const char* raw_name() const {
			return decorated_name;
		}

		// members
		VTable*		vtable;				// 00 - vtable of std::type_info
		const char*	undecorated_name;	// 08 - _UndecoratedName
		const char	decorated_name[6];	// 10 - _DecoratedName
	};
	static_assert(sizeof(TypeDescriptor) == 0x18);	// can be larger
	

	// RTTI 1
	struct BaseClassDescriptor
	{
		static constexpr auto kBelongID = MSPE::Section::ID::kRData;

		struct PMD
		{
			std::int32_t	mDisp;	// 0 - member displacement
			std::int32_t	pDisp;	// 4 - vbtable displacement, -1: vtable is at displacement PMD.mDisp inside the class
			std::int32_t	vDisp;	// 8 - displacement within vbtable
		};
		static_assert(sizeof(PMD) == 0xC);

		enum class Attribute : std::uint32_t
		{
			kNone						= 0,
			kNotVisible					= 1 << 0,
			kAmbiguous					= 1 << 1,
			kPrivate					= 1 << 2,
			kPrivOrProtBase				= 1 << 3,
			kVirtual					= 1 << 4,
			kNonpolymorphic				= 1 << 5,
			kHasHierarchyDescriptor		= 1 << 6
		};

		bool IsValid() const;

		// members
		RVA<TypeDescriptor>	typeDescriptor;		// 00 - ref to TypeDescriptor (RTTI 0) for class
		std::uint32_t		numContainedBases;	// 04 - count of extended classes in BaseClassArray (RTTI 2)
		PMD					where;				// 08 - member displacement structure
		Attribute			attributes;			// 14 - bit flags, usually 0
	};
	static_assert(sizeof(BaseClassDescriptor) == 0x18);

	// RTTI 2
	struct BaseClassArray
	{
		static constexpr auto kBelongID = MSPE::Section::ID::kRData;

		bool IsValid() const;

		inline BaseClassDescriptor* GetAt(std::ptrdiff_t idx) const {
			return baseClassDescs[idx].Get();
		}
		inline BaseClassDescriptor* operator[](std::ptrdiff_t idx) const {
			return GetAt(idx);
		}

		// members
		RVA<BaseClassDescriptor>	baseClassDescs[1];
	};


	// RTTI 3
	struct ClassHierarchyDescriptor
	{
		static constexpr auto kBelongID = MSPE::Section::ID::kRData;

		enum class Attribute : std::uint32_t
		{
			kNone						= 0,
			kMultipleInheritance		= 1 << 0,
			kVirtualInheritance			= 1 << 1,
			kAmbiguousInheritance		= 1 << 2
		};

		bool IsValid() const;

		// members
		std::uint32_t					signature;			// 00
		Attribute						attributes;			// 04 - bit flags
		std::uint32_t					numBaseClasses;		// 08 - count of RTTI 1 ref entries in RTTI 2 array
		//RVA<RVA<BaseClassDescriptor>>	pBaseClassArray;	// 0C - ref to BaseClassArray (RTTI 2)
		RVA<BaseClassArray>				pBaseClassArray;	// 0C - ref to BaseClassArray (RTTI 2)
	};
	static_assert(sizeof(ClassHierarchyDescriptor) == 0x10);


	// RTTI 4
	struct CompleteObjectLocator
	{
		static constexpr auto kBelongID = MSPE::Section::ID::kRData;

		bool IsValid() const;

		enum class Signiture : std::uint32_t
		{
			kSignature32 = 0,
			kSignature64 = 1
		};

		static CompleteObjectLocator* Find(const TypeDescriptor* a_typeDesc, std::uint32_t a_offset = 0);

		// members
		Signiture						signature;			// 00 - 0: 32-bit, 1:64-bit
		std::uint32_t					offset;				// 04 - offset of vbtable within class
		std::uint32_t					ctorDispOffset;		// 08 - constructor displacement offset
		RVA<TypeDescriptor>				typeDescriptor;		// 0C - ref to TypeDescriptor (RTTI 0) for class
		RVA<ClassHierarchyDescriptor>	classDescriptor;	// 10 - ref to ClassHierarchyDescriptor (RTTI 3)
	};
	static_assert(sizeof(CompleteObjectLocator) == 0x14);


	class VTable
	{
	public:
		static constexpr auto kBelongID = MSPE::Section::ID::kRData;

		VTable() = delete;

		bool IsValid() const;

		CompleteObjectLocator* GetCompleteObjectLocator() const;
	private:
		// members
		void*	vftable[1];		// 00
	};
}
