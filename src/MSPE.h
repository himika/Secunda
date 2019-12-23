#pragma once

#include <string_view>
#include <cassert>

// microsoft portable executable
namespace MSPE
{
	class Module;
	class Session;


	// Module
	class Module
	{
	protected:
		class pointer_t
		{
		public:
			pointer_t() = delete;
			pointer_t(const pointer_t&) = delete;
			constexpr explicit pointer_t(uintptr_t a_addr) : _addr(a_addr) {}

			template <typename Ty, std::enable_if_t<std::is_pointer_v<Ty>, std::nullptr_t> = nullptr>
			inline operator Ty() {
				return reinterpret_cast<Ty>(_addr);
			}
			template <typename Ty, std::enable_if_t<std::is_member_function_pointer_v<Ty>, std::nullptr_t> = nullptr>
			inline operator Ty() {
				return *reinterpret_cast<Ty*>(&_addr);
			}

		protected:
			uintptr_t _addr;
		};

	public:
		static uintptr_t base();
		static size_t size();

		static inline uintptr_t addr(std::uint32_t a_rva) {
			assert(a_rva < size());
			return base() + a_rva;
		}

		static inline pointer_t ptr(std::uint32_t a_rva) {
			return pointer_t(addr(a_rva));
		}

		static inline std::uint32_t rva(uintptr_t a_addr) {
			assert(contains(a_addr));
			return a_addr - base();
		}
		template <class T, std::enable_if_t<std::is_pointer_v<T>, std::nullptr_t> = nullptr>
		static inline std::uint32_t rva(T pointer_t) {
			return rva(reinterpret_cast<uintptr_t>(pointer_t));
		}
		template <class T, std::enable_if_t<std::is_member_function_pointer_v<T>, std::nullptr_t> = nullptr>
		static inline std::uint32_t rva(T pointer_t) {
			return rva(*reinterpret_cast<uintptr_t*>(&pointer_t));
		}

		static inline bool contains(uintptr_t a_addr) {
			return (base() <= a_addr) && (a_addr < base() + size());
		}
		template <class T, std::enable_if_t<std::is_pointer_v<T>, std::nullptr_t> = nullptr>
		static inline bool contains(T pointer_t) {
			return contains(reinterpret_cast<uintptr_t>(pointer_t));
		}
		template <class T, std::enable_if_t<std::is_member_function_pointer_v<T>, std::nullptr_t> = nullptr>
		static inline std::uint32_t contains(T pointer_t) {
			return contains(*reinterpret_cast<uintptr_t*>(&pointer_t));
		}
	};

	// Section
	class Section
	{
	public:
		enum class ID
		{
			kCode,
			kRData,
			kData,
			kTotal
		};

		Section() = delete;

		static const Section& Get(ID a_id);

		inline uintptr_t base() const {
			return _base;
		}
		inline size_t size() const {
			return _size;
		}
		inline std::uint32_t rva() const {
			return _rva;
		}
		inline const char* name() const {
			return _name;
		}
		inline bool contains(uintptr_t a_addr) const {
			return (base() <= a_addr) && (a_addr < base() + size());
		}
		template <class T>
		inline bool contains(T* pointer_t) const {
			return contains(reinterpret_cast<uintptr_t>(pointer_t));
		}

		template <class T = void>
		inline explicit operator T* () const
		{
			return reinterpret_cast<T*>(_base);
		}

		template <class T>
		inline operator std::basic_string_view<T>() const {
			auto start = static_cast<T*>(*this);
			auto size = _size / sizeof(T);
			return std::basic_string_view(start, size);
		}

	//private:
		explicit constexpr Section(const char* a_name, uintptr_t a_base = 0, size_t a_size = 0, std::uint32_t a_rva = 0) :
			_name(a_name),
			_base(a_base),
			_size(a_size),
			_rva(a_rva)
		{}

		// members
		const char*		_name;
		uintptr_t		_base;
		size_t			_size;
		std::uint32_t	_rva;
	};
}