// This is free and unencumbered software released into the public domain.

// Anyone is free to copy, modify, publish, use, compile, sell, or
// distribute this software, either in source code form or as a compiled
// binary, for any purpose, commercial or non-commercial, and by any
// means.

// In jurisdictions that recognize copyright laws, the author or authors
// of this software dedicate any and all copyright interest in the
// software to the public domain. We make this dedication for the benefit
// of the public at large and to the detriment of our heirs and
// successors. We intend this dedication to be an overt act of
// relinquishment in perpetuity of all present and future rights to this
// software under copyright law.

// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
// IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR
// OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
// ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
// OTHER DEALINGS IN THE SOFTWARE.

// For more information, please refer to <https://unlicense.org>

#pragma once

// The following macros can be defined by the user:
// 1. SATOMI_ASSERT(...) - basic assert to avoid including <assert.h>
// 2. SATOMI_DO_NOT_DEFINE_MEMORY_ORDER - skip defining memory_order enum
// 3. SATOMI_DO_NOT_DEFINE_MACROS - skip defining usage macros
// 4. SATOMI_ARM_USE_LSE128 - to use SWPP* instructions for 128 bit atomic_exchange/store
//    Unfortunately no compiler currently provides a macro definition to check for this automatically so the user has to define something
//    and '+lse128' still needs to be enabled otherwise it will fail to compile, i.e. '-march=armv9.4-a+lse128'
//    https://developer.arm.com/documentation/ddi0602/2024-03/Base-Instructions/SWPP--SWPPA--SWPPAL--SWPPL--Swap-quadword-in-memory-
// 5. SATOMI_BREAK_ARM_MSVC_ABI_COMPATIBILITY - forces NON-conformance on clang/mingw with MSVC STL for ARM64 (without LSE) on Windows.
//    By default an extra memory barrier (dmb ish) will be inserted after any successful stores
//    (atomic_compare_exchange_*, atomic_exchange, atomic_store, atomic_fetch_*) if memory_order == seq_cst.
//    Use this if you want to avoid the cost of the extra fence if you're not interfacing with the MSVC STL. For more info:
//    https://reviews.llvm.org/D141748
//    https://github.com/llvm/llvm-project/commit/1ea201d73be2fdf03347e9c6be09ebed5f8e0e00

#ifndef SATOMI_ASSERT
  #include <assert.h>
  #define SATOMI_ASSERT(condition) assert(condition)
#endif

#ifndef SATOMI_DO_NOT_DEFINE_MEMORY_ORDER

  typedef enum memory_order
  {
    memory_order_relaxed,
    memory_order_consume,
    memory_order_acquire,
    memory_order_release,
    memory_order_acq_rel,
    memory_order_seq_cst
  } memory_order;

#endif

#ifdef __cplusplus
extern "C"
{
#endif

#if defined(_WIN64)

  int __stdcall WaitOnAddress(volatile void *Address, void *CompareAddress, unsigned __int64 AddressSize, unsigned long dwMilliseconds);
  void __stdcall WakeByAddressSingle(void *Address);
  void __stdcall WakeByAddressAll(void *Address);
  #pragma comment(lib, "Synchronization.lib")

#elif defined(LINUX) || defined(__linux__)

  #if !defined(__x86_64__) && !defined(__aarch64__)
    #error Unsupported processor
  #endif

#elif defined (__APPLE__)

  #if !defined(__x86_64__) && !defined(__aarch64__)
    #error Unsupported processor
  #endif

  // private macOS api (Darwin 16, macOS 10.12), needs to be weakly linked or have used dlsym to use
  // https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/sys/ulock.h#L68
  // for more info:
  // https://shift.click/blog/futex-like-apis/#darwin-macos-ios-tvos-watchos-and-more
  // https://github.com/llvm/llvm-project/blob/dc3ae608e95a62e0a4a2532d87bf34ce7c9714ef/libcxx/src/atomic.cpp#L82
  #define SATOMI_UL_COMPARE_AND_WAIT 1
  #define SATOMI_ULF_WAKE_ALL        0x00000100

  int __ulock_wait(__UINT32_TYPE__ operation, void *addr, __UINT64_TYPE__ value, __UINT32_TYPE__ timeout) __attribute__((weak_import));
  int __ulock_wake(__UINT32_TYPE__ operation, void *addr, __UINT64_TYPE__ wake_value) __attribute__((weak_import));

#else

  #error Unsupported platform

#endif

#if defined(_MSC_VER) && !defined(__clang__)
  #define SATOMI_ALIGNAS(x) __declspec(align(x))
  #define SATOMI_U64 unsigned __int64
#else
  #define SATOMI_ALIGNAS(x) __attribute__((aligned(x)))
  #define SATOMI_U64 __UINT64_TYPE__
#endif

#ifdef __cplusplus
  #define SATOMI_BOOL bool
#else
  #define SATOMI_BOOL _Bool
#endif

// is the type a power-of-2 and is it self-aligned (i don't know of any architectures that support unaligned atomics)
#define SATOMI_CHECK_PRECONDITIONS(size, x) \
  (((SATOMI_ASSERT((size & (size - 1)) == 0), (size & (size - 1)) == 0) && \
    (SATOMI_ASSERT(((SATOMI_U64)(x) % size) == 0), (((SATOMI_U64)(x) % size) == 0))) || (SATOMI_TRAP(), 1))

#if defined(_MSC_VER) && !defined(__clang__)

  void _ReadWriteBarrier(void);
  // pragma to avoid deprecation warnings
  #define SATOMI_COMPILER_BARRIER() _Pragma("warning(push)") _Pragma("warning(disable : 4996)") _ReadWriteBarrier() _Pragma("warning(pop)")
  __declspec(noreturn) void __fastfail(unsigned int code);
  #pragma intrinsic(__fastfail)
  #define SATOMI_TRAP() __fastfail(/*FAST_FAIL_FATAL_APP_EXIT*/ 7)
  void *__cdecl memcpy(void *destination, const void *source, SATOMI_U64 count);
  // safely reinterpreting arbitrary types to integrals (padding bits are NOT taken into account)
  #define SATOMI_MEMCPY(size, to, from) memcpy(to, from, size)
  #define SATOMI_INLINE __forceinline

  #define SATOMI_CHOOSE_SIZE(macro, size, base) \
    if (size == 1) { SATOMI_CHOOSE_MEMORY_ORDER(order, ret.v[0] = base##8, (macro(__int8))) }        \
    else if (size == 2) { SATOMI_CHOOSE_MEMORY_ORDER(order, ret.v[0] = base##16, (macro(__int16))) } \
    else if (size == 4) { SATOMI_CHOOSE_MEMORY_ORDER(order, ret.v[0] = base, (macro(long))) }        \
    else if (size == 8) { SATOMI_CHOOSE_MEMORY_ORDER(order, ret.v[0] = base##64, (macro(__int64))) }

  #if defined(_M_ARM64) || defined(_M_ARM64EC)

    __int64 __ldrexd(const volatile __int64 *);
    void __dmb(unsigned int _Type);
    #pragma intrinsic(__dmb)

    #define SATOMI_DEFINE_MEMORY_ORDERS(X, args) X args; X##_nf args; X##_acq args; X##_rel args;
    #define SATOMI_CHOOSE_MEMORY_ORDER(order, X, args) \
      if (order == memory_order_relaxed) { X##_nf args; } \
      else if (order == memory_order_consume || order == memory_order_acquire) { X##_acq args; } \
      else if (order == memory_order_release) { X##_rel args; } \
      else if (order == memory_order_acq_rel || order == memory_order_seq_cst) { X args; } \
      else { __fastfail(/*FAST_FAIL_FATAL_APP_EXIT*/ 7); }
    #define SATOMI_COMPILER_OR_MEMORY_BARRIER() __dmb(/*_ARM64_BARRIER_ISH*/ 0xB)

  #else

    #define SATOMI_DEFINE_MEMORY_ORDERS(X, args) X args;
    #define SATOMI_CHOOSE_MEMORY_ORDER(order, X, args) X args;
    // x86/x64 hardware only emits memory barriers inside _Interlocked intrinsics
    #define SATOMI_COMPILER_OR_MEMORY_BARRIER() SATOMI_COMPILER_BARRIER()
    long _InterlockedIncrement(long volatile * _Addend);

  #endif

  // necessary in order to not inject hidden memory ordering guarantees (like with /volatile:ms)
  // for more info https://learn.microsoft.com/en-us/cpp/intrinsics/arm-intrinsics?view=msvc-170#remarks
  __int8 __iso_volatile_load8(const volatile __int8 *location);
  __int16 __iso_volatile_load16(const volatile __int16 *location);
  __int32 __iso_volatile_load32(const volatile __int32 *location);
  __int64 __iso_volatile_load64(const volatile __int64 *location);
  void __iso_volatile_store8(volatile __int8 *location, __int8 value);
  void __iso_volatile_store16(volatile __int16 *location, __int16 value);
  void __iso_volatile_store32(volatile __int32 *location, __int32 value);
  void __iso_volatile_store64(volatile __int64 *location, __int64 value);

  SATOMI_DEFINE_MEMORY_ORDERS(long _InterlockedCompareExchange, (long volatile *target, long exchange, long comparand))
  SATOMI_DEFINE_MEMORY_ORDERS(char _InterlockedCompareExchange8, (char volatile *target, char exchange, char comparand))
  SATOMI_DEFINE_MEMORY_ORDERS(short _InterlockedCompareExchange16, (short volatile *target, short exchange, short comparand))
  SATOMI_DEFINE_MEMORY_ORDERS(__int64 _InterlockedCompareExchange64, (__int64 volatile *target, __int64 exchange, __int64 comparand))

  SATOMI_DEFINE_MEMORY_ORDERS(unsigned char _InterlockedCompareExchange128, (__int64 volatile *target, __int64 high, __int64 low, __int64 *comparand))

  SATOMI_DEFINE_MEMORY_ORDERS(long _InterlockedAnd, (long volatile *target, long value))
  SATOMI_DEFINE_MEMORY_ORDERS(char _InterlockedAnd8, (char volatile *target, char value))
  SATOMI_DEFINE_MEMORY_ORDERS(short _InterlockedAnd16, (short volatile *target, short value))
  SATOMI_DEFINE_MEMORY_ORDERS(__int64 _InterlockedAnd64, (__int64 volatile *target, __int64 value))

  SATOMI_DEFINE_MEMORY_ORDERS(long _InterlockedExchange, (long volatile *target, long value))
  SATOMI_DEFINE_MEMORY_ORDERS(char _InterlockedExchange8, (char volatile *target, char value))
  SATOMI_DEFINE_MEMORY_ORDERS(short _InterlockedExchange16, (short volatile *target, short value))
  SATOMI_DEFINE_MEMORY_ORDERS(__int64 _InterlockedExchange64, (__int64 volatile *target, __int64 value))

  SATOMI_DEFINE_MEMORY_ORDERS(long _InterlockedExchangeAdd, (long volatile *target, long value))
  SATOMI_DEFINE_MEMORY_ORDERS(char _InterlockedExchangeAdd8, (char volatile *target, char value))
  SATOMI_DEFINE_MEMORY_ORDERS(short _InterlockedExchangeAdd16, (short volatile *target, short value))
  SATOMI_DEFINE_MEMORY_ORDERS(__int64 _InterlockedExchangeAdd64, (__int64 volatile *target, __int64 value))

  SATOMI_DEFINE_MEMORY_ORDERS(long _InterlockedOr, (long volatile *target, long value))
  SATOMI_DEFINE_MEMORY_ORDERS(char _InterlockedOr8, (char volatile *target, char value))
  SATOMI_DEFINE_MEMORY_ORDERS(short _InterlockedOr16, (short volatile *target, short value))
  SATOMI_DEFINE_MEMORY_ORDERS(__int64 _InterlockedOr64, (__int64 volatile *target, __int64 value))

  SATOMI_DEFINE_MEMORY_ORDERS(long _InterlockedXor, (long volatile *target, long value))
  SATOMI_DEFINE_MEMORY_ORDERS(char _InterlockedXor8, (char volatile *target, char value))
  SATOMI_DEFINE_MEMORY_ORDERS(short _InterlockedXor16, (short volatile *target, short value))
  SATOMI_DEFINE_MEMORY_ORDERS(__int64 _InterlockedXor64, (__int64 volatile *target, __int64 value))

  #undef SATOMI_DEFINE_MEMORY_ORDERS

#else

  #if defined(__GNUC__) && !defined(__clang__)
    #pragma GCC diagnostic push
    #pragma GCC diagnostic ignored "-Wstringop-overflow"
    #pragma GCC diagnostic ignored "-Wstringop-overread"
  #elif defined(__clang__)
    #pragma GCC diagnostic push
    #pragma GCC diagnostic ignored "-Wvariadic-macro-arguments-omitted"
  #endif

  #define SATOMI_TRAP() __builtin_trap()
  // safely reinterpreting arbitrary types to integrals (padding bits are NOT taken into account)
  #define SATOMI_MEMCPY(size, to, from) __builtin_memcpy(to, from, size)
  #define SATOMI_INLINE inline __attribute__((always_inline))

  #if defined(_WIN32) && !defined(SATOMI_BREAK_ARM_MSVC_ABI_COMPATIBILITY)
    // stupid ABI fence by a stupid company
    #define SATOMI_MSVC_STL_SEQ_CST_FENCE "dmb ish\n\t"
  #else
    #define SATOMI_MSVC_STL_SEQ_CST_FENCE ""
  #endif

  #define SATOMI_CHOOSE_MEMORY_ORDER_ASM(order, ...)\
    if (order == memory_order_relaxed) { SATOMI_ATOMIC_ASM("", "", "", __VA_ARGS__) } \
    else if (order == memory_order_consume || order == memory_order_acquire) { SATOMI_ATOMIC_ASM("a", "", "", __VA_ARGS__) } \
    else if (order == memory_order_release) { SATOMI_ATOMIC_ASM("", "l", "", __VA_ARGS__) } \
    else if (order == memory_order_acq_rel) { SATOMI_ATOMIC_ASM("a", "l", "", __VA_ARGS__) } \
    else if (order == memory_order_seq_cst) { SATOMI_ATOMIC_ASM("a", "l", SATOMI_MSVC_STL_SEQ_CST_FENCE, __VA_ARGS__) } \
    else { __builtin_trap(); }

  #define SATOMI_CHECK_ALIGNMENT(alignment, x) (void)((decltype(sizeof(int))(&x) % alignment) == 0 || (__builtin_trap(), 1))

#endif

#if defined (LINUX) || defined(__linux__) || defined(__APPLE__)

  // align(64) to avoid false sharing between slots
  struct SATOMI_ALIGNAS(64) satomi__waiting_slot
  {
    int wait_count;
    int version;
  };

  #define SATOMI_WAITING_LIST_COUNT (1 << 7)

#if defined(__cplusplus) && defined(__clang__)
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wc++17-extensions"

  inline
#else
  __attribute__((__common__))
#endif
  struct satomi__waiting_slot satomi__waiter_list[SATOMI_WAITING_LIST_COUNT];

#if defined(__cplusplus) && defined(__clang__)
  #pragma clang diagnostic pop
#endif

  #define SATOMI_GET_WAITING_SLOT(address) (&satomi__waiter_list[((__UINTPTR_TYPE__)(address) >> 2) & (SATOMI_WAITING_LIST_COUNT - 1)])

#endif



SATOMI_INLINE void satomi__atomic_thread_fence(memory_order order)
{
#if defined(_MSC_VER) && !defined(__clang__)

  SATOMI_COMPILER_BARRIER();
  #if defined(_M_ARM64) || defined(_M_ARM64EC)
    if (order == memory_order_acquire || order == memory_order_consume)
      __dmb(/*_ARM64_BARRIER_ISHLD*/ 0x9);
    else
      SATOMI_COMPILER_OR_MEMORY_BARRIER();
  #else
    if (order == memory_order_seq_cst)
    {
    #pragma warning(push)
    #pragma warning(disable : 6001)  // "Using uninitialized memory 'guard'"
    #pragma warning(disable : 28113) // "Accessing a local variable guard via an Interlocked function:
                                     // This is an unusual usage which could be reconsidered."
      volatile long guard;
      (void)_InterlockedIncrement(&guard);
      SATOMI_COMPILER_BARRIER();
    #pragma warning(pop)
    }
  #endif

#elif defined (__x86_64__)

  if (order == memory_order_seq_cst)
  {
    unsigned char dummy = 0u;
    __asm__ __volatile__ ("lock; notb %0" : "+m" (dummy) : : "memory");
  }
  else if (order != memory_order_relaxed)
    __asm__ __volatile__ ("" ::: "memory");

#elif defined(__aarch64__)

  if (order != memory_order_relaxed)
  {
    if (order == memory_order_consume || order == memory_order_acquire)
      __asm__ __volatile__ ("dmb ishld\n\t" ::: "memory");
    else
      __asm__ __volatile__ ("dmb ish\n\t" ::: "memory");
  }

#endif
}

SATOMI_INLINE void satomi__atomic_signal_fence(memory_order order)
{
#if defined(_MSC_VER) && !defined(__clang__)

  if (order != memory_order_relaxed)
    SATOMI_COMPILER_BARRIER();

#else

  if (order != memory_order_relaxed)
    __asm__ __volatile__ ("" ::: "memory");

#endif
}



// Don't forget to clear padding!
SATOMI_INLINE SATOMI_BOOL satomi__atomic_compare_exchange_strong(SATOMI_U64 size,
  volatile void *target, void *expected, const void *desired, memory_order order)
{
  SATOMI_CHECK_PRECONDITIONS(size, target);
  if (size > 16)
  {
    SATOMI_ASSERT(0 && "Size of atomic is too large for this architecture");
    SATOMI_TRAP();
    return 0;
  }

#if defined(_MSC_VER) && !defined(__clang__)

  (void)order;

  struct SATOMI_ALIGNAS(16) int128__ { __int64 v[2]; } ret, d, e;
  d.v[0] = 0;
  e.v[0] = 0;
  SATOMI_MEMCPY(size, &d, desired);
  SATOMI_MEMCPY(size, &e, expected);

  #define SATOMI_HELPER(cast) (volatile cast *)target, (cast)d.v[0], (cast)e.v[0]
  SATOMI_CHOOSE_SIZE(SATOMI_HELPER, size, _InterlockedCompareExchange)
  #undef SATOMI_HELPER

  else if (size == 16)
  {
    (void)e;
    (void)ret;
    unsigned char result = 0;
    SATOMI_CHOOSE_MEMORY_ORDER(order, result = _InterlockedCompareExchange128, ((volatile __int64 *)target,
      d.v[1], d.v[0], (__int64 *)expected))

    return result != 0;
  }

  if (ret.v[0] == e.v[0])
    return 1;
  SATOMI_MEMCPY(size, expected, &ret);
  return 0;

#elif defined (__x86_64__)

  #define SATOMI_ATOMIC_ASM(type, affix)                  \
    __asm__ __volatile__                                  \
    (                                                     \
      "lock; cmpxchg" affix " %[desired], %[target]\n\t"  \
      "sete %[success]"                                   \
      : [target] "+m" (*(type *)target),                  \
        "+a" (*(type *)expected), [success] "=q" (success)\
      : [desired] "q" (*(type *)desired)                  \
      : "cc", "memory"                                    \
    )

  SATOMI_BOOL success = 0;
  if (size == 1) { SATOMI_ATOMIC_ASM(__UINT8_TYPE__, "b"); }
  else if (size == 2) { SATOMI_ATOMIC_ASM(__UINT16_TYPE__, "w"); }
  else if (size == 4) { SATOMI_ATOMIC_ASM(__UINT32_TYPE__, "l"); }
  else if (size == 8) { SATOMI_ATOMIC_ASM(__UINT64_TYPE__, "q"); }
  else if (size == 16)
  {
    SATOMI_U64 e[2], d[2];
    SATOMI_MEMCPY(size, &e, expected);
    SATOMI_MEMCPY(size, &d, desired);

    __asm__ __volatile__
    (
      "lock; cmpxchg16b %[target]\n\t"
      "sete %[success]\n\t"
      : [target] "+m" (*(__UINT64_TYPE__ *)target),
        "+a" (e[0]), "+d" (e[1]), [success] "=q" (success)
      : "b" (d[0]), "c" (d[1])
      : "cc", "memory"
    );

    SATOMI_MEMCPY(size, expected, &e);
  }

  return success;

  #undef SATOMI_ATOMIC_ASM

#elif defined(__aarch64__)

  // builtin CAS support with ARM LSE 1
  #ifdef __ARM_FEATURE_ATOMICS

    #define SATOMI_ATOMIC_ASM(load_order, store_order, _, type, affix, modifier)                          \
      __asm__ __volatile__                                                                                \
      (                                                                                                   \
        "cas" load_order store_order affix " " modifier "[expected], " modifier "[desired], %[target]\n\t"\
        : [target] "+Q" (*(type *)target), [expected] "+r" (ret)                                          \
        : [desired] "r" (*(type *)desired)                                                                \
        : "memory"                                                                                        \
      );

    #define SATOMI_PASTE_BLOCK(order, type, ...)                \
      type e, ret;                                              \
      SATOMI_MEMCPY(size, &e, expected);                        \
      ret = e;                                                  \
      SATOMI_CHOOSE_MEMORY_ORDER_ASM(order, type, __VA_ARGS__); \
      SATOMI_MEMCPY(size, expected, &ret);                      \
      return e == ret

    if (size == 1) { SATOMI_PASTE_BLOCK(order, __UINT8_TYPE__, "b", "%w"); }
    else if (size == 2) { SATOMI_PASTE_BLOCK(order, __UINT16_TYPE__, "h", "%w"); }
    else if (size == 4) { SATOMI_PASTE_BLOCK(order, __UINT32_TYPE__, "", "%w"); }
    else if (size == 8) { SATOMI_PASTE_BLOCK(order, __UINT64_TYPE__, "", "%x"); }
    else if (size == 16)
    {
      SATOMI_U64 e[2], d[2];
      SATOMI_MEMCPY(size, &e, expected);
      SATOMI_MEMCPY(size, &d, desired);

      // copies values to specific registers
      // on gcc hard register constraints can be used but those are not supported on clang
      // hardcoding caller saved registers (as per ARM64 linux ABI)
      // because ARM expects arguments to start at an even register and be contiguous
      register SATOMI_U64 x8 asm ("x8") = e[0];
      register SATOMI_U64 x9 asm ("x9") = e[1];
      register SATOMI_U64 x10 asm ("x10") = d[0];
      register SATOMI_U64 x11 asm ("x11") = d[1];

      #undef SATOMI_ATOMIC_ASM
      #define SATOMI_ATOMIC_ASM(load_order, store_order, ...)                                                         \
        __asm__ __volatile__                                                                                          \
        (                                                                                                             \
          "casp" load_order store_order " %x[expected_0], %x[expected_1], %x[desired_0], %x[desired_1], %[target]\n\t"\
          : [target] "+Q" (*(SATOMI_U64 *)target), [expected_0] "+r" (x8), [expected_1] "+r" (x9)                     \
          : [desired_0] "r" (x10), [desired_1] "r" (x11)                                                              \
          : "cc", "memory"                                                                                            \
        );

      SATOMI_CHOOSE_MEMORY_ORDER_ASM(order);

      SATOMI_BOOL success = e[0] == x8 && e[1] == x9;
      e[0] = x8;
      e[1] = x9;
      SATOMI_MEMCPY(size, expected, &e);
      return success;
    }

    #undef SATOMI_PASTE_BLOCK
    #undef SATOMI_ATOMIC_ASM

  #else

    #define SATOMI_ATOMIC_ASM(load_order, store_order, msvc_fence, type, suffix, modifier, /*zero extend instruction*/...)\
      __asm__ __volatile__                                                                                                \
      (                                                                                                                   \
        __VA_ARGS__                                                                                                       \
        "1:\n\t"                                                                                                          \
        "ld" load_order "xr" suffix " " modifier "[out], %[target]\n\t"                                                   \
        "cmp " modifier "[out], " modifier "[expected]\n\t"                                                               \
        "b.ne 2f\n\t"                                                                                                     \
        "st" store_order "xr" suffix " %w[success], " modifier "[desired], %[target]\n\t"                                 \
        "cbnz %w[success], 1b\n\t"                                                                                        \
        msvc_fence                                                                                                        \
        "2:\n\t"                                                                                                          \
        "cset %w[success], eq\n\t"                                                                                        \
        : [target] "+Q" (*(type *)target), [success] "=&r" (success), [out] "=&r" (out)                                   \
        : [desired] "r" (*(type *)desired), [expected] "r" (*(type *)expected)                                            \
        : "cc", "memory"                                                                                                  \
      );

    #define SATOMI_PASTE_BLOCK(order, type, ...)                \
      type out;                                                 \
      SATOMI_CHOOSE_MEMORY_ORDER_ASM(order, type, __VA_ARGS__); \
      SATOMI_MEMCPY(size, expected, &out);                      \
      return success

    SATOMI_BOOL success;
    if (size == 1) { SATOMI_PASTE_BLOCK(order, __UINT8_TYPE__, "b", "%w", "uxtb %w[expected], %w[expected]\n\t"); }
    else if (size == 2) { SATOMI_PASTE_BLOCK(order, __UINT16_TYPE__, "h", "%w", "uxth %w[expected], %w[expected]\n\t"); }
    else if (size == 4) { SATOMI_PASTE_BLOCK(order, __UINT32_TYPE__, "", "%w", ""); }
    else if (size == 8) { SATOMI_PASTE_BLOCK(order, __UINT64_TYPE__, "", "%x", ""); }
    else if (size == 16)
    {
      struct SATOMI_ALIGNAS(16) uint128__ { SATOMI_U64 v[2]; } out, e, d;
      SATOMI_MEMCPY(size, &e, expected);
      SATOMI_MEMCPY(size, &d, desired);

      unsigned success;

      #undef SATOMI_ATOMIC_ASM
      #define SATOMI_ATOMIC_ASM(load_order, store_order, msvc_fence, ...)               \
        __asm__ __volatile__                                                            \
        (                                                                               \
          "1:\n\t"                                                                      \
          "ld" load_order "xp %x[out_0], %x[out_1], %[target]\n\t"                      \
          "cmp %x[out_0], %x[expected_0]\n\t"                                           \
          "ccmp %x[out_1], %x[expected_1], #0, eq\n\t"                                  \
          "b.ne 2f\n\t"                                                                 \
          "st" store_order "xp %w[success], %x[desired_0], %x[desired_1], %[target]\n\t"\
          "cbnz %w[success], 1b\n\t"                                                    \
          msvc_fence                                                                    \
          "2:\n\t"                                                                      \
          "cset %w[success], eq\n\t"                                                    \
          : [success] "=&r" (success), [target] "+Q" (*(struct uint128__ *)target),     \
            [out_0] "=&r" (out.v[0]), [out_1] "=&r" (out.v[1])                          \
          : [desired_0] "r" (d.v[0]), [desired_1] "r" (d.v[1]),                         \
            [expected_0] "r" (e.v[0]), [expected_1] "r" (e.v[1])                        \
          : "cc", "memory"                                                              \
        );

      SATOMI_CHOOSE_MEMORY_ORDER_ASM(order)

      SATOMI_MEMCPY(size, expected, &out);

      return success;
    }

    #undef SATOMI_PASTE_BLOCK
    #undef SATOMI_ATOMIC_ASM

  #endif

#endif

  return 0;
}

// Don't forget to clear padding!
SATOMI_INLINE SATOMI_BOOL satomi__atomic_compare_exchange_weak(SATOMI_U64 size,
  volatile void *target, void *expected, const void *desired, memory_order order)
{
  SATOMI_CHECK_PRECONDITIONS(size, target);
  if (size > 16)
  {
    SATOMI_ASSERT(0 && "Size of atomic is too large for this architecture");
    SATOMI_TRAP();
    return 0;
  }

#if defined(_MSC_VER) && !defined(__clang__)

  // on msvc there aren't any weak versions of compare_exchange so forward to compare_exchange_strong
  return satomi__atomic_compare_exchange_strong(size, target, expected, desired, order);

#elif defined(__x86_64__)

  // compare_exchange_weak and compare_exchange_strong are identical on x86-64
  return satomi__atomic_compare_exchange_strong(size, target, expected, desired, order);

#elif defined(__aarch64__)

  // builtin CAS support with ARM LSE 1
  #ifdef __ARM_FEATURE_ATOMICS

    // if we have LSE support compare_exchange_weak/strong are identical
    // because compare_exchange_strong doesn't require loops
    return satomi__atomic_compare_exchange_strong(size, target, expected, desired, order);

  #else

    #pragma push_macro("SATOMI_MSVC_STL_SEQ_CST_FENCE")
    #undef SATOMI_MSVC_STL_SEQ_CST_FENCE
    #define SATOMI_MSVC_STL_SEQ_CST_FENCE "cbnz %w[success], 1f\n\t" "dmb ish\n\t"

    #define SATOMI_ATOMIC_ASM(load_order, store_order, msvc_fence, type, suffix, modifier, /*zero extend instruction*/...)\
      __asm__ __volatile__                                                                                                \
      (                                                                                                                   \
        __VA_ARGS__                                                                                                       \
        "ld" load_order "xr" suffix " " modifier "[out], %[target]\n\t"                                                   \
        "cmp " modifier "[out], " modifier "[expected]\n\t"                                                               \
        "b.ne 1f\n\t"                                                                                                     \
        "st" store_order "xr" suffix " %w[success], " modifier "[desired], %[target]\n\t"                                 \
        msvc_fence                                                                                                        \
        "1:\n\t"                                                                                                          \
        "cset %w[success], eq\n\t"                                                                                        \
        : [target] "+Q" (*(type *)target), [success] "=&r" (success), [out] "=&r" (out)                                   \
        : [desired] "r" (*(type *)desired), [expected] "r" (*(type *)expected)                                            \
        : "cc", "memory"                                                                                                  \
      );

    #define SATOMI_PASTE_BLOCK(order, type, ...)                \
      type out;                                                 \
      SATOMI_CHOOSE_MEMORY_ORDER_ASM(order, type, __VA_ARGS__); \
      SATOMI_MEMCPY(size, expected, &out);                      \
      return success

    SATOMI_BOOL success;
    if (size == 1) { SATOMI_PASTE_BLOCK(order, __UINT8_TYPE__, "b", "%w", "uxtb %w[expected], %w[expected]\n\t"); }
    else if (size == 2) { SATOMI_PASTE_BLOCK(order, __UINT16_TYPE__, "h", "%w", "uxth %w[expected], %w[expected]\n\t"); }
    else if (size == 4) { SATOMI_PASTE_BLOCK(order, __UINT32_TYPE__, "", "%w", ""); }
    else if (size == 8) { SATOMI_PASTE_BLOCK(order, __UINT64_TYPE__, "", "%x", ""); }
    else if (size == 16)
    {
      struct SATOMI_ALIGNAS(16) uint128__ { SATOMI_U64 v[2]; } out, e, d;
      SATOMI_MEMCPY(size, &e, expected);
      SATOMI_MEMCPY(size, &d, desired);
      SATOMI_BOOL success;

      #undef SATOMI_ATOMIC_ASM
      #define SATOMI_ATOMIC_ASM(load_order, store_order, msvc_fence, ...)               \
        __asm__ __volatile__                                                            \
        (                                                                               \
          "ld" load_order "xp %x[out_0], %x[out_1], %[target]\n\t"                      \
          "cmp %x[out_0], %x[expected_0]\n\t"                                           \
          "ccmp %x[out_1], %x[expected_1], #0, eq\n\t"                                  \
          "b.ne 1f\n\t"                                                                 \
          "st" store_order "xp %w[success], %x[desired_0], %x[desired_1], %[target]\n\t"\
          msvc_fence                                                                    \
          "1:\n\t"                                                                      \
          "cset %w[success], eq\n\t"                                                    \
          : [success] "=&r" (success), [target] "+Q" (*(struct uint128__ *)target),     \
            [out_0] "=&r" (out.v[0]), [out_1] "=&r" (out.v[1])                          \
          : [desired_0] "r" (d.v[0]), [desired_1] "r" (d.v[1]),                         \
            [expected_0] "r" (e.v[0]), [expected_1] "r" (e.v[1])                        \
          : "cc", "memory"                                                              \
        );

      SATOMI_CHOOSE_MEMORY_ORDER_ASM(order)
      #undef SATOMI_ATOMIC_ASM

      SATOMI_MEMCPY(size, expected, &out);
      return success;
    }

    #undef SATOMI_PASTE_BLOCK
    #pragma pop_macro("SATOMI_MSVC_STL_SEQ_CST_FENCE")

    return 0;

  #endif

#endif
}

SATOMI_INLINE void satomi__atomic_exchange(SATOMI_U64 size, void *variable,
  volatile void *target, const void *desired, memory_order order)
{
  SATOMI_CHECK_PRECONDITIONS(size, target);
  if (size > 16)
  {
    SATOMI_ASSERT(0 && "Size of atomic is too large for this architecture");
    SATOMI_TRAP();
    return;
  }

#if defined(_MSC_VER) && !defined(__clang__)

  struct SATOMI_ALIGNAS(16) int128__ { __int64 v[2]; } ret, d;
  d.v[0] = 0;
  SATOMI_MEMCPY(size, &d, desired);

  #define SATOMI_HELPER(cast) (volatile cast *)target, (cast)d.v[0]
  SATOMI_CHOOSE_SIZE(SATOMI_HELPER, size, _InterlockedExchange)
  #undef SATOMI_HELPER

  else if (size == 16)
  {
    (void)d;
    while (!satomi__atomic_compare_exchange_strong(size, target, &ret, desired, order)) {}
  }

  if (variable)
    SATOMI_MEMCPY(size, variable, &ret);

#elif defined(__x86_64__)

  #define SATOMI_ATOMIC_ASM(type, affix)        \
    __asm__ __volatile__                        \
    (                                           \
      "xchg" affix " %[desired], %[target]\n\t" \
      : [target] "+m" (*(type *)target),        \
        [desired] "+r" (*(type *)&d.v[0])       \
      :                                         \
      : "memory"                                \
    );                                          \
    if (variable)                               \
      SATOMI_MEMCPY(size, variable, &d.v[0]);

  struct SATOMI_ALIGNAS(16) uint128__ { SATOMI_U64 v[2]; } out, d;
  SATOMI_MEMCPY(size, &d, desired);

  if (size == 1) { SATOMI_ATOMIC_ASM(__UINT8_TYPE__, "b"); }
  else if (size == 2) { SATOMI_ATOMIC_ASM(__UINT16_TYPE__, "w"); }
  else if (size == 4) { SATOMI_ATOMIC_ASM(__UINT32_TYPE__, "l"); }
  else if (size == 8) { SATOMI_ATOMIC_ASM(__UINT64_TYPE__, "q"); }
  else if (size == 16)
  {
    __asm__ __volatile__
    (
      // the load needs to be done in assembly because movq is guaranteed to be atomic
      "movq %[target_0], %%rax\n\t"
      "movq %[target_1], %%rdx\n\t"
      ".align 16\n\t"
      "1: lock; cmpxchg16b %[target_0]\n\t"
      "jne 1b\n\t"
      : [target_0] "+m" (((volatile uint128__ *)target)[0]),
        [target_1] "+m" (((volatile SATOMI_U64 *)target)[1]),
        "=&a" (out.v[0]), "=&d" (out.v[1])
      : "b" (d.v[0]), "c" (d.v[1])
      : "cc", "memory"
    );

    if (variable)
      SATOMI_MEMCPY(size, variable, &out);
  }

  #undef SATOMI_ATOMIC_ASM

#elif defined(__aarch64__)

  #define SATOMI_PASTE_BLOCK(order, type, ...)                \
    type d, out;                                              \
    SATOMI_MEMCPY(size, &d, desired);                         \
    SATOMI_CHOOSE_MEMORY_ORDER_ASM(order, type, __VA_ARGS__); \
    if (variable)                                             \
      SATOMI_MEMCPY(size, variable, &out);

  // builtin exchange support with ARM LSE 1
  #ifdef __ARM_FEATURE_ATOMICS

    #define SATOMI_ATOMIC_ASM(load_order, store_order, msvc_fence, type, suffix, modifier, ...)       \
      __asm__ __volatile__                                                                            \
      (                                                                                               \
        "swp" load_order store_order suffix " " modifier "[desired], " modifier "[out], %[target]\n\t"\
        : [target] "+Q" (*(type *)target), [out] "=&r" (out)                                          \
        : [desired] "r" (d)                                                                           \
        : "memory"                                                                                    \
      );

  #else

    #define SATOMI_ATOMIC_ASM(load_order, store_order, msvc_fence, type, suffix, modifier, ...) \
      SATOMI_BOOL success;                                                                      \
      __asm__ __volatile__                                                                      \
      (                                                                                         \
        "1:\n\t"                                                                                \
        "ld" load_order "xr" suffix " " modifier "[out], %[target]\n\t"                         \
        "st" store_order "xr" suffix " %w[success], " modifier "[desired], %[target]\n\t"       \
        "cbnz %w[success], 1b\n\t"                                                              \
        msvc_fence                                                                              \
        : [success] "=&r" (success), [target] "+Q" (*(type *)target), [out] "=&r" (out)         \
        : [desired] "r" (d)                                                                     \
        : "memory"                                                                              \
      );

  #endif

  if (size == 1) { SATOMI_PASTE_BLOCK(order, __UINT8_TYPE__, "b", "%w"); }
  else if (size == 2) { SATOMI_PASTE_BLOCK(order, __UINT16_TYPE__, "h", "%w"); }
  else if (size == 4) { SATOMI_PASTE_BLOCK(order, __UINT32_TYPE__, "", "%w"); }
  else if (size == 8) { SATOMI_PASTE_BLOCK(order, __UINT64_TYPE__, "", "%x"); }

  #undef SATOMI_ATOMIC_ASM

  else if (size == 16)
  {
  #ifdef SATOMI_ARM_USE_LSE128

    struct SATOMI_ALIGNAS(16) uint128__ { SATOMI_U64 v[2]; } out;
    SATOMI_MEMCPY(size, &out, desired);

    #define SATOMI_ATOMIC_ASM(load_order, store_order, msvc_fence, ...)               \
      __asm__ __volatile__                                                            \
      (                                                                               \
        "swpp" load_order store_order " %x[out_0], %x[out_1], %[target]\n\t"          \
        : [target] "+Q" (*(struct uint128__ *)target),                                \
          [out_0] "=&r" (out.v[0]), [out_1] "=&r" (out.v[1])                          \
        :                                                                             \
        : "memory"                                                                    \
      );

    SATOMI_CHOOSE_MEMORY_ORDER_ASM(order)

    if (variable)
      SATOMI_MEMCPY(size, variable, &out);

  #else

    struct SATOMI_ALIGNAS(16) uint128__ { SATOMI_U64 v[2]; } out, d;
    SATOMI_BOOL success;
    SATOMI_MEMCPY(size, &d, desired);

    #define SATOMI_ATOMIC_ASM(load_order, store_order, msvc_fence, ...)               \
      __asm__ __volatile__                                                            \
      (                                                                               \
        "1:\n\t"                                                                      \
        "ld" load_order "xp %x[out_0], %x[out_1], %[target]\n\t"                      \
        "st" store_order "xp %w[success], %x[desired_0], %x[desired_1], %[target]\n\t"\
        "cbnz %w[success], 1b\n\t"                                                    \
        msvc_fence                                                                    \
        : [success] "=&r" (success), [target] "+Q" (*(struct uint128__ *)target),     \
          [out_0] "=&r" (out.v[0]), [out_1] "=&r" (out.v[1])                          \
        : [desired_0] "r" (d.v[0]), [desired_1] "r" (d.v[1])                          \
        : "memory"                                                                    \
      );

    SATOMI_CHOOSE_MEMORY_ORDER_ASM(order)

    if (variable)
      SATOMI_MEMCPY(size, variable, &out);

  #endif
  }

  #undef SATOMI_ATOMIC_ASM
  #undef SATOMI_PASTE_BLOCK

#endif
}




SATOMI_INLINE void satomi__atomic_load(SATOMI_U64 size,
  void *variable, const volatile void *target, memory_order order)
{
  SATOMI_CHECK_PRECONDITIONS(size, target);
  if (size > 16)
  {
    SATOMI_ASSERT(0 && "Size of atomic is too large for this architecture");
    SATOMI_TRAP();
    return;
  }

  if (order == memory_order_release)
    order = memory_order_acquire;
  else if (order == memory_order_acq_rel)
    order = memory_order_seq_cst;

#if defined(_MSC_VER) && !defined(__clang__)

  struct SATOMI_ALIGNAS(16) int128__ { __int64 v[2]; } ret;

  // ldr + dmb ish, another stupid ABI
  #define SATOMI_HELPER(size)                                                   \
    ret.v[0] = __iso_volatile_load##size((const volatile __int##size *)target); \
    if (order != memory_order_relaxed)                                          \
      SATOMI_COMPILER_OR_MEMORY_BARRIER();

  if (size == 1) { SATOMI_HELPER(8); }
  else if (size == 2) { SATOMI_HELPER(16); }
  else if (size == 4) {SATOMI_HELPER(32); }
  else if (size == 8) { SATOMI_HELPER(64); }
  else if (size == 16)
  {
    SATOMI_CHOOSE_MEMORY_ORDER(order, (void)_InterlockedCompareExchange128, ((volatile __int64 *)target, 0, 0, ret.v))
  }

  if (variable)
    SATOMI_MEMCPY(size, variable, &ret);

  #undef SATOMI_HELPER

#elif defined(__x86_64__)

#define SATOMI_ATOMIC_ASM(type, affix)  \
  type out;                             \
  __asm__ __volatile__                  \
  (                                     \
    "mov" affix " %[target], %[out]\n\t"\
    : [out] "=r" (out)                  \
    : [target] "m" (*(type *)target)    \
    : "memory"                          \
  );                                    \
  if (variable)                         \
    SATOMI_MEMCPY(size, variable, &out)

  if (size == 1) { SATOMI_ATOMIC_ASM(__UINT8_TYPE__, ""); }
  else if (size == 2) { SATOMI_ATOMIC_ASM(__UINT16_TYPE__, ""); }
  else if (size == 4) { SATOMI_ATOMIC_ASM(__UINT32_TYPE__, ""); }
  else if (size == 8) { SATOMI_ATOMIC_ASM(__UINT64_TYPE__, "q"); }
  else if (size == 16)
  {
    struct SATOMI_ALIGNAS(16) uint128__ { SATOMI_U64 v[2]; } out;

    #if defined(__AVX__)

      // Intel Software Developer Manual Volume 3, Guaranteed Atomic Operations
      // Processors supporting AVX guarantee aligned vector moves to be atomic.
      __asm__ __volatile__
      (
        "vmovdqa %[target], %[out]\n\t"
        : [out] "=x" (out)
        : [target] "m" (*(struct uint128__ *)target)
        : "memory"
      );

    #else

      __asm__ __volatile__
      (
        // store whatever is rbx/rcx in rax/rdx so that
        // even if we succeed to exchange we already have the value in rax/rdx
        "movq %%rbx, %%rax\n\t"
        "movq %%rcx, %%rdx\n\t"
        "lock; cmpxchg16b %[target]\n\t"
        : "=&a" (out.v[0]), "=&d" (out.v[1])
        : [target] "m" (*(struct uint128__ *)target)
        : "cc", "memory"
      );

    #endif

    if (variable)
      SATOMI_MEMCPY(size, variable, &out);
  }

  #undef SATOMI_ATOMIC_ASM

#elif defined(__aarch64__)

  #define SATOMI_ATOMIC_ASM(load_order, store_order, msvc_fence, type, suffix, modifier, ...) \
    __asm__ __volatile__                                                                      \
    (                                                                                         \
      "ld" load_order "r" suffix " " modifier "[out], %[target]\n\t"                          \
      : [out] "=r" (out)                                                                      \
      : [target] "Q" (*(type *)target)                                                        \
      : "memory"                                                                              \
    );

  #define SATOMI_PASTE_BLOCK(order, type, ...)                \
    type out;                                                 \
    SATOMI_CHOOSE_MEMORY_ORDER_ASM(order, type, __VA_ARGS__); \
    if (variable)                                             \
      SATOMI_MEMCPY(size, variable, &out);

  #pragma push_macro("SATOMI_CHOOSE_MEMORY_ORDER_ASM")
  #undef SATOMI_CHOOSE_MEMORY_ORDER_ASM

  // feature macro to check for ARMv8.3 RCPC/LDAPR
  #if __ARM_FEATURE_RCPC >= 1

    #define SATOMI_CHOOSE_MEMORY_ORDER_ASM(order, ...)\
      if (order == memory_order_relaxed) { SATOMI_ATOMIC_ASM("", "", "", __VA_ARGS__) } \
      else if (order == memory_order_consume || order == memory_order_acquire) { SATOMI_ATOMIC_ASM("ap", "", "", __VA_ARGS__) } \
      else if (order == memory_order_seq_cst) { SATOMI_ATOMIC_ASM("a", "l", SATOMI_MSVC_STL_SEQ_CST_FENCE, __VA_ARGS__) } \
      else { __builtin_trap(); }

  #else

    #define SATOMI_CHOOSE_MEMORY_ORDER_ASM(order, ...)\
      if (order == memory_order_relaxed) { SATOMI_ATOMIC_ASM("", "", "", __VA_ARGS__) } \
      else if (order == memory_order_consume || order == memory_order_acquire) { SATOMI_ATOMIC_ASM("a", "", "", __VA_ARGS__) } \
      else if (order == memory_order_seq_cst) { SATOMI_ATOMIC_ASM("a", "l", SATOMI_MSVC_STL_SEQ_CST_FENCE, __VA_ARGS__) } \
      else { __builtin_trap(); }

  #endif

  if (size == 1) { SATOMI_PASTE_BLOCK(order, __UINT8_TYPE__, "b", "%w"); }
  else if (size == 2) { SATOMI_PASTE_BLOCK(order, __UINT16_TYPE__, "h", "%w"); }
  else if (size == 4) { SATOMI_PASTE_BLOCK(order, __UINT32_TYPE__, "", "%w"); }
  else if (size == 8) { SATOMI_PASTE_BLOCK(order, __UINT64_TYPE__, "", "%x"); }

  #undef SATOMI_CHOOSE_MEMORY_ORDER_ASM
  #pragma pop_macro("SATOMI_CHOOSE_MEMORY_ORDER_ASM")

  else if (size == 16)
  {
  // checking for ARMv8.4 (LDP and STP)
  #if __ARM_FEATURE_DOTPROD

    struct SATOMI_ALIGNAS(16) uint128__ { SATOMI_U64 v[2]; } out;

    // > From v8.4a onwards, aligned 128-bit ldp and stp instructions are guaranteed to be single-copy atomic
    // https://reviews.llvm.org/D67485
    #undef SATOMI_ATOMIC_ASM

    // the load might pass an earlier store so we need either ldar or dmb ishld for seq_cst
    // https://gcc.gnu.org/bugzilla/show_bug.cgi?id=108891
    #define SATOMI_ATOMIC_ASM(load_order, store_order, pre_fence, post_fence) \
      __asm__ __volatile__                                                    \
      (                                                                       \
        pre_fence                                                             \
        "ld" load_order "p " "%x[out_0], %x[out_1], %[target]\n\t"            \
        post_fence                                                            \
        : [out_0] "=&r" (out.v[0]), [out_1] "=r" (out.v[1])                   \
        : [target] "Q" (*(uint128__ *)target)                                 \
        : "memory"                                                            \
      );

    if (order == memory_order_relaxed) { SATOMI_ATOMIC_ASM("", "", "", ""); }

    // feature macro to check for ARMv8.9 RCPC3 (LDIAPP and STILP)
    // needs +rcpc3 extension, i.e. -march=armv8.4-a+rcpc3
    // as of gcc 16.1 it just consumes the argument and doesn't define __ARM_FEATURE_RCPC == 3
    #if __ARM_FEATURE_RCPC >= 3
      else if (order == memory_order_consume || order == memory_order_acquire) { SATOMI_ATOMIC_ASM("iap", "", "", ""); }
      else if (order == memory_order_seq_cst) { SATOMI_ATOMIC_ASM("iap", "", "ldar %x[out_0], %[target]\n\t", "") }
    #else
      else if (order == memory_order_consume || order == memory_order_acquire) { SATOMI_ATOMIC_ASM("", "", "", "dmb ishld\n\t"); }
      else if (order == memory_order_seq_cst) { SATOMI_ATOMIC_ASM("", "", "ldar %x[out_0], %[target]\n\t", "dmb ishld\n\t") }
    #endif
    else { __builtin_trap(); }

    if (variable)
      SATOMI_MEMCPY(size, variable, &out);

  #else

    // WARNING!!!
    // the following implementations NEED a store (casp/stxp)
    // in order to confirm that the load was atomic
    // if the load is from read-only memory, this WILL CRASH the program
    // https://gcc.gnu.org/bugzilla/show_bug.cgi?id=70814#c3

  // builtin CAS support with ARM LSE 1
  #ifdef __ARM_FEATURE_ATOMICS

    // utilise casp to load
    // desired value doesn't matter, so we can just pass the same thing
    (void)satomi__atomic_compare_exchange_strong(size,
      (volatile void *)target, variable, variable, order);
    return;

  #else

    struct SATOMI_ALIGNAS(16) uint128__ { SATOMI_U64 v[2]; } out;

    SATOMI_BOOL success;

    #undef SATOMI_ATOMIC_ASM
    #define SATOMI_ATOMIC_ASM(load_order)                           \
      __asm__ __volatile__                                          \
      (                                                             \
        "1:\n\t"                                                    \
        "ld" load_order "xp %x[value_0], %x[value_1], %[target]\n\t"\
        "stxp %w[success], %x[value_0], %x[value_1], %[target]\n\t" \
        "cbnz %w[success], 1b\n\t"                                  \
        : [success] "=&r" (success),                                \
          [value_0] "=&r" (out.v[0]), [value_1] "=&r" (out.v[1])    \
        : [target] "Q" (*(struct uint128__ *)target)                \
        : "memory"                                                  \
      )

    if (order == memory_order_relaxed)
      SATOMI_ATOMIC_ASM("");
    else
      SATOMI_ATOMIC_ASM("a");

    if (variable)
      SATOMI_MEMCPY(size, variable, &out);

  #endif
  #endif
  }

  #undef SATOMI_ATOMIC_ASM
#endif
}

SATOMI_INLINE void satomi__atomic_store(SATOMI_U64 size,
  volatile void *target, void *value, memory_order order)
{
  SATOMI_CHECK_PRECONDITIONS(size, target);
  if (size > 16)
  {
    SATOMI_ASSERT(0 && "Size of atomic is too large for this architecture");
    SATOMI_TRAP();
    return;
  }

  if (order == memory_order_acquire || order == memory_order_consume)
    order = memory_order_release;
  else if (order == memory_order_acq_rel)
    order = memory_order_seq_cst;

#if defined(_MSC_VER) && !defined(__clang__)

  #if defined(_M_ARM64) || defined(_M_ARM64EC)
    // the stupid ABI mentioned at the top
    #define SATOMI_SEQ_CST_STORE(iso_suffix, ...) SATOMI_COMPILER_OR_MEMORY_BARRIER(); __iso_volatile_store##iso_suffix(memory, v); SATOMI_COMPILER_OR_MEMORY_BARRIER();
  #else
    #define SATOMI_SEQ_CST_STORE(iso_suffix, interlocked_suffix, ...) (void)_InterlockedExchange##interlocked_suffix(__VA_ARGS__ memory, v);
  #endif

  #define SATOMI_DEFINE_STORE_MEMORY_ORDERS(iso_suffix, interlocked_suffix, ...)\
    volatile __int##iso_suffix *memory = (volatile __int##iso_suffix *)target;  \
    __int##iso_suffix v;                                                        \
    SATOMI_MEMCPY(size, &v, value);                                             \
    if (order == memory_order_relaxed)                                          \
      __iso_volatile_store##iso_suffix(memory, v);                              \
    else if (order == memory_order_release)                                     \
    {                                                                           \
      SATOMI_COMPILER_OR_MEMORY_BARRIER();                                      \
      __iso_volatile_store##iso_suffix(memory, v);                              \
    }                                                                           \
    else                                                                        \
    {                                                                           \
      SATOMI_SEQ_CST_STORE(iso_suffix, interlocked_suffix, __VA_ARGS__)         \
    }

  if (size == 1) { SATOMI_DEFINE_STORE_MEMORY_ORDERS(8, 8) }
  else if (size == 2) { SATOMI_DEFINE_STORE_MEMORY_ORDERS(16, 16) }
  else if (size == 4) { SATOMI_DEFINE_STORE_MEMORY_ORDERS(32, , (volatile long *)) } // stupid cast for a stupid company
  else if (size == 8) { SATOMI_DEFINE_STORE_MEMORY_ORDERS(64, 64) }
  else if (size == 16)
  {
    struct SATOMI_ALIGNAS(16) int128__ { __int64 v[2]; } v;
    SATOMI_MEMCPY(size, &v, value);
    while (!satomi__atomic_compare_exchange_strong(size, target, v.v, value, order)) {}
  }

  #undef SATOMI_DEFINE_STORE_MEMORY_ORDERS
  #undef SATOMI_SEQ_CST_STORE

#elif defined(__x86_64__)

  #define SATOMI_ATOMIC_ASM(type, affix)  \
    type out;                             \
    SATOMI_MEMCPY(size, &out, value);     \
    __asm__ __volatile__                  \
    (                                     \
      "mov" affix " %[out], %[target]\n\t"\
      : [target] "=m" (*(type *)target)   \
      : [out] "r" (out)                   \
      : "memory"                          \
    );

  if (size == 1) { SATOMI_ATOMIC_ASM(__UINT8_TYPE__, "b"); }
  else if (size == 2) { SATOMI_ATOMIC_ASM(__UINT16_TYPE__, "w"); }
  else if (size == 4) { SATOMI_ATOMIC_ASM(__UINT32_TYPE__, "l"); }
  else if (size == 8) { SATOMI_ATOMIC_ASM(__UINT64_TYPE__, "q"); }
  else if (size == 16)
  {
    struct SATOMI_ALIGNAS(16) uint128__ { SATOMI_U64 v[2]; } v;

  #if defined(__AVX__)

    // Intel Software Developer Manual Volume 3, Guaranteed Atomic Operations
    // Processors supporting AVX guarantee aligned vector moves to be atomic.

    // the manual load from memory inside the asm block is
    // because clang "doesn't know how to handle indirect register inputs yet for constraint 'x'"
    __asm__ __volatile__
    (
      "vmovdqa %[value], %%xmm8\n\t"
      "vmovdqa %%xmm8, %[storage]\n\t"
      : [storage] "=m" (*(struct uint128__ *)target)
      : [value] "m" (*(struct uint128__ *)value)
      : "xmm8", "memory"
    );

  #else

    SATOMI_MEMCPY(size, &v, value);
    __asm__ __volatile__
    (
      "movq %[target_lo], %%rax\n\t"
      "movq %[target_hi], %%rdx\n\t"
      ".align 16\n\t"
      "1: lock; cmpxchg16b %[target_lo]\n\t"
      "jne 1b\n\t"
      : [target_lo] "=m" (((volatile SATOMI_U64 *)target)[0]),
        [target_hi] "=m" (((volatile SATOMI_U64 *)target)[1])
      : "b" (v.v[0]), "c" (v.v[1])
      : "cc", "rax", "rdx", "memory"
    );

  #endif
  }

  #undef SATOMI_ATOMIC_ASM

#elif defined(__aarch64__)

  #pragma push_macro("SATOMI_CHOOSE_MEMORY_ORDER_ASM")
  #undef SATOMI_CHOOSE_MEMORY_ORDER_ASM
  #define SATOMI_CHOOSE_MEMORY_ORDER_ASM(order, ...)\
    if (order == memory_order_relaxed) { SATOMI_ATOMIC_ASM("", "", "", __VA_ARGS__) } \
    else if (order == memory_order_release) { SATOMI_ATOMIC_ASM("", "l", "", __VA_ARGS__) } \
    else if (order == memory_order_seq_cst) { SATOMI_ATOMIC_ASM("", "l", SATOMI_MSVC_STL_SEQ_CST_FENCE, __VA_ARGS__) } \
    else { __builtin_trap(); }

  #define SATOMI_ATOMIC_ASM(load_order, store_order, msvc_fence, type, suffix, modifier)\
    type v;                                                                             \
    SATOMI_MEMCPY(size, &v, value);                                                     \
    __asm__ __volatile__                                                                \
    (                                                                                   \
      "st" store_order "r" suffix " " modifier "[value], %[target]\n\t"                 \
      msvc_fence                                                                        \
      : [target] "+Q" (*(type *)target)                                                 \
      : [value] "r" (v)                                                                 \
      : "memory"                                                                        \
    );

  if (size == 1) { SATOMI_CHOOSE_MEMORY_ORDER_ASM(order, __UINT8_TYPE__, "b", "%w"); }
  else if (size == 2) { SATOMI_CHOOSE_MEMORY_ORDER_ASM(order, __UINT16_TYPE__, "h", "%w"); }
  else if (size == 4) { SATOMI_CHOOSE_MEMORY_ORDER_ASM(order, __UINT32_TYPE__, "", "%w"); }
  else if (size == 8) { SATOMI_CHOOSE_MEMORY_ORDER_ASM(order, __UINT64_TYPE__, "", "%x"); }

  #undef SATOMI_ATOMIC_ASM
  #pragma pop_macro("SATOMI_CHOOSE_MEMORY_ORDER_ASM")

  else if (size == 16)
  {
    struct SATOMI_ALIGNAS(16) uint128__ { SATOMI_U64 v[2]; } v;
    SATOMI_MEMCPY(size, &v, value);

  // checking for ARMv8.4 (LDP and STP)
  #if __ARM_FEATURE_DOTPROD

    #define SATOMI_ATOMIC_ASM_V8_4(store_order, pre_fence, post_fence)\
      __asm__ __volatile__                                            \
      (                                                               \
        pre_fence                                                     \
        "st" store_order "p %x[value_0], %x[value_1], %[target]\n\t"  \
        post_fence                                                    \
        : [target] "+Q" (*(struct uint128__ *)target)                 \
        : [value_0] "r" (v.v[0]), [value_1] "r" (v.v[1])              \
        : "memory"                                                    \
      )

    #define SATOMI_ATOMIC_ASM_LSE128(load_order, store_order)               \
      __asm__ __volatile__                                                  \
      (                                                                     \
        "swpp" load_order store_order " %x[out_0], %x[out_1], %[target]\n\t"\
        : [target] "+Q" (*(struct uint128__ *)target),                      \
          [out_0] "+&r" (v.v[0]), [out_1] "+&r" (v.v[1])                    \
        :                                                                   \
        : "memory"                                                          \
      )

    if (order == memory_order_relaxed)
    {
      SATOMI_ATOMIC_ASM_V8_4("", "", "");
    }
    else if (order == memory_order_release)
    {
    // feature macro to check for ARMv8.9 RCPC3 (LDIAPP and STILP)
    // needs +rcpc3 extension, i.e. -march=armv8.4-a+rcpc3
    // as of gcc 16.1 it just consumes the argument and doesn't define __ARM_FEATURE_RCPC == 3
    #if __ARM_FEATURE_RCPC >= 3

      // use stilp, doesn't require fences
      SATOMI_ATOMIC_ASM_V8_4("il", "", "");

    #elif defined(SATOMI_ARM_USE_LSE128)

      // use swpp if stp would require a fence
      // https://reviews.llvm.org/D143506
      SATOMI_ATOMIC_ASM_LSE128("", "l");

    #else

      // > From v8.4a onwards, aligned 128-bit ldp and stp instructions are guaranteed to be single-copy atomic
      // https://reviews.llvm.org/D67485
      // use dmb ish + stp
      SATOMI_ATOMIC_ASM_V8_4("", "dmb ish\n\t", "");

    #endif

    }
    else if (order == memory_order_seq_cst)
    {
    #if defined(SATOMI_ARM_USE_LSE128)

      // use swpp if stp would require a fence
      // https://reviews.llvm.org/D143506
      SATOMI_ATOMIC_ASM_LSE128("a", "l");

    #elif __ARM_FEATURE_RCPC >= 3

      // use dmb ish + stilp
      // for more info:
      // https://github.com/taiki-e/atomic-maybe-uninit/blob/4059f083af2c9413a0beb70e92dd434db05c2e19/src/arch/aarch64.rs#L527
      SATOMI_ATOMIC_ASM_V8_4("il", "dmb ish\n\t", "");

    #else

      // use dmb ish + stp + dmb ish
      // according to llvm codegen (clang 22.1.0)
      SATOMI_ATOMIC_ASM_V8_4("", "dmb ish\n\t", "dmb ish\n\t");

    #endif
    }

    #undef SATOMI_ATOMIC_ASM_V8_4
    #undef SATOMI_ATOMIC_ASM_LSE128

  // builtin CAS support with ARM LSE 1
  #elif __ARM_FEATURE_ATOMICS

    // use casp
    uint128__ out = v;
    while (!satomi__atomic_compare_exchange_strong(size, target, &out, &v, order)) { }

  #else
    // if we don't have casp atomics use a cas loop
    // not redirecting this to satomi__atomic_compare_exchange_strong
    // because it's more effient to rewrite the algo

    uint128__ out;
    SATOMI_BOOL success;

    #define SATOMI_ATOMIC_ASM_LOOP(store_order)                                   \
      __asm__ __volatile__                                                        \
      (                                                                           \
        "1:\n\t"                                                                  \
        "ldxp %x[out_0], %x[out_1], %[target]\n\t"                                \
        "st" store_order "xp %w[success], %x[value_0], %x[value_1], %[target]\n\t"\
        "cbnz %w[success], 1b\n\t"                                                \
        : [success] "=&r" (success), [target] "+Q" (*(struct uint128__ *)target), \
          [out_0] "=&r" (out.v[0u]), [out_1] "=&r" (out.v[1u])                    \
        : [value_0] "r" (v.v[0u]), [value_1] "r" (v.v[1u])                        \
        : "memory"                                                                \
      )

    if (order == memory_order_relaxed)
      SATOMI_ATOMIC_ASM_LOOP("");
    else
      SATOMI_ATOMIC_ASM_LOOP("l");

    #undef SATOMI_ATOMIC_ASM_LOOP
  #endif
  }

#endif
}




// only available for integral types (no floating point)
// assumes 2's complement (which is the defacto standard)
SATOMI_INLINE void satomi__atomic_fetch_add(SATOMI_U64 size,
  void *variable, volatile void *target, void *operand, SATOMI_BOOL subtracting, memory_order order)
{
  SATOMI_CHECK_PRECONDITIONS(size, target);
  if (size > 16)
  {
    SATOMI_ASSERT(0 && "Size of atomic is too large for this architecture");
    SATOMI_TRAP();
    return;
  }

#if defined(_MSC_VER) && !defined(__clang__)

  struct SATOMI_ALIGNAS(16) int128__ { __int64 v[2]; } ret, o;
  o.v[0] = 0;
  SATOMI_MEMCPY(size, &o, operand);
  if (subtracting && size < 16)
    o.v[0] = -o.v[0];

  #define SATOMI_HELPER(cast) (volatile cast *)target, (cast)o.v[0]
  SATOMI_CHOOSE_SIZE(SATOMI_HELPER, size, _InterlockedExchangeAdd)
  #undef SATOMI_HELPER

  else if (size == 16)
  {
    satomi__atomic_load(size, &ret, target, order);
    if (subtracting)
    {
      SATOMI_U64 temp = ~(SATOMI_U64)o.v[0];
      o.v[1] += ((temp + 1) < temp);
      o.v[0] = -o.v[0];
    }

    struct int128__ intermediate;
    do
    {
      // reminder: x86 is little endian
      // annoying casts to avoid any potential overflow warnings
      intermediate.v[0] = (__int64)((SATOMI_U64)ret.v[0] + (SATOMI_U64)o.v[0]);
      // carry over if an overflow has occured in the lower part
      intermediate.v[1] = (__int64)((SATOMI_U64)ret.v[1] + (SATOMI_U64)o.v[1] +
        ((SATOMI_U64)intermediate.v[0] < (SATOMI_U64)ret.v[0]));
    }
    while (!satomi__atomic_compare_exchange_strong(size, target, &ret, &intermediate, order));
  }

  if (variable)
    SATOMI_MEMCPY(size, variable, &ret);

#else

  #if defined(__x86_64__)

    #define SATOMI_ATOMIC_ASM(type, affix)                    \
      type o;                                                 \
      SATOMI_MEMCPY(size, &o, operand);                       \
      if (subtracting) o = -o;                                \
      __asm__ __volatile__                                    \
      (                                                       \
        "lock; xadd" affix " %[operand], %[target]\n\t"       \
        : [target] "+m" (*(type *)target), [operand] "+r" (o) \
        :                                                     \
        : "memory"                                            \
      );                                                      \
      if (variable)                                           \
        SATOMI_MEMCPY(size, variable, &o);

    if (size == 1) { SATOMI_ATOMIC_ASM(__UINT8_TYPE__, "b"); }
    else if (size == 2) { SATOMI_ATOMIC_ASM(__UINT16_TYPE__, "w"); }
    else if (size == 4) { SATOMI_ATOMIC_ASM(__UINT32_TYPE__, "l"); }
    else if (size == 8) { SATOMI_ATOMIC_ASM(__UINT64_TYPE__, "q"); }

    #undef SATOMI_ATOMIC_ASM

  #elif defined(__aarch64__)

    // builtin CAS support with ARM LSE 1
    #ifdef __ARM_FEATURE_ATOMICS

      #define SATOMI_ATOMIC_ASM(load_order, store_order, msvc_fence, type, suffix, modifier)                    \
        type o, temp, original;                                                                                 \
        SATOMI_MEMCPY(size, &o, operand);                                                                       \
        if (subtracting) o = -o;                                                                                \
        __asm__ __volatile__                                                                                    \
        (                                                                                                       \
          "ldadd" load_order store_order suffix " " modifier "[operand], " modifier "[original], %[target]\n\t" \
          : [target] "+Q" (*(type *)target), [original] "=&r" (original)                                        \
          : [operand] "r" (o)                                                                                   \
          : "memory"                                                                                            \
        );                                                                                                      \
        if (variable)                                                                                           \
          SATOMI_MEMCPY(size, variable, &original);

    #else

      SATOMI_BOOL success;
      #define SATOMI_ATOMIC_ASM(load_order, store_order, msvc_fence, type, suffix, modifier)\
        type o, temp, original;                                                             \
        SATOMI_MEMCPY(size, &o, operand);                                                   \
        if (subtracting) o = -o;                                                            \
        __asm__ __volatile__                                                                \
        (                                                                                   \
          "1:\n\t"                                                                          \
          "ld" load_order "xr" suffix " " modifier "[original], %[target]\n\t"              \
          "add " modifier "[temp], " modifier "[original], " modifier "[operand]\n\t"       \
          "st" store_order "xr" suffix " %w[success], " modifier "[temp], %[target]\n\t"    \
          "cbnz %w[success], 1b\n\t"                                                        \
          msvc_fence                                                                        \
          : [target] "+Q" (*(type *)target), [success] "=&r" (success),                     \
            [temp] "=&r" (temp), [original] "=&r" (original)                                \
          : [operand] "r" (o)                                                               \
          : "memory"                                                                        \
        );                                                                                  \
        if (variable)                                                                       \
          SATOMI_MEMCPY(size, variable, &original);

    #endif

    if (size == 1) { SATOMI_CHOOSE_MEMORY_ORDER_ASM(order, __UINT8_TYPE__, "b", "%w"); }
    else if (size == 2) { SATOMI_CHOOSE_MEMORY_ORDER_ASM(order, __UINT16_TYPE__, "h", "%w"); }
    else if (size == 4) { SATOMI_CHOOSE_MEMORY_ORDER_ASM(order, __UINT32_TYPE__, "", "%w"); }
    else if (size == 8) { SATOMI_CHOOSE_MEMORY_ORDER_ASM(order, __UINT64_TYPE__, "", "%x"); }

    #undef SATOMI_ATOMIC_ASM

  #endif

  else if (size == 16)
  {
    __extension__ unsigned __int128 ret, o, intermediate;
    // relaxed because we ONLY care about the value
    satomi__atomic_load(size, &ret, target, memory_order_relaxed);
    SATOMI_MEMCPY(size, &o, operand);
    if (subtracting)
      o = -o;

    // NOTE: this generates slightly subpar code on armv8-a (>= armv8.1-a with casp is fine though)
    // because it can't interleave the addition inside the cas loop but it isn't too bad
    do
    {
      intermediate = ret + o;
    } while (!satomi__atomic_compare_exchange_strong(size, target, &ret, &intermediate, order));

    if (variable)
      SATOMI_MEMCPY(size, variable, &ret);
  }
#endif
}

#if defined(__x86_64__)

  #define SATOMI_ATOMIC_ASM(type, affix, a_register)          \
    type o, temp, original;                                   \
    SATOMI_MEMCPY(size, &o, operand);                         \
    __asm__ __volatile__                                      \
    (                                                         \
      "mov" affix " %[target], " a_register "\n\t"            \
      "1: mov" affix " %[operand], %[temp]\n\t"               \
      SATOMI_ATOMIC_OP affix " " a_register ", %[temp]\n\t"   \
      "lock; cmpxchg" affix " %[temp], %[target]\n\t"         \
      "jne 1b\n\t"                                            \
      : [target] "+m" (*(type *)target), [temp] "=&r" (temp), \
        [original] "+&a" (original)                           \
      : [operand] "r" (o)                                     \
      : "cc", "memory"                                        \
    );                                                        \
    if (variable)                                             \
      SATOMI_MEMCPY(size, variable, &original);

#elif defined(__aarch64__)

  #ifdef __ARM_FEATURE_ATOMICS

    #define SATOMI_ATOMIC_ASM(load_order, store_order, msvc_fence, type, suffix, modifier, ...)                       \
      type o, temp, original;                                                                                         \
      SATOMI_MEMCPY(size, &o, operand);                                                                               \
      __VA_ARGS__                                                                                                     \
      __asm__ __volatile__                                                                                            \
      (                                                                                                               \
        SATOMI_ATOMIC_OP load_order store_order suffix " " modifier "[operand], " modifier "[original], %[target]\n\t"\
        : [target] "+Q" (*(type *)target), [original] "=&r" (original)                                                \
        : [operand] "r" (o)                                                                                           \
        : "memory"                                                                                                    \
      );                                                                                                              \
      if (variable)                                                                                                   \
        SATOMI_MEMCPY(size, variable, &original);

  #else

    #define SATOMI_ATOMIC_ASM(load_order, store_order, msvc_fence, type, suffix, modifier, ...)   \
      SATOMI_BOOL success;                                                                        \
      type o, temp, original;                                                                     \
      SATOMI_MEMCPY(size, &o, operand);                                                           \
      __VA_ARGS__                                                                                 \
      __asm__ __volatile__                                                                        \
      (                                                                                           \
        "1:\n\t"                                                                                  \
        "ld" load_order "xr" suffix " " modifier "[original], %[target]\n\t"                      \
        SATOMI_ATOMIC_OP " " modifier "[temp], " modifier "[original], " modifier "[operand]\n\t" \
        "st" store_order "xr" suffix " %w[success], " modifier "[temp], %[target]\n\t"            \
        "cbnz %w[success], 1b\n\t"                                                                \
        msvc_fence                                                                                \
        : [target] "+Q" (*(type *)target), [success] "=&r" (success),                             \
          [temp] "=&r" (temp), [original] "=&r" (original)                                        \
        : [operand] "r" (o)                                                                       \
        : "memory"                                                                                \
      );                                                                                          \
      if (variable)                                                                               \
        SATOMI_MEMCPY(size, variable, &original);

  #endif

#endif

SATOMI_INLINE void satomi__atomic_fetch_and(SATOMI_U64 size,
  void *variable, volatile void *target, void *operand, memory_order order)
{
  SATOMI_CHECK_PRECONDITIONS(size, target);
  if (size > 16)
  {
    SATOMI_ASSERT(0 && "Size of atomic is too large for this architecture");
    SATOMI_TRAP();
    return;
  }

#if defined(_MSC_VER) && !defined(__clang__)

  struct SATOMI_ALIGNAS(16) int128__ { __int64 v[2]; } ret, o;
  o.v[0] = 0;
  SATOMI_MEMCPY(size, &o, operand);

  #define SATOMI_HELPER(cast) (volatile cast *)target, (cast)o.v[0]
  SATOMI_CHOOSE_SIZE(SATOMI_HELPER, size, _InterlockedAnd)
  #undef SATOMI_HELPER

  else if (size == 16)
  {
    // relaxed because we ONLY care about the value
    satomi__atomic_load(size, &ret, target, memory_order_relaxed);
    SATOMI_MEMCPY(size, &o, operand);

    struct int128__ intermediate;
    do
    {
      intermediate.v[0] &= o.v[0];
      intermediate.v[1] &= o.v[1];
    } while (!satomi__atomic_compare_exchange_strong(size, target, &ret, &intermediate, order));

  }

  if (variable)
    SATOMI_MEMCPY(size, variable, &ret);

#else
#if defined(__x86_64__)

  #define SATOMI_ATOMIC_OP "and"

  if (size == 1) { SATOMI_ATOMIC_ASM(__UINT8_TYPE__, "b", "%%al"); }
  else if (size == 2) { SATOMI_ATOMIC_ASM(__UINT16_TYPE__, "w", "%%ax"); }
  else if (size == 4) { SATOMI_ATOMIC_ASM(__UINT32_TYPE__, "l", "%%eax"); }
  else if (size == 8) { SATOMI_ATOMIC_ASM(__UINT64_TYPE__, "q", "%%rax"); }

  #undef SATOMI_ATOMIC_OP

#elif defined(__aarch64__)

  // builtin CAS support with ARM LSE 1
  #ifdef __ARM_FEATURE_ATOMICS
    #define SATOMI_ATOMIC_OP "ldclr"
    #define SATOMI_ATOMIC_EXTRA o = ~o;
  #else
    #define SATOMI_ATOMIC_OP "and"
    #define SATOMI_ATOMIC_EXTRA
  #endif

  if (size == 1) { SATOMI_CHOOSE_MEMORY_ORDER_ASM(order, __UINT8_TYPE__, "b", "%w", SATOMI_ATOMIC_EXTRA); }
  else if (size == 2) { SATOMI_CHOOSE_MEMORY_ORDER_ASM(order, __UINT16_TYPE__, "h", "%w", SATOMI_ATOMIC_EXTRA); }
  else if (size == 4) { SATOMI_CHOOSE_MEMORY_ORDER_ASM(order, __UINT32_TYPE__, "", "%w", SATOMI_ATOMIC_EXTRA); }
  else if (size == 8) { SATOMI_CHOOSE_MEMORY_ORDER_ASM(order, __UINT64_TYPE__, "", "%x", SATOMI_ATOMIC_EXTRA); }

  #undef SATOMI_ATOMIC_OP
  #undef SATOMI_ATOMIC_EXTRA

#endif

  else if (size == 16)
  {
    __extension__ unsigned __int128 ret, o, intermediate;
    // relaxed because we ONLY care about the value
    satomi__atomic_load(size, &ret, target, memory_order_relaxed);
    SATOMI_MEMCPY(size, &o, operand);
    do
    {
      intermediate = ret & o;
    } while (!satomi__atomic_compare_exchange_strong(size, target, &ret, &intermediate, order));

    if (variable)
      SATOMI_MEMCPY(size, variable, &ret);
  }

#endif
}

SATOMI_INLINE void satomi__atomic_fetch_or(SATOMI_U64 size,
  void *variable, volatile void *target, void *operand, memory_order order)
{
  SATOMI_CHECK_PRECONDITIONS(size, target);
  if (size > 16)
  {
    SATOMI_ASSERT(0 && "Size of atomic is too large for this architecture");
    SATOMI_TRAP();
    return;
  }

#if defined(_MSC_VER) && !defined(__clang__)

  struct SATOMI_ALIGNAS(16) int128__ { __int64 v[2]; } ret, o;
  o.v[0] = 0;
  SATOMI_MEMCPY(size, &o, operand);

  #define SATOMI_HELPER(cast) (volatile cast *)target, (cast)o.v[0]
  SATOMI_CHOOSE_SIZE(SATOMI_HELPER, size, _InterlockedOr)
  #undef SATOMI_HELPER

  else if (size == 16)
  {
    // relaxed because we ONLY care about the value
    satomi__atomic_load(size, &ret, target, memory_order_relaxed);
    SATOMI_MEMCPY(size, &o, operand);

    struct int128__ intermediate;
    do
    {
      intermediate.v[0] |= o.v[0];
      intermediate.v[1] |= o.v[1];
    } while (!satomi__atomic_compare_exchange_strong(size, target, &ret, &intermediate, order));
  }

  if (variable)
    SATOMI_MEMCPY(size, variable, &ret);

#else
#if defined(__x86_64__)

  #define SATOMI_ATOMIC_OP "or"

  if (size == 1) { SATOMI_ATOMIC_ASM(__UINT8_TYPE__, "b", "%%al"); }
  else if (size == 2) { SATOMI_ATOMIC_ASM(__UINT16_TYPE__, "w", "%%ax"); }
  else if (size == 4) { SATOMI_ATOMIC_ASM(__UINT32_TYPE__, "l", "%%eax"); }
  else if (size == 8) { SATOMI_ATOMIC_ASM(__UINT64_TYPE__, "q", "%%rax"); }

  #undef SATOMI_ATOMIC_OP

#elif defined(__aarch64__)

  // builtin CAS support with ARM LSE 1
  #ifdef __ARM_FEATURE_ATOMICS
    #define SATOMI_ATOMIC_OP "ldset"
  #else
    #define SATOMI_ATOMIC_OP "orr"
  #endif

  if (size == 1) { SATOMI_CHOOSE_MEMORY_ORDER_ASM(order, __UINT8_TYPE__, "b", "%w"); }
  else if (size == 2) { SATOMI_CHOOSE_MEMORY_ORDER_ASM(order, __UINT16_TYPE__, "h", "%w"); }
  else if (size == 4) { SATOMI_CHOOSE_MEMORY_ORDER_ASM(order, __UINT32_TYPE__, "", "%w"); }
  else if (size == 8) { SATOMI_CHOOSE_MEMORY_ORDER_ASM(order, __UINT64_TYPE__, "", "%x"); }

  #undef SATOMI_ATOMIC_OP

#endif

  else if (size == 16)
  {
    __extension__ unsigned __int128 ret, o, intermediate;
    // relaxed because we ONLY care about the value
    satomi__atomic_load(size, &ret, target, memory_order_relaxed);
    SATOMI_MEMCPY(size, &o, operand);
    do
    {
      intermediate = ret | o;
    } while (!satomi__atomic_compare_exchange_strong(size, target, &ret, &intermediate, order));

    if (variable)
      SATOMI_MEMCPY(size, variable, &ret);
  }
#endif
}

SATOMI_INLINE void satomi__atomic_fetch_xor(SATOMI_U64 size,
  void *variable, volatile void *target, void *operand, memory_order order)
{
  SATOMI_CHECK_PRECONDITIONS(size, target);
  if (size > 16)
  {
    SATOMI_ASSERT(0 && "Size of atomic is too large for this architecture");
    SATOMI_TRAP();
    return;
  }

#if defined(_MSC_VER) && !defined(__clang__)

  struct SATOMI_ALIGNAS(16) int128__ { __int64 v[2]; } ret, o;
  SATOMI_MEMCPY(size, &o, operand);

  #define SATOMI_HELPER(cast) (volatile cast *)target, (cast)o.v[0]
  SATOMI_CHOOSE_SIZE(SATOMI_HELPER, size, _InterlockedXor)
  #undef SATOMI_HELPER

  else if (size == 16)
  {
    // relaxed because we ONLY care about the value
    satomi__atomic_load(size, &ret, target, memory_order_relaxed);
    SATOMI_MEMCPY(size, &o, operand);

    struct int128__ intermediate;
    do
    {
      intermediate.v[0] ^= o.v[0];
      intermediate.v[1] ^= o.v[1];
    } while (!satomi__atomic_compare_exchange_strong(size, target, &ret, &intermediate, order));
  }

  if (variable)
    SATOMI_MEMCPY(size, variable, &ret);

#else
#if defined(__x86_64__)

  #define SATOMI_ATOMIC_OP "xor"

  if (size == 1) { SATOMI_ATOMIC_ASM(__UINT8_TYPE__, "b", "%%al"); }
  else if (size == 2) { SATOMI_ATOMIC_ASM(__UINT16_TYPE__, "w", "%%ax"); }
  else if (size == 4) { SATOMI_ATOMIC_ASM(__UINT32_TYPE__, "l", "%%eax"); }
  else if (size == 8) { SATOMI_ATOMIC_ASM(__UINT64_TYPE__, "q", "%%rax"); }

  #undef SATOMI_ATOMIC_OP

#elif defined(__aarch64__)

  // builtin CAS support with ARM LSE 1
  #ifdef __ARM_FEATURE_ATOMICS
    #define SATOMI_ATOMIC_OP "ldeor"
  #else
    #define SATOMI_ATOMIC_OP "eor"
  #endif

  if (size == 1) { SATOMI_CHOOSE_MEMORY_ORDER_ASM(order, __UINT8_TYPE__, "b", "%w"); }
  else if (size == 2) { SATOMI_CHOOSE_MEMORY_ORDER_ASM(order, __UINT16_TYPE__, "h", "%w"); }
  else if (size == 4) { SATOMI_CHOOSE_MEMORY_ORDER_ASM(order, __UINT32_TYPE__, "", "%w"); }
  else if (size == 8) { SATOMI_CHOOSE_MEMORY_ORDER_ASM(order, __UINT64_TYPE__, "", "%x"); }

  #undef SATOMI_ATOMIC_OP

#endif

  else if (size == 16)
  {
    __extension__ unsigned __int128 ret, o, intermediate;
    // relaxed because we ONLY care about the value
    satomi__atomic_load(size, &ret, target, memory_order_relaxed);
    SATOMI_MEMCPY(size, &o, operand);
    do
    {
      intermediate = ret ^ o;
    } while (!satomi__atomic_compare_exchange_strong(size, target, &ret, &intermediate, order));

    if (variable)
      SATOMI_MEMCPY(size, variable, &ret);
  }
#endif
}

#undef SATOMI_ATOMIC_ASM




#if (defined (LINUX) || defined (__linux__)) && defined(__x86_64__)

  #define SATOMI_SYS_FUTEX 202
  #define SATOMI_WAKE_SYSCALL(address, waiters_to_wake_up)         \
    __asm__ __volatile__                                           \
    (                                                              \
      "mov %[syscall_number], %%rax\n\t"                           \
      "mov %[a], %%rdi\n\t"                                        \
      "mov %[futex_op], %%rsi\n\t"                                 \
      "mov %[count], %%edx\n\t"                                    \
      "syscall\n\t"                                                \
      :                                                            \
      : [syscall_number] "Z" (SATOMI_SYS_FUTEX), [a] "r" (address),\
        [futex_op] "Z" (1 /*wake op*/ | 128 /*private flag*/),     \
        [count] "r" (waiters_to_wake_up)                           \
      : "rax", "rdi", "rsi", "rdx", "r10"                          \
    );

#elif (defined (LINUX) || defined (__linux__)) && defined(__aarch64__)

  #define SATOMI_SYS_FUTEX 98
  #define SATOMI_WAKE_SYSCALL(address, waiters_to_wake_up)         \
    __asm__ __volatile__                                           \
    (                                                              \
      "mov w8, %x[syscall_number]\n\t"                             \
      "mov x0, %x[a]\n\t"                                          \
      "mov x1, %x[futex_op]\n\t"                                   \
      "mov w2, %w[count]\n\t"                                      \
      "sxtw x2, w2\n\t"                                            \
      "svc #0\n\t"                                                 \
      :                                                            \
      : [syscall_number] "M" (SATOMI_SYS_FUTEX), [a] "r" (address),\
        [futex_op] "N" (1 /*wake op*/ | 128 /*private flag*/),     \
        [count] "r" (waiters_to_wake_up)                           \
      : "w8", "x0", "x1", "x2"                                     \
    );

#endif

SATOMI_INLINE void satomi__atomic_wait(SATOMI_U64 size, void *variable,
  volatile void *target, void *expected, memory_order order)
{
  SATOMI_CHECK_PRECONDITIONS(size, target);
  if (size > 16)
  {
    SATOMI_ASSERT(0 && "Size of atomic is too large for this architecture");
    SATOMI_TRAP();
    return;
  }

  if (order == memory_order_release)
    order = memory_order_acquire;
  else if (order == memory_order_acq_rel)
    order = memory_order_seq_cst;

#if defined (_WIN64)

  struct SATOMI_ALIGNAS(16) uint128__ { SATOMI_U64 v[2]; } ret, e;
  SATOMI_MEMCPY(size, &e, expected);
  satomi__atomic_load(size, &ret, target, order);

  if (size <= 8)
  {
    while (ret.v[0] == e.v[0])
    {
      WaitOnAddress(target, &e, size, 0xFFFFFFFF /*No timeout*/);
      satomi__atomic_load(size, &ret, target, order);
    }
  }
  else if (size == 16)
  {
    while (ret.v[0] == e.v[0] && ret.v[1] == e.v[1])
    {
      WaitOnAddress(target, &e, 8, 0xFFFFFFFF /*No timeout*/);
      satomi__atomic_load(size, &ret, target, order);
    }
  }

  if (variable)
    SATOMI_MEMCPY(size, variable, &ret);

#else

  // assumes linux has futexes, kernel versions must be >= 2.6.22

  // assumes macOS has __ulock_wait and __ulock_wake, >= Darwin 16 (macOS 10.12)

  struct SATOMI_ALIGNAS(16) uint128__ { SATOMI_U64 v[2]; } current, e;
  current.v[0] = 0;
  e.v[0] = 0;
  SATOMI_MEMCPY(size, &e, expected);
  satomi__atomic_load(size, &current, target, order);

  struct satomi__waiting_slot *slot = SATOMI_GET_WAITING_SLOT(target);
  (void)__atomic_fetch_add(&slot->wait_count, 1, __ATOMIC_SEQ_CST);

  int *address = 0;
  int compare;

  if (size >= sizeof(slot->version) &&
    (((__UINTPTR_TYPE__)target) % sizeof(int)) == 0)
  {
    address = (int *)target;
    SATOMI_MEMCPY(sizeof(compare), &compare, expected);
  }
  else
  {
    address = &slot->version;
    compare = __atomic_load_n(&slot->version, __ATOMIC_RELAXED);
  }

  while(1)
  {
    static const int spin_count = 16;
    SATOMI_BOOL finish = 0;
    for (int i = 0; i < spin_count; ++i)
    {
      satomi__atomic_load(size, &current, target, order);
      if (__builtin_memcmp(&current, &e, size) != 0)
      {
        finish = 1;
        break;
      }

    #if defined(__x86_64__)
      __asm__ __volatile__("pause");
    #elif defined(__aarch64__)
      __asm__ __volatile__("yield");
    #endif
    }

    if (finish)
      break;

  #if defined (LINUX) || defined (__linux__)
    __INT64_TYPE__ result;
    #define SATOMI_WAIT_OP (0 /*wait op*/ | 128 /*private flag*/)

  #if defined(__x86_64__)

    __asm__ __volatile__
    (
      "mov %[syscall_number], %%rax\n\t"
      "mov %[address], %%rdi\n\t"
      "mov %[futex_op], %%rsi\n\t"
      "mov %[compare], %%edx\n\t"
      "mov %[timeout], %%r10\n\t"
      "syscall\n\t"
      "mov %%rax, %[result]"
      : [result] "=r" (result)
      : [syscall_number] "Z" (SATOMI_SYS_FUTEX), [address] "r" (address),
        [futex_op] "Z" (SATOMI_WAIT_OP), [compare] "r" (compare), [timeout] "Z" (0)
      : "rax", "rdi", "rsi", "rdx", "r10"
    );

  #elif defined(__aarch64__)

    __asm__ __volatile__
    (
      "mov w8, %x[syscall_number]\n\t"
      "mov x0, %x[address]\n\t"
      "mov x1, %x[futex_op]\n\t"
      "mov w2, %w[compare]\n\t"
      "sxtw x2, w2\n\t"
      "mov x3, %x[timeout]\n\t"
      "svc #0\n\t"
      "mov %x[result], x0"
      : [result] "=r" (result)
      : [syscall_number] "M" (SATOMI_SYS_FUTEX), [address] "r" (address),
        [futex_op] "N" (SATOMI_WAIT_OP), [compare] "r" (compare), [timeout] "N" (0)
      : "w8", "x0", "x1", "x2", "x3"
    );

  #endif

    #undef SATOMI_WAIT_OP

    if (!result && (-result) != 11 /*EAGAIN*/)
      __builtin_trap();

  #elif defined (__APPLE__)

    __ulock_wait(SATOMI_UL_COMPARE_AND_WAIT, address, (SATOMI_U64)compare, 0);

  #endif
  }

  (void)__atomic_fetch_sub(&slot->wait_count, 1, __ATOMIC_RELEASE);

  if (variable)
    SATOMI_MEMCPY(size, variable, &current);
#endif
}

SATOMI_INLINE void satomi__atomic_notify_one(SATOMI_U64 size, volatile void *target)
{
  SATOMI_CHECK_PRECONDITIONS(size, target);
  if (size > 16)
  {
    SATOMI_ASSERT(0 && "Size of atomic is too large for this architecture");
    SATOMI_TRAP();
    return;
  }

#if defined (_WIN64)

  WakeByAddressSingle((void *)target);

#else

  // assumes linux has futexes, kernel versions must be >= 2.6.22

  // assumes macOS has __ulock_wait and __ulock_wake, >= Darwin 16 (macOS 10.12)

  struct satomi__waiting_slot *slot = SATOMI_GET_WAITING_SLOT(target);
  SATOMI_BOOL is_anyone_waiting = __atomic_load_n(&slot->wait_count, __ATOMIC_RELAXED) != 0;
  if (!is_anyone_waiting)
    return;

  int *address = 0;
  int waiters_to_wake_up = 1;

  if (size >= sizeof(slot->version) &&
    (((__UINTPTR_TYPE__)target) % sizeof(int)) == 0)
  {
    address = (int *)target;
  }
  else
  {
    (void)__atomic_fetch_add(&slot->version, 1, __ATOMIC_SEQ_CST);
    // waking up everyone because a different atomic might have the same hash
    // so we can't guarantee waking up threads only on OUR atomic with notify_one
    waiters_to_wake_up = __INT_MAX__;
    address = &slot->version;
  }

  #if defined (LINUX) || defined (__linux__)

    SATOMI_WAKE_SYSCALL(address, waiters_to_wake_up)

  #elif defined (__APPLE__)

    int extra = waiters_to_wake_up == __INT_MAX__ ? SATOMI_ULF_WAKE_ALL : 0;
    __ulock_wake(SATOMI_UL_COMPARE_AND_WAIT | extra, address, 0);

  #endif

#endif
}

SATOMI_INLINE void satomi__atomic_notify_all(SATOMI_U64 size, volatile void *target)
{
  SATOMI_CHECK_PRECONDITIONS(size, target);
  if (size > 16)
  {
    SATOMI_ASSERT(0 && "Size of atomic is too large for this architecture");
    SATOMI_TRAP();
    return;
  }

#if defined (_WIN64)

  WakeByAddressAll((void *)target);

#else

  // assumes linux has futexes, kernel versions must be >= 2.6.22

  // assumes macOS has __ulock_wait and __ulock_wake, >= Darwin 16 (macOS 10.12)

  struct satomi__waiting_slot *slot = SATOMI_GET_WAITING_SLOT(target);
  SATOMI_BOOL is_anyone_waiting = __atomic_load_n(&slot->wait_count, __ATOMIC_RELAXED) != 0;
  if (!is_anyone_waiting)
      return;

  int *address = 0;

  if (size >= sizeof(slot->version) &&
    (((__UINTPTR_TYPE__)target) % sizeof(int)) == 0)
  {
    address = (int *)target;
  }
  else
  {
    (void)__atomic_fetch_add(&slot->version, 1, __ATOMIC_SEQ_CST);
    address = &slot->version;
  }

  #if defined (LINUX) || defined (__linux__)

    int waiters_to_wake_up = __INT_MAX__;

    SATOMI_WAKE_SYSCALL(address, waiters_to_wake_up)

    #undef SATOMI_WAKE_SYSCALL
    #undef SATOMI_SYS_FUTEX

  #elif defined (__APPLE__)

    __ulock_wake(SATOMI_UL_COMPARE_AND_WAIT | SATOMI_ULF_WAKE_ALL, address, 0);

    #undef SATOMI_UL_COMPARE_AND_WAIT
    #undef SATOMI_ULF_WAKE_ALL

  #endif

  #undef SATOMI_WAITING_LIST_COUNT
  #undef SATOMI_GET_WAITING_SLOT

#endif
}

#ifdef __cplusplus
}
#endif

#if defined(__GNUC__) && !defined(__clang__)
  #pragma GCC diagnostic pop
#elif defined(__clang__)
  #pragma GCC diagnostic pop
#endif

#undef SATOMI_BOOL
#undef SATOMI_ALIGNAS
#undef SATOMI_U64
#undef SATOMI_CHECK_PRECONDITIONS
#undef SATOMI_COMPILER_BARRIER
#undef SATOMI_TRAP
#undef SATOMI_MEMCPY
#undef SATOMI_INLINE
#undef SATOMI_CHOOSE_MEMORY_ORDER
#undef SATOMI_CHOOSE_MEMORY_ORDER_ASM
#undef SATOMI_MSVC_STL_SEQ_CST_FENCE
#undef SATOMI_CHOOSE_SIZE
#undef SATOMI_COMPILER_OR_MEMORY_BARRIER


#ifndef SATOMI_DO_NOT_DEFINE_MACROS

  #define ATOMIC_BOOL_LOCK_FREE     2
  #define ATOMIC_CHAR_LOCK_FREE     2
  #define ATOMIC_CHAR16_T_LOCK_FREE 2
  #define ATOMIC_CHAR32_T_LOCK_FREE 2
  #define ATOMIC_WCHAR_T_LOCK_FREE  2
  #define ATOMIC_SHORT_LOCK_FREE    2
  #define ATOMIC_INT_LOCK_FREE      2
  #define ATOMIC_LONG_LOCK_FREE     2
  #define ATOMIC_LLONG_LOCK_FREE    2
  #define ATOMIC_POINTER_LOCK_FREE  2
  #define ATOMIC_CHAR8_T_LOCK_FREE  2

  // small macro to do arbitrary default parameters
  #ifdef __cplusplus
    #ifdef __GNUC__
      #pragma GCC diagnostic push
      #pragma GCC diagnostic ignored "-Wpedantic"
      #pragma GCC diagnostic ignored "-Wvariadic-macros"
      #pragma GCC diagnostic ignored "-Wc++20-extensions"
    #endif

    #define SATOMI_IGNORE(x)
    #define SATOMI_DEFAULT_OR(T, def, ...) (__VA_OPT__(SATOMI_IGNORE)(def) __VA_ARGS__)
  #else
    #define SATOMI_DEFAULT_OR(T, def, ...) ((T[]){(def), __VA_ARGS__}[(sizeof((T[]){(def), __VA_ARGS__})/sizeof(T)) - 1])
  #endif

  // not actually useful anymore but added for completeness
  #define kill_dependency(target) (target)

  #define atomic_is_lock_free(atomic) (sizeof(atomic) <= 16)

  #define atomic_thread_fence satomi__atomic_thread_fence

  #define atomic_signal_fence satomi__atomic_signal_fence

  #define atomic_compare_exchange_strong(target, expected, desired, ...) \
    (SATOMI_ASSERT(sizeof(*(target)) == sizeof(*(expected)) && sizeof(*(target)) == sizeof(*(desired))), \
    satomi__atomic_compare_exchange_strong(sizeof(*(target)), target, expected, desired, SATOMI_DEFAULT_OR(memory_order, memory_order_seq_cst, __VA_ARGS__)))

  #define atomic_compare_exchange_weak(target, expected, desired, ...) \
    (SATOMI_ASSERT(sizeof(*(target)) == sizeof(*(expected)) && sizeof(*(target)) == sizeof(*(desired))), \
    satomi__atomic_compare_exchange_weak(sizeof(*(target)), target, expected, desired, SATOMI_DEFAULT_OR(memory_order, memory_order_seq_cst, __VA_ARGS__)))

  #define atomic_exchange(ret, target, value, ...) \
    (SATOMI_ASSERT(sizeof(*(target)) == sizeof(*(value))), \
    satomi__atomic_exchange(sizeof(*(target)), ret, target, value, SATOMI_DEFAULT_OR(memory_order, memory_order_seq_cst, __VA_ARGS__)))

  #define atomic_load(ret, target, ...) \
    satomi__atomic_load(sizeof(*(target)), ret, target, SATOMI_DEFAULT_OR(memory_order, memory_order_seq_cst, __VA_ARGS__))

  #define atomic_store(target, value, ...) \
    (SATOMI_ASSERT(sizeof(*(target)) == sizeof(*(value))), \
    satomi__atomic_store(sizeof(*(target)), target, value, SATOMI_DEFAULT_OR(memory_order, memory_order_seq_cst, __VA_ARGS__)))

  #define atomic_fetch_add(ret, target, operand, ...) \
    (SATOMI_ASSERT(sizeof(*(target)) == sizeof(*(operand))), \
    satomi__atomic_fetch_add(sizeof(*(target)), ret, target, operand, 0, SATOMI_DEFAULT_OR(memory_order, memory_order_seq_cst, __VA_ARGS__)))

  #define atomic_fetch_sub(ret, target, operand, ...) \
    (SATOMI_ASSERT(sizeof(*(target)) == sizeof(*(operand))), \
    satomi__atomic_fetch_add(sizeof(*(target)), ret, target, operand, 1, SATOMI_DEFAULT_OR(memory_order, memory_order_seq_cst, __VA_ARGS__)))

  #define atomic_fetch_and(ret, target, operand, ...) \
    (SATOMI_ASSERT(sizeof(*(target)) == sizeof(*(operand))), \
    satomi__atomic_fetch_and(sizeof(*(target)), ret, target, operand, SATOMI_DEFAULT_OR(memory_order, memory_order_seq_cst, __VA_ARGS__)))

  #define atomic_fetch_or(ret, target, operand, ...) \
    (SATOMI_ASSERT(sizeof(*(target)) == sizeof(*(operand))), \
    satomi__atomic_fetch_or(sizeof(*(target)), ret, target, operand, SATOMI_DEFAULT_OR(memory_order, memory_order_seq_cst, __VA_ARGS__)))

  #define atomic_fetch_xor(ret, target, operand, ...) \
    (SATOMI_ASSERT(sizeof(*(target)) == sizeof(*(operand))), \
    satomi__atomic_fetch_xor(sizeof(*(target)), ret, target, operand, SATOMI_DEFAULT_OR(memory_order, memory_order_seq_cst, __VA_ARGS__)))

  #define atomic_wait(ret, target, expected, ...) \
    (SATOMI_ASSERT(sizeof(*(target)) == sizeof(*(expected))), \
    satomi__atomic_wait(sizeof(*(target)), ret, target, expected, SATOMI_DEFAULT_OR(memory_order, memory_order_seq_cst, __VA_ARGS__)))

  #define atomic_notify_one(target, ...) \
    satomi__atomic_notify_one(sizeof(*(target)), target, SATOMI_DEFAULT_OR(memory_order, memory_order_seq_cst, __VA_ARGS__))

  #define atomic_notify_all(target, ...) \
    satomi__atomic_notify_all(sizeof(*(target)), target, SATOMI_DEFAULT_OR(memory_order, memory_order_seq_cst, __VA_ARGS__))


  #if defined(__cplusplus) && defined(__GNUC__)
    #pragma GCC diagnostic pop
  #endif

#endif
