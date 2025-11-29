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

#ifndef SATOMI_H
#define SATOMI_H

// Customisation points are:
// 1. SATOMI_ASSERT - basic assert to avoid using <assert.h>
// 2. SATOMI_DO_NOT_DEFINE_MEMORY_ORDER - define to skip memory_order enum
// 3. SATOMI_DO_NOT_DEFINE_MACROS - define to skip usage macros

#ifndef SATOMI_ASSERT
  #include <assert.h>
  #define SATOMI_ASSERT(condition) assert(condition)
#endif

#ifndef NULL
  #define SATOMI_NULL (0)
#else
  #define SATOMI_NULL NULL
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

#define SATOMI_STATIC_ASSERT(condition, message) typedef char satomi__static_assertion_##message[(condition)?1:-1]

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

  #if defined(_M_ARM) || defined(_M_ARM64) || defined(_M_ARM64EC)

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
    #define SATOMI_COMPILER_OR_MEMORY_BARRIER() __dmb(0xB)
    #define SATOMI_MEMORY_LOAD_ACQUIRE_BARRIER() __dmb(0x9)

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

  SATOMI_STATIC_ASSERT(sizeof(SATOMI_U64) == sizeof(void *), Only_64_bit_arches_are_supported);

  #if defined(__GNUC__) && !defined(__clang__)
    #pragma GCC diagnostic push
    #pragma GCC diagnostic ignored "-Wstringop-overflow"
    #pragma GCC diagnostic ignored "-Wstringop-overread"
  #endif

  #define SATOMI_TRAP() __builtin_trap()
  // safely reinterpreting arbitrary types to integrals (padding bits are NOT taken into account)
  #define SATOMI_MEMCPY(size, to, from) __builtin_memcpy(to, from, size)
  #define SATOMI_INLINE inline __attribute__((always_inline))

  #define SATOMI_CHOOSE_MEMORY_ORDER_ASM(order)\
    if (order == memory_order_relaxed) { SATOMI_ATOMIC_ASM("", "") } \
    else if (order == memory_order_consume || order == memory_order_acquire) { SATOMI_ATOMIC_ASM("a", "") } \
    else if (order == memory_order_release) { SATOMI_ATOMIC_ASM("", "l") } \
    else if (order == memory_order_acq_rel || order == memory_order_seq_cst) { SATOMI_ATOMIC_ASM("a", "l") } \
    else { __builtin_trap(); }
  #define SATOMI_CHOOSE_SIZE(size, macro)                            \
    if (size == 1) { macro(__UINT8_TYPE__); }      \
    else if (size == 2) { macro(__UINT16_TYPE__); }\
    else if (size == 4) { macro(__UINT32_TYPE__); }\
    else if (size == 8) { macro(__UINT64_TYPE__); }
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

SATOMI_INLINE void satomi__atomic_thread_fence(memory_order order)
{
#if defined(_MSC_VER) && !defined(__clang__)
  SATOMI_COMPILER_BARRIER();
  #if defined(_M_ARM) || defined(_M_ARM64) || defined(_M_ARM64EC)
    if (order == memory_order_acquire || order == memory_order_consume)
      SATOMI_MEMORY_LOAD_ACQUIRE_BARRIER();
    else
      SATOMI_COMPILER_OR_MEMORY_BARRIER();
  #else
    if (order == memory_order_seq_cst)
    {
    #pragma warning(push)
    #pragma warning(disable : 6001)  // "Using uninitialized memory 'guard'"
    #pragma warning(disable : 28113) // "Accessing a local variable guard via an Interlocked function: This is an unusual
                                      // usage which could be reconsidered."
      volatile long guard;
      (void)_InterlockedIncrement(&guard);
      SATOMI_COMPILER_BARRIER();
    #pragma warning(pop)
    }
  #endif
#else
  #if defined (__x86_64__)
    if (order == memory_order_seq_cst)
    {
      unsigned char dummy = 0u;
      __asm__ __volatile__ ("lock; notb %0" : "+m" (dummy) : : "memory");
    }
    else if (order != memory_order_relaxed)
      __asm__ __volatile__ ("" ::: "memory");
  #else
    if (order != memory_order_relaxed)
    {
      if (order == memory_order_consume || order == memory_order_acquire)
        __asm__ __volatile__ ("dmb ishld\n\t" ::: "memory");
      else
        __asm__ __volatile__ ("dmb ish\n\t" ::: "memory");
    }
  #endif
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

  // this works because windows only works on little-endian machines
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

#else

  #define SATOMI_ATOMIC_OP(INT) INT d; SATOMI_MEMCPY(size, &d, desired); return __atomic_compare_exchange_n((volatile INT *)target, (INT *)expected, d,\
    0, (int)order, (int)(order == memory_order_acq_rel || order == memory_order_seq_cst ? memory_order_acquire : \
    order == memory_order_release ?  memory_order_relaxed : order));
  SATOMI_CHOOSE_SIZE(size, SATOMI_ATOMIC_OP)
  #undef SATOMI_ATOMIC_OP
  
  else if (size == 16)
  {
    struct SATOMI_ALIGNAS(16) uint128__ { SATOMI_U64 v[2]; } ret, e, d;
    SATOMI_MEMCPY(size, &e, expected);
    SATOMI_MEMCPY(size, &d, desired);

  #if defined (__x86_64__)

    SATOMI_BOOL success;
    (void)ret;
    __asm__ __volatile__
    (
      "lock; cmpxchg16b %[target]\n\t"
      "sete %[success]\n\t"
      : [target] "+m" (*(struct uint128__ *)target), "+a" (e.v[0]), "+d" (e.v[1]), [success] "=q" (success)
      : "b" (d.v[0]), "c" (d.v[1])
      : "cc", "memory"
    );

    SATOMI_MEMCPY(size, expected, &e);

  #elif defined (__aarch64__)
    
    unsigned success;
    
    #define SATOMI_ATOMIC_ASM(load_order, store_order)                                \
      __asm__ __volatile__                                                            \
      (                                                                               \
        "1:\n\t"                                                                      \
        "ld" load_order "xp %x[original_0], %x[original_1], %[target]\n\t"            \
        "cmp %x[original_0], %x[expected_0]\n\t"                                      \
        "ccmp %x[original_1], %x[expected_1], #0, eq\n\t"                             \
        "b.ne 2f\n\t"                                                                 \
        "st" store_order "xp %w[success], %x[desired_0], %x[desired_1], %[target]\n\t"\
        "cbnz %w[success], 1b\n\t"                                                    \
        "2:\n\t"                                                                      \
        "cset %w[success], eq\n\t"                                                    \
        : [success] "=&r" (success), [target] "+Q" (*(struct uint128__ *)target),     \
          [original_0] "=&r" (ret.v[0u]), [original_1] "=&r" (ret.v[1u])              \
        : [desired_0] "r" (d.v[0u]), [desired_1] "r" (d.v[1u]),                       \
          [expected_0] "r" (e.v[0u]), [expected_1] "r" (e.v[1u])                      \
        : "cc", "memory"                                                              \
      );

    SATOMI_CHOOSE_MEMORY_ORDER_ASM(order)
    #undef SATOMI_ATOMIC_ASM

    SATOMI_MEMCPY(size, expected, &ret);

  #endif

    return success;
  }
  
  return 0;
#endif
}

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

  return satomi__atomic_compare_exchange_strong(size, target, expected, desired, order);

#else

  #define SATOMI_ATOMIC_OP(INT) INT d; SATOMI_MEMCPY(size, &d, desired); return __atomic_compare_exchange_n((volatile INT *)target, (INT *)expected, d,\
    1, (int)order, (int)(order == memory_order_acq_rel || order == memory_order_seq_cst ? memory_order_acquire : memory_order_relaxed));
  SATOMI_CHOOSE_SIZE(size, SATOMI_ATOMIC_OP)
  #undef SATOMI_ATOMIC_OP

  else if (size == 16)
  {
  #if defined(__x86_64__)

    return satomi__atomic_compare_exchange_strong(size, target, expected, desired, order);

  #elif defined(__aarch64__)

    struct SATOMI_ALIGNAS(16) uint128__ { SATOMI_U64 v[2]; } ret, e, d;
    SATOMI_MEMCPY(size, &e, expected);
    SATOMI_MEMCPY(size, &d, desired);
    SATOMI_BOOL success;

    #define SATOMI_ATOMIC_ASM(load_order, store_order)                                \
      __asm__ __volatile__                                                            \
      (                                                                               \
        "mov %w[success], #0\n\t"                                                     \
        "ld" load_order "xp %x[original_0], %x[original_1], %[target]\n\t"            \
        "cmp %x[original_0], %x[expected_0]\n\t"                                      \
        "ccmp %x[original_1], %x[expected_1], #0, eq\n\t"                             \
        "b.ne 1f\n\t"                                                                 \
        "st" store_order "xp %w[success], %x[desired_0], %x[desired_1], %[target]\n\t"\
        "eor %w[success], %w[success], #1\n\t"                                        \
        "1:\n\t"                                                                      \
        : [success] "=&r" (success), [target] "+Q" (*(struct uint128__ *)target),     \
          [original_0] "=&r" (ret.v[0u]), [original_1] "=&r" (ret.v[1u])              \
        : [desired_0] "r" (d.v[0u]), [desired_1] "r" (d.v[1u]),                       \
          [expected_0] "r" (e.v[0u]), [expected_1] "r" (e.v[1u])                      \
        : "cc", "memory"                                                              \
      );

    SATOMI_CHOOSE_MEMORY_ORDER_ASM(order)
    #undef SATOMI_ATOMIC_ASM

    SATOMI_MEMCPY(size, expected, &ret);
    return success;

  #endif
  }

  return 0;

#endif
}

SATOMI_INLINE void satomi__atomic_exchange(SATOMI_U64 size, void *variable,
  volatile void *target, const void *value, memory_order order)
{
  SATOMI_CHECK_PRECONDITIONS(size, target);
  if (size > 16)
  {
    SATOMI_ASSERT(0 && "Size of atomic is too large for this architecture");
    SATOMI_TRAP();
    return;
  }

#if defined(_MSC_VER) && !defined(__clang__)

  struct SATOMI_ALIGNAS(16) int128__ { __int64 v[2]; } ret, v;
  v.v[0] = 0;
  SATOMI_MEMCPY(size, &v, value);

  #define SATOMI_HELPER(cast) (volatile cast *)target, (cast)v.v[0]
  SATOMI_CHOOSE_SIZE(SATOMI_HELPER, size, _InterlockedExchange)
  #undef SATOMI_HELPER

  else if (size == 16)
  {
    (void)v;
    while (!satomi__atomic_compare_exchange_strong(size, target, &ret, value, order)) {}
  }

  if (variable != SATOMI_NULL)
    SATOMI_MEMCPY(size, variable, &ret);

#else

  #define SATOMI_ATOMIC_OP(INT) INT ret, v = 0; SATOMI_MEMCPY(size, &v, value); \
    ret = __atomic_exchange_n((volatile INT *)target, v, (int)order); \
    if (variable != SATOMI_NULL) SATOMI_MEMCPY(size, variable, &ret);
  SATOMI_CHOOSE_SIZE(size, SATOMI_ATOMIC_OP)
  #undef SATOMI_ATOMIC_OP

  else if (size == 16)
  {
    struct SATOMI_ALIGNAS(16) uint128__ { SATOMI_U64 v[2]; } ret, v;
    SATOMI_MEMCPY(size, &v, value);

    // shamelessly stolen from boost.atomic
  #if defined (__x86_64__)

    __asm__ __volatile__
    (
      // the load needs to be done in assembly because movq is guaranteed to be atomic
      "movq %[target_lo], %%rax\n\t"
      "movq %[target_hi], %%rdx\n\t"
      ".align 16\n\t"
      "1: lock; cmpxchg16b %[target_lo]\n\t"
      "jne 1b\n\t"
      : [target_lo] "+m" (((volatile SATOMI_U64 *)target)[0]), 
        [target_hi] "+m" (((volatile SATOMI_U64 *)target)[1]), 
        "=&a" (ret.v[0]), "=&d" (ret.v[1])
      : "b" (v.v[0]), "c" (v.v[1])
      : "cc", "memory"
    );

  #elif defined (__aarch64__)

    SATOMI_BOOL success;
    
    #define SATOMI_ATOMIC_ASM(load_order, store_order)                            \
      __asm__ __volatile__                                                        \
      (                                                                           \
        "1:\n\t"                                                                  \
        "ld" load_order "xp %x[original_0], %x[original_1], %[target]\n\t"        \
        "st" store_order "xp %w[success], %x[value_0], %x[value_1], %[target]\n\t"\
        "cbnz %w[success], 1b\n\t"                                                \
        : [success] "=&r" (success), [target] "+Q" (*(struct uint128__ *)target), \
          [original_0] "=&r" (ret.v[0u]), [original_1] "=&r" (ret.v[1u])          \
        : [value_0] "r" (v.v[0u]), [value_1] "r" (v.v[1u])                        \
        : "memory"                                                                \
      );

    SATOMI_CHOOSE_MEMORY_ORDER_ASM(order)
    #undef SATOMI_ATOMIC_ASM

  #endif

    if (variable != SATOMI_NULL)
      SATOMI_MEMCPY(size, &variable, &ret);
  }
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

  if (size == 1)
  {
    ret.v[0] = __iso_volatile_load8((const volatile __int8 *)target);
    if (order != memory_order_relaxed)
      SATOMI_COMPILER_OR_MEMORY_BARRIER();
  }
  else if (size == 2)
  {
    ret.v[0] = __iso_volatile_load16((const volatile __int16 *)target);
    if (order != memory_order_relaxed)
      SATOMI_COMPILER_OR_MEMORY_BARRIER();
  }
  else if (size == 4)
  {
    ret.v[0] = __iso_volatile_load32((const volatile __int32 *)target);
    if (order != memory_order_relaxed)
      SATOMI_COMPILER_OR_MEMORY_BARRIER();
  }
  else if (size == 8)
  {
  #ifdef _M_ARM
    ret.v[0] = __ldrexd((const volatile __int64 *)target);
  #else
    ret.v[0] = __iso_volatile_load64((const volatile __int64 *)target);
  #endif
    if (order != memory_order_relaxed)
      SATOMI_COMPILER_OR_MEMORY_BARRIER();
  }
  else if (size == 16)
  {
    SATOMI_CHOOSE_MEMORY_ORDER(order, (void)_InterlockedCompareExchange128, ((volatile __int64 *)target, 0, 0, ret.v))
  }

  if (variable != SATOMI_NULL)
    SATOMI_MEMCPY(size, variable, &ret);

#else

  #define SATOMI_ATOMIC_OP(INT) INT v = __atomic_load_n((volatile INT *)target, (int)order); \
    if (variable != SATOMI_NULL) SATOMI_MEMCPY(size, variable, &v);
  SATOMI_CHOOSE_SIZE(size, SATOMI_ATOMIC_OP)
  #undef SATOMI_ATOMIC_OP

  else if (size == 16)
  {
    struct SATOMI_ALIGNAS(16) uint128__ { SATOMI_U64 v[2]; } ret;

    #if defined(__x86_64__)

      #if defined(__AVX__)

        // Intel Software Developer Manual Volume 3, Guaranteed Atomic Operations 
        // Processors supporting AVX guarantee aligned vector moves to be atomic.
        __asm__ __volatile__
        (
          "vmovdqa %[target], %[value]\n\t"
          : [value] "=x" (ret)
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
          : "=&a" (ret.v[0]), "=&d" (ret.v[1])
          : [target] "m" (*(struct uint128__ *)target)
          : "cc", "memory"
        );
      
      #endif

    #elif defined(__aarch64__)
      
      unsigned success;

      #define SATOMI_DEFINE_LOAD_MEMORY_ORDERS(acquire_order)            \
        __asm__ __volatile__                                             \
        (                                                                \
          "1:\n\t"                                                       \
          "ld" acquire_order "xp %x[value_0], %x[value_1], %[target]\n\t"\
          "stxp %w[success], %x[value_0], %x[value_1], %[target]\n\t"    \
          "cbnz %w[success], 1b\n\t"                                     \
          : [success] "=&r" (success),                                   \
            [value_0] "=&r" (ret.v[0]), [value_1] "=&r" (ret.v[1])       \
          : [target] "Q" (*(struct uint128__ *)target)                   \
          : "memory"                                                     \
        );

      if (order == memory_order_relaxed)
        SATOMI_DEFINE_LOAD_MEMORY_ORDERS("")
      else
        SATOMI_DEFINE_LOAD_MEMORY_ORDERS("a")
      
      #undef SATOMI_DEFINE_LOAD_MEMORY_ORDERS

    #endif

    if (variable != SATOMI_NULL)
      SATOMI_MEMCPY(size, variable, &ret);
  }
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

  #if defined(_M_ARM) || defined(_M_ARM64) || defined(_M_ARM64EC)
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

#else

  #define SATOMI_ATOMIC_OP(INT) INT v; SATOMI_MEMCPY(size, &v, value); __atomic_store_n((volatile INT *)target, v, (int)order);
  SATOMI_CHOOSE_SIZE(size, SATOMI_ATOMIC_OP)
  #undef SATOMI_ATOMIC_OP

  else if (size == 16)
  {
    struct SATOMI_ALIGNAS(16) uint128__ { SATOMI_U64 v[2]; } ret, v;
    SATOMI_MEMCPY(size, &v, value);

  #if defined(__x86_64__)

    (void)ret;

    #if defined(__AVX__)

      // Intel Software Developer Manual Volume 3, Guaranteed Atomic Operations 
      // Processors supporting AVX guarantee aligned vector moves to be atomic.      
      __asm__ __volatile__
      (
        "vmovdqa %[value], %[storage]\n\t"
        : [storage] "=m" (*(struct uint128__ *)target)
        : [value] "x" (v)
        : "memory"
      );
      
    #else

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

  #elif defined(__aarch64__)
    
    unsigned success;

    #define SATOMI_DEFINE_STORE_MEMORY_ORDERS(store_order)                        \
      __asm__ __volatile__                                                        \
      (                                                                           \
        "1:\n\t"                                                                  \
        "ldxp %x[original_0], %x[original_1], %[target]\n\t"                      \
        "st" store_order "xp %w[success], %x[value_0], %x[value_1], %[target]\n\t"\
        "cbnz %w[success], 1b\n\t"                                                \
        : [success] "=&r" (success), [target] "+Q" (*(struct uint128__ *)target), \
          [original_0] "=&r" (ret.v[0u]), [original_1] "=&r" (ret.v[1u])          \
        : [value_0] "r" (v.v[0u]), [value_1] "r" (v.v[1u])                        \
        : "memory"                                                                \
      );

    if (order == memory_order_relaxed)
      SATOMI_DEFINE_STORE_MEMORY_ORDERS("")
    else
      SATOMI_DEFINE_STORE_MEMORY_ORDERS("l")
    
    #undef SATOMI_DEFINE_STORE_MEMORY_ORDERS

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

  if (variable != SATOMI_NULL)
    SATOMI_MEMCPY(size, variable, &ret);

#else

  #define SATOMI_ATOMIC_OP(INT) INT o; SATOMI_MEMCPY(size, &o, operand); if (subtracting) o = -o;\
    INT old = __atomic_fetch_add((volatile INT *)target, o, (int)order); \
    if (variable != SATOMI_NULL) SATOMI_MEMCPY(size, variable, &old);
  SATOMI_CHOOSE_SIZE(size, SATOMI_ATOMIC_OP)
  #undef SATOMI_ATOMIC_OP

  else if (size == 16)
  {
  #if defined(__x86_64__)

    __extension__ unsigned __int128 ret, o, intermediate;
    satomi__atomic_load(size, &ret, target, order);
    SATOMI_MEMCPY(size, &o, operand);
    if (subtracting)
      o = -o;
    
    do
    {
      intermediate = ret + o;
    } while (!satomi__atomic_compare_exchange_strong(size, target, &ret, &intermediate, order));
    
  #elif defined(__aarch64__)

    #if defined(__AARCH64EL__) || \
      (defined(__BYTE_ORDER__) && defined(__ORDER_LITTLE_ENDIAN__) && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__) || \
      (defined(__LITTLE_ENDIAN__) && !defined(__BIG_ENDIAN__))

      // little endian
      #define SATOMI_ARG_LO "0"
      #define SATOMI_ARG_HI "1"

    #else

      // big endian
      #define SATOMI_ARG_LO "1"
      #define SATOMI_ARG_HI "0"

    #endif

    struct SATOMI_ALIGNAS(16) uint128__ { SATOMI_U64 v[2]; } ret, intermediate, o;

    {
      __extension__ unsigned __int128 temp;
      SATOMI_MEMCPY(size, &temp, operand);
      if (subtracting)
        temp = -temp;
      SATOMI_MEMCPY(size, &o, &temp);
    }

    unsigned success;

    #define SATOMI_ATOMIC_ASM(load_order, store_order)                                                        \
      __asm__ __volatile__                                                                                    \
      (                                                                                                       \
        "1:\n\t"                                                                                              \
        "ld" load_order "xp %x[original_0], %x[original_1], %[target]\n\t"                                    \
        "adds %x[result_" SATOMI_ARG_LO "], %x[original_" SATOMI_ARG_LO "], %x[operand_" SATOMI_ARG_LO "]\n\t"\
        "adc %x[result_" SATOMI_ARG_HI "], %x[original_" SATOMI_ARG_HI "], %x[operand_" SATOMI_ARG_HI "]\n\t" \
        "st" store_order "xp %w[success], %x[result_0], %x[result_1], %[target]\n\t"                          \
        "cbnz %w[success], 1b\n\t"                                                                            \
        : [success] "=&r" (success), [target] "+Q" (*(struct uint128__ *)target),                             \
          [original_0] "=&r" (ret.v[0]), [original_1] "=&r" (ret.v[1]),                                       \
          [result_0] "=&r" (intermediate.v[0]), [result_1] "=&r" (intermediate.v[1])                          \
        : [operand_0] "Lr" (o.v[0]), [operand_1] "Lr" (o.v[1])                                                \
        : "cc", "memory"                                                                                      \
      );
    
    SATOMI_CHOOSE_MEMORY_ORDER_ASM(order)
    #undef SATOMI_ARG_LO
    #undef SATOMI_ARG_HI
    #undef SATOMI_ATOMIC_ASM

  #endif
  
    if (variable != SATOMI_NULL)
      SATOMI_MEMCPY(size, variable, &ret);
  }

#endif
}

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
    satomi__atomic_load(size, &ret, target, order);
    SATOMI_MEMCPY(size, &o, operand);

    struct int128__ intermediate;
    do
    {
      intermediate.v[0] &= o.v[0];
      intermediate.v[1] &= o.v[1];
    } while (!satomi__atomic_compare_exchange_strong(size, target, &ret, &intermediate, order));

  }

  if (variable != SATOMI_NULL)
    SATOMI_MEMCPY(size, variable, &ret);

#else

  #define SATOMI_ATOMIC_OP(INT) INT o; SATOMI_MEMCPY(size, &o, operand); \
    INT old = __atomic_fetch_and((volatile INT *)target, o, (int)order); \
    if (variable != SATOMI_NULL) SATOMI_MEMCPY(size, variable, &old);
  SATOMI_CHOOSE_SIZE(size, SATOMI_ATOMIC_OP)
  #undef SATOMI_ATOMIC_OP

  else if (size == 16)
  {
  #if defined(__x86_64__)

    __extension__ unsigned __int128 ret, o, intermediate;
    satomi__atomic_load(size, &ret, target, order);
    SATOMI_MEMCPY(size, &o, operand);
    do
    {
      intermediate = ret & o;
    } while (!satomi__atomic_compare_exchange_strong(size, target, &ret, &intermediate, order));

  #elif defined(__aarch64__)

    struct SATOMI_ALIGNAS(16) uint128__ { SATOMI_U64 v[2]; } ret, intermediate, o;
    SATOMI_MEMCPY(size, &o, operand);
    unsigned success;

    #define SATOMI_ATOMIC_ASM(load_order, store_order)                              \
      __asm__ __volatile__                                                          \
      (                                                                             \
        "1:\n\t"                                                                    \
        "ld" load_order "xp %x[original_0], %x[original_1], %[target]\n\t"          \
        "and %x[result_0], %x[original_0], %x[operand_0]\n\t"                       \
        "and %x[result_1], %x[original_1], %x[operand_1]\n\t"                       \
        "st" store_order "xp %w[success], %x[result_0], %x[result_1], %[target]\n\t"\
        "cbnz %w[success], 1b\n\t"                                                  \
        : [success] "=&r" (success), [target] "+Q" (*(struct uint128__ *)target),   \
          [original_0] "=&r" (ret.v[0]), [original_1] "=&r" (ret.v[1]),             \
          [result_0] "=&r" (intermediate.v[0]), [result_1] "=&r" (intermediate.v[1])\
        : [operand_0] "Lr" (o.v[0]), [operand_1] "Lr" (o.v[1])                      \
        : "cc", "memory"                                                            \
      );
    
    SATOMI_CHOOSE_MEMORY_ORDER_ASM(order)
    #undef SATOMI_ATOMIC_ASM

  #endif

    if (variable != SATOMI_NULL)
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
    satomi__atomic_load(size, &ret, target, order);
    SATOMI_MEMCPY(size, &o, operand);

    struct int128__ intermediate;
    do
    {
      intermediate.v[0] |= o.v[0];
      intermediate.v[1] |= o.v[1];
    } while (!satomi__atomic_compare_exchange_strong(size, target, &ret, &intermediate, order));
  }

  if (variable != SATOMI_NULL)
    SATOMI_MEMCPY(size, variable, &ret);

#else

  #define SATOMI_ATOMIC_OP(INT) INT o; SATOMI_MEMCPY(size, &o, operand); \
    INT ret = __atomic_fetch_or((volatile INT *)target, o, (int)order); \
    if (variable != SATOMI_NULL) SATOMI_MEMCPY(size, variable, &ret);
  SATOMI_CHOOSE_SIZE(size, SATOMI_ATOMIC_OP)
  #undef SATOMI_ATOMIC_OP

  if (size == 16)
  {
  #if defined(__x86_64__)

    __extension__ unsigned __int128 ret, o, intermediate;
    satomi__atomic_load(size, &ret, target, order);
    SATOMI_MEMCPY(size, &o, operand);
    do
    {
      intermediate = ret | o;
    } while (!satomi__atomic_compare_exchange_strong(size, target, &ret, &intermediate, order));

  #elif defined(__aarch64__)

    struct SATOMI_ALIGNAS(16) uint128__ { SATOMI_U64 v[2]; } ret, intermediate, o;
    SATOMI_MEMCPY(size, &o, operand);
    unsigned success;

    #define SATOMI_ATOMIC_ASM(load_order, store_order)                              \
      __asm__ __volatile__                                                          \
      (                                                                             \
        "1:\n\t"                                                                    \
        "ld" load_order "xp %x[original_0], %x[original_1], %[target]\n\t"          \
        "orr %x[result_0], %x[original_0], %x[operand_0]\n\t"                       \
        "orr %x[result_1], %x[original_1], %x[operand_1]\n\t"                       \
        "st" store_order "xp %w[success], %x[result_0], %x[result_1], %[target]\n\t"\
        "cbnz %w[success], 1b\n\t"                                                  \
        : [success] "=&r" (success), [target] "+Q" (*(struct uint128__ *)target),   \
          [original_0] "=&r" (ret.v[0]), [original_1] "=&r" (ret.v[1]),             \
          [result_0] "=&r" (intermediate.v[0]), [result_1] "=&r" (intermediate.v[1])\
        : [operand_0] "Lr" (o.v[0]), [operand_1] "Lr" (o.v[1])                      \
        : "cc", "memory"                                                            \
      );
    
    SATOMI_CHOOSE_MEMORY_ORDER_ASM(order)
    #undef SATOMI_ATOMIC_ASM

  #endif

    if (variable != SATOMI_NULL)
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
    satomi__atomic_load(size, &ret, target, order);
    SATOMI_MEMCPY(size, &o, operand);

    struct int128__ intermediate;
    do
    {
      intermediate.v[0] ^= o.v[0];
      intermediate.v[1] ^= o.v[1];
    } while (!satomi__atomic_compare_exchange_strong(size, target, &ret, &intermediate, order));
  }

  if (variable != SATOMI_NULL)
    SATOMI_MEMCPY(size, variable, &ret);

#else

  #define SATOMI_ATOMIC_OP(INT) INT o; SATOMI_MEMCPY(size, &o, operand); \
    INT ret = __atomic_fetch_xor((volatile INT *)target, o, (int)order); \
    if (variable != SATOMI_NULL) SATOMI_MEMCPY(size, variable, &ret);
  SATOMI_CHOOSE_SIZE(size, SATOMI_ATOMIC_OP)
  #undef SATOMI_ATOMIC_OP

  else if (size == 16)
  {
  #if defined(__x86_64__)

    __extension__ unsigned __int128 ret, o, intermediate;
    satomi__atomic_load(size, &ret, target, order);
    SATOMI_MEMCPY(size, &o, operand);
    do
    {
      intermediate = ret ^ o;
    } while (!satomi__atomic_compare_exchange_strong(size, target, &ret, &intermediate, order));

  #elif defined(__aarch64__)

    struct SATOMI_ALIGNAS(16) uint128__ { SATOMI_U64 v[2]; } ret, intermediate, o;
    SATOMI_MEMCPY(size, &o, operand);
    unsigned success;

    #define SATOMI_ATOMIC_ASM(load_order, store_order)                              \
      __asm__ __volatile__                                                          \
      (                                                                             \
        "1:\n\t"                                                                    \
        "ld" load_order "xp %x[original_0], %x[original_1], %[target]\n\t"          \
        "eor %x[result_0], %x[original_0], %x[operand_0]\n\t"                       \
        "eor %x[result_1], %x[original_1], %x[operand_1]\n\t"                       \
        "st" store_order "xp %w[success], %x[result_0], %x[result_1], %[target]\n\t"\
        "cbnz %w[success], 1b\n\t"                                                  \
        : [success] "=&r" (success), [target] "+Q" (*(struct uint128__ *)target),   \
          [original_0] "=&r" (ret.v[0]), [original_1] "=&r" (ret.v[1]),             \
          [result_0] "=&r" (intermediate.v[0]), [result_1] "=&r" (intermediate.v[1])\
        : [operand_0] "Lr" (o.v[0]), [operand_1] "Lr" (o.v[1])                      \
        : "cc", "memory"                                                            \
      );
    
    SATOMI_CHOOSE_MEMORY_ORDER_ASM(order)
    #undef SATOMI_ATOMIC_ASM

  #endif

    if (variable != SATOMI_NULL)
      SATOMI_MEMCPY(size, variable, &ret);
  }
#endif
}




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

  if (variable != SATOMI_NULL)
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

  int *address = SATOMI_NULL;
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
        [futex_op] "Z" (SATOMI_WAIT_OP), [compare] "r" (compare), [timeout] "Z" (SATOMI_NULL)
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
        [futex_op] "N" (SATOMI_WAIT_OP), [compare] "r" (compare), [timeout] "N" (SATOMI_NULL)
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

  if (variable != SATOMI_NULL)
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

  int *address = SATOMI_NULL;
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

  int *address = SATOMI_NULL;

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
#endif

#undef SATOMI_NULL
#undef SATOMI_BOOL
#undef SATOMI_ALIGNAS
#undef SATOMI_U64
#undef SATOMI_STATIC_ASSERT
#undef SATOMI_CHECK_PRECONDITIONS
#undef SATOMI_COMPILER_BARRIER
#undef SATOMI_TRAP
#undef SATOMI_MEMCPY
#undef SATOMI_INLINE
#undef SATOMI_CHOOSE_MEMORY_ORDER
#undef SATOMI_CHOOSE_MEMORY_ORDER_ASM
#undef SATOMI_CHOOSE_SIZE
#undef SATOMI_MEMORY_LOAD_ACQUIRE_BARRIER
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
    #ifdef _MSC_VER
      #define SATOMI_DEFAULT_OR(T, def, ...) (def, ##__VA_ARGS__)
    #else
      #pragma GCC diagnostic push
      #pragma GCC diagnostic ignored "-Wvariadic-macros"
      #pragma GCC diagnostic ignored "-Wc++20-extensions"
      
      #define SATOMI_IGNORE(x) 
      #define SATOMI_DEFAULT_OR(T, def, ...) (__VA_OPT__(SATOMI_IGNORE)(def) __VA_ARGS__)
    #endif
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

  #define atomic_exchange(variable, target, value, ...) \
    (SATOMI_ASSERT(sizeof(*(target)) == sizeof(*(value))), \
    satomi__atomic_exchange(sizeof(*(target)), variable, target, value, SATOMI_DEFAULT_OR(memory_order, memory_order_seq_cst, __VA_ARGS__)))

  #define atomic_load(variable, target, ...) \
    satomi__atomic_load(sizeof(*(target)), variable, target, SATOMI_DEFAULT_OR(memory_order, memory_order_seq_cst, __VA_ARGS__))

  #define atomic_store(target, value, ...) \
    (SATOMI_ASSERT(sizeof(*(target)) == sizeof(*(value))), \
    satomi__atomic_store(sizeof(*(target)), target, value, SATOMI_DEFAULT_OR(memory_order, memory_order_seq_cst, __VA_ARGS__)))

  #define atomic_fetch_add(variable, target, operand, ...) \
    (SATOMI_ASSERT(sizeof(*(target)) == sizeof(*(operand))), \
    satomi__atomic_fetch_add(sizeof(*(target)), variable, target, operand, 0, SATOMI_DEFAULT_OR(memory_order, memory_order_seq_cst, __VA_ARGS__)))

  #define atomic_fetch_sub(variable, target, operand, ...) \
    (SATOMI_ASSERT(sizeof(*(target)) == sizeof(*(operand))), \
    satomi__atomic_fetch_add(sizeof(*(target)), variable, target, operand, 1, SATOMI_DEFAULT_OR(memory_order, memory_order_seq_cst, __VA_ARGS__)))

  #define atomic_fetch_and(variable, target, operand, ...) \
    (SATOMI_ASSERT(sizeof(*(target)) == sizeof(*(operand))), \
    satomi__atomic_fetch_and(sizeof(*(target)), variable, target, operand, SATOMI_DEFAULT_OR(memory_order, memory_order_seq_cst, __VA_ARGS__)))

  #define atomic_fetch_or(variable, target, operand, ...) \
    (SATOMI_ASSERT(sizeof(*(target)) == sizeof(*(operand))), \
    satomi__atomic_fetch_or(sizeof(*(target)), variable, target, operand, SATOMI_DEFAULT_OR(memory_order, memory_order_seq_cst, __VA_ARGS__)))

  #define atomic_fetch_xor(variable, target, operand, ...) \
    (SATOMI_ASSERT(sizeof(*(target)) == sizeof(*(operand))), \
    satomi__atomic_fetch_xor(sizeof(*(target)), variable, target, operand, SATOMI_DEFAULT_OR(memory_order, memory_order_seq_cst, __VA_ARGS__)))

  #define atomic_wait(variable, target, expected, ...) \
    (SATOMI_ASSERT(sizeof(*(target)) == sizeof(*(expected))), \
    satomi__atomic_wait(sizeof(*(target)), variable, target, expected, SATOMI_DEFAULT_OR(memory_order, memory_order_seq_cst, __VA_ARGS__)))

  #define atomic_notify_one(target, ...) \
    satomi__atomic_notify_one(sizeof(*(target)), target, SATOMI_DEFAULT_OR(memory_order, memory_order_seq_cst, __VA_ARGS__))

  #define atomic_notify_all(target, ...) \
    satomi__atomic_notify_all(sizeof(*(target)), target, SATOMI_DEFAULT_OR(memory_order, memory_order_seq_cst, __VA_ARGS__))


  #if defined(__cplusplus) && !defined(_MSC_VER)
    #pragma GCC diagnostic pop
  #endif

#endif

#endif
