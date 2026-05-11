# satomi
### s(imple)atomi(c)

Completely lock-less atomic headers: 

`satomi.h` for C99 (C++98 compatible) (mirroring `<stdatomic.h>`) and 

`satomi.hpp` for C++20 (mirroring `<atomic>` which is also `constexpr`)

## Why does this exist?
Portable lock-less 16 byte atomics on x86 don't exist (with the exception of [boost.atomic](https://github.com/boostorg/atomic)) at the time of writing. This library was created to unify behaviours across compilers, while being simple to use and maintain.

From the big 3: 
 - Clang is the only one with support for them but they are hidden behind a compiler flag (`-mcx16`), 
 - MSVC doesn't guarantee them because changing that will constitute an [ABI break](https://developercommunity.visualstudio.com/t/optimize-stdatomic-for-16-byte-types-use-interlock/498970#T-N1528823) (but they're enabled in atomic_ref), 
 - GCC [doesn't honour -mcx16](https://gcc.gnu.org/bugzilla/show_bug.cgi?id=80878) to force generation of desired assembly, so the only way to get the correct behaviour is to use the old `__sync` builtins, which the `__atomic` builtins were supposed to replace. 

For a more in-depth analysis I recommend reading [Timur Doumler's blog post](https://timur.audio/dwcas-in-c) on the matter.

---

If you already know how to use atomics, the API should look familiar, however there are some slight differences.

In the C99 version:

1. Because C doesn't have arbitrary generics and not every compiler has extensions for this purpose, wherever there's a `T` return value, the store needs to be passed as an out-parameter, i.e. `atomic_load(&variable, &atomic)`. Those out-parameters can also be `NULL`.
2. The API is provided through macros that wrap the same underlying functions with a `satomi__` prefix. There's a customisation point `SATOMI_DO_NOT_DEFINE_MACROS` which will allow you to define your own macros if the provided ones are not suitable. There's also `SATOMI_DO_NOT_DEFINE_MEMORY_ORDER` to avoid memory order enum definition.
3. `atomic_wait/notify_one/notify_all` have been added from the C++20 API.

In the C++20 version:

1. The free functions take regular `T &` instead of `satomi::atomic<T> *`, so that regular variables can also be treated atomically if needs be.
2. `atomic_wait` internally performs `atomic_load`s, so the most recent load is returned from the function.
3. No operators are overloaded to discourage the bad habit of treating atomics like regular variables.

## Warnings and Caveats
1. If you're using the C99 version of the library, please **MAKE SURE TO CLEAR PADDING** bits otherwise `compare_exchange`s will **FAIL** even if the value-representation matches. In the C++20 version that's taken care of by intrinsics that are not available in C99.
2. Only x86-64 and aarch64 (little endian only) are supported.
3. Objects larger than what the CPU architecture allows for CAS operations (16 bytes) are not supported since they require locks. Create your own mechanisms with the atomics here (using the wait/notify primitives) if you have such a use case.
4. When using the free functions or C++20 atomic_ref to do atomic operations you have to make sure your variables are self-aligned (meaning `address of object` % `size of object` == 0). If alignment isn't honoured the functions WILL abort (`SIGILL`/`SIGTRAP`) the program because you will get UB otherwise.


## Examples

### C
```c
volatile int a = 1;
int add = 1;
atomic_fetch_add(NULL, &a, &add, memory_order_relaxed);
add = 2;
atomic_fetch_sub(NULL, &a, &add, memory_order_acq_rel);
int b;
atomic_load(&b, &a, memory_order_acquire);

uint16_t wants_to_be_atomic = 0;
uint16_t store = 5;
atomic_store(&wants_to_be_atomic, &store, memory_order_seq_cst);
uint16_t c;
atomic_load(&c, &wants_to_be_atomic, memory_order_relaxed);
store = 2;
atomic_compare_exchange_strong(&wants_to_be_atomic, &c, &store, memory_order_acq_rel);

volatile double d = 32.0;
double e;
atomic_load(&e, &d, memory_order_acquire);
// some math...
atomic_store(&d, &e, memory_order_release);

#if defined(_MSC_VER) && !defined(__clang__)
  #define ALIGNAS(x) __declspec(align(x))
#else
  #define ALIGNAS(x) __attribute__((aligned(x)))
#endif

struct ALIGNAS(16) uuid_t
{
  uint32_t part_1;
  uint16_t part_2;
  uint16_t part_3;
  uint64_t part_4;
} uuid = { 0x56264c8d, 0xbb85, 0x44dc, 0xb3ddf6926baad9ee };

struct uuid_t uuid_copy;
atomic_load(&uuid_copy, &uuid, memory_order_relaxed);
struct uuid_t new_uuid = { 0xc34d62f8, 0x8b76, 0x425c, 0x99e88c4bd60f227c };
atomic_compare_exchange_weak(&uuid, &uuid_copy, &new_uuid, memory_order_acq_rel);
```

### C++
```c++
satomi::atomic a = 1;
a.fetch_add(1, satomi::memory_order_relaxed);
a.fetch_sub(2, satomi::memory_order_acq_rel);
int b = a.load(satomi::memory_order_acquire);

uint16_t wants_to_be_atomic = 0;
satomi::atomic_store(wants_to_be_atomic, uint16_t(5), satomi::memory_order_seq_cst);
uint16_t c = satomi::atomic_load(wants_to_be_atomic, satomi::memory_order_relaxed);
satomi::atomic_compare_exchange_strong(wants_to_be_atomic, c, uint16_t(2), satomi::memory_order_acq_rel);

satomi::atomic<double> d = 32.0;
auto e = d.load(satomi::memory_order_acquire);
// some math...
d.store(e, satomi::memory_order_release);

struct alignas(16) uuid_t
{
  constexpr bool operator==(const uuid_t &) const = default;

  uint32_t part_1;
  uint16_t part_2;
  uint16_t part_3;
  uint64_t part_4;
} uuid = { 0x56264c8d, 0xbb85, 0x44dc, 0xb3ddf6926baad9ee };

satomi::atomic_ref uuid_ref{ uuid };
auto uuid_copy = uuid_ref.load(satomi::memory_order_relaxed);
uuid_ref.compare_exchange_weak(uuid_copy, { 0xc34d62f8, 0x8b76, 0x425c, 0x99e88c4bd60f227c }, satomi::memory_order_acq_rel);
```
