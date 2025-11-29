# satomi
### s(imple)atomi(c)

Completely lock-less atomic headers: 

`satomi.h` for C99 (C++98 compatible) (mirroring `<stdatomic.h>`) and 

`satomi.hpp` for C++20 (mirroring `<atomic>` which is also `constexpr`)

## Why does this exist?
TL;DR: portable lock-less 16 byte atomics don't exist (with the exception of [boost.atomic](https://github.com/boostorg/atomic)) at the time of writing.

Every compiler has a different opinion on lock-less 16 byte atomics and they rarely align with the others. From the big 3: 
 - Clang supports them but they are hidden behind a compiler flag (`-mcx16`), 
 - MSVC doesn't guarantee them because changing that will constitute an [ABI break](https://developercommunity.visualstudio.com/t/optimize-stdatomic-for-16-byte-types-use-interlock/498970#T-N1528823) (but they're enabled in atomic_ref), 
 - GCC [doesn't even honour compiler flags](https://gcc.gnu.org/bugzilla/show_bug.cgi?id=80878) to force generation of desired assembly, so the only way to get the correct behaviour is to use the old `__sync` builtins, which the `__atomic` builtins were supposed to replace. 

For a more in-depth analysis I recommend reading [Timur Doumler's blog post](https://timur.audio/dwcas-in-c) on the matter.

This library was created to unify behaviours across compilers, while being simple to use and maintain.

---

If you already know how to use atomics, the API should look familiar, however there are some slight differences.

In the C99 version:

1. Because C doesn't have arbitrary generics and not every compiler makes extensions for this purpose, wherever there's a `T` return value, the store needs to be passed as an out-parameter (i.e. `atomic_load(&variable, &atomic)`). Those out-parameters can also be `NULL`.
2. The API is provided through macros that wrap the same underlying functions with a `satomi__` prefix. There's a customisation point `SATOMI_DO_NOT_DEFINE_MACROS` which will allow you to define your own macros if the provided ones are not suitable. There's also `SATOMI_DO_NOT_DEFINE_MEMORY_ORDER` to avoid memory order enum definition.
3. `atomic_wait/notify_one/notify_all` have been added from the C++20 API.

In the C++20 version:

1. The free functions take regular `T &` instead of `satomi::atomic<T> *`, so that regular variables can also be treated atomically if needs be.
2. `atomic_wait` internally performs `atomic_load`s, so the most recent load is returned from the function.
3. No operators are overloaded to discourage the bad habit of treating atomics like regular variables.

## Warnings and Caveats
1. If you're using the C99 version of the library, please **MAKE SURE** you **CLEAR PADDING** bits otherwise `compare_exchange`s will **FAIL** even if the value-representation matches. In the C++20 version that's taken care of by intrinsics that are not available in C99.
2. Only x86_64 and arm64 are supported for now.
3. Objects larger than what the CPU architecture allows for CAS operations (16 bytes) are not supported since they require locks. Create your own mechanisms with the atomics here (using the wait/notify primitives) if you have such a use case.
4. When using the free functions or C++20 atomic_ref to do atomic operations you have to make sure your variables are self-aligned (meaning `address of object` % `size of object` == 0). If alignment isn't honoured the functions WILL abort (`SIGILL`/`SIGTRAP`) the program because you will get UB otherwise.
5. On gcc/clang this library currently depends on libc for atomic intrisincs for <= 8 bytes, which are universally lock-less, but generally do not inline corresponding instructions on arm64 (will most likely change this in the future).


## Examples

### C
```c
int a = 1;
int add = 1;
atomic_fetch_add(NULL, &a, &add, memory_order_relaxed);
add = 2;
atomic_fetch_sub(NULL, &a, &add, memory_order_acq_rel);
int b;
atomic_load(&b, &a, memory_order_acquire);

uint16_t would_like_to_be_atomic = 0;
uint16_t store = 5;
atomic_store(&would_like_to_be_atomic, &store, memory_order_seq_cst);
uint16_t atomically_loaded;
atomic_load(&atomically_loaded, &would_like_to_be_atomic, memory_order_relaxed);
store = 2;
atomic_compare_exchange_strong(&would_like_to_be_atomic, &atomically_loaded, &store, memory_order_acq_rel);

double c = 32.0;
double d;
atomic_load(&d, &c, memory_order_acquire);
// some math...
atomic_store(&c, &d, memory_order_release);

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
namespace sat = satomi;

sat::atomic a = 1;
a.fetch_add(1, sat::memory_order_relaxed);
a.fetch_sub(2, sat::memory_order_acq_rel);
int b = a.load(sat::memory_order_acquire);

uint16_t would_like_to_be_atomic = 0;
sat::atomic_store(would_like_to_be_atomic, uint16_t(5), sat::memory_order_seq_cst);
uint16_t atomically_loaded = sat::atomic_load(would_like_to_be_atomic, sat::memory_order_relaxed);
sat::atomic_compare_exchange_strong(would_like_to_be_atomic, atomically_loaded, uint16_t(2), sat::memory_order_acq_rel);

sat::atomic<double> c = 32.0;
auto d = c.load(sat::memory_order_acquire);
// some math...
c.store(d, sat::memory_order_release);

struct alignas(16) uuid_t
{
  constexpr bool operator==(const uuid_t &) const = default;

  uint32_t part_1;
  uint16_t part_2;
  uint16_t part_3;
  uint64_t part_4;
} uuid = { 0x56264c8d, 0xbb85, 0x44dc, 0xb3ddf6926baad9ee };

sat::atomic_ref uuid_ref{ uuid };
auto uuid_copy = uuid_ref.load(sat::memory_order_relaxed);
uuid_ref.compare_exchange_weak(uuid_copy, { 0xc34d62f8, 0x8b76, 0x425c, 0x99e88c4bd60f227c }, sat::memory_order_acq_rel);
```
