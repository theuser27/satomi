# satomi
### s(imple)atomi(c)

Completely lock-less constexpr C++20 header replacement for `<atomic>` 

## Why does this exist?
TL;DR: portable lock-less 16 byte atomics don't exist (with the exception of [boost.atomic](https://github.com/boostorg/atomic)) at the time of writing.

Every compiler has a different opinion on lock-less 16 byte atomics and they rarely align with the others. From the big 3: 
 - Clang supports them but they are hidden behind a compiler flag (`-mcx16`), 
 - MSVC doesn't guarantee them because changing that will constitute an [ABI break](https://developercommunity.visualstudio.com/t/optimize-stdatomic-for-16-byte-types-use-interlock/498970#T-N1528823) (but they're enabled in atomic_ref), 
 - GCC [doesn't even honour compiler flags](https://gcc.gnu.org/bugzilla/show_bug.cgi?id=80878) to force generation of desired assembly, so the only way to get the correct behaviour is to use the old `__sync` builtins, which the `__atomic` builtins were supposed to replace. 

For a more in-depth analysis I recommend reading [Timur Doumler's blog post](https://timur.audio/dwcas-in-c) on the matter.

This library was created to unify behaviours across compilers, while being simple to use and maintain.

---

If you already know how to use atomics, the API should look familiar. There are however slight differences (+ some opinions on how atomics should be used).

1. The free functions take regular `T &` instead of `std::atomic<T> *` 
2. No operators are overloaded to discourage the bad habit of treating atomics like regular variables.

## Warnings and Caveats
1. Only x86_64 and arm64 are supported for now.
2. Objects larger than what the CPU architecture allows for CAS operations (16 bytes) are not supported since they require locks. Create your own mechanisms with the atomics here (using the wait/notify primitives) if you have such a use case.
3. When using the free functions or atomic_ref to do atomic operations you have to make sure your variables are self-aligned (meaning `address of object` % `size of object` == 0). If alignment isn't honoured the functions WILL abort (`SIGILL`/`SIGTRAP`) the program because you will get UB otherwise.
4. On linux this library currently depends on libc for atomic intrisincs for <= 8 bytes, which are universally lock-less (will most likely change this in the future).


## Examples
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

sat::atomic<double> c{};
c.fetch_add(32.0);
auto d = c.load(sat::memory_order_acquire);
// some math...
c.store(d, sat::memory_order_release);

struct alignas(16) broken_up_uuid_t
{
  constexpr bool operator==(const broken_up_uuid_t &) const = default;

  uint32_t part_1;
  uint16_t part_2;
  uint16_t part_3;
  uint64_t part_4;
} uuid = { 0x56264c8d, 0xbb85, 0x44dc, 0xb3ddf6926baad9ee };

sat::atomic_ref uuid_ref{ uuid };
auto uuid_copy = uuid_ref.load(sat::memory_order_relaxed);
uuid_ref.compare_exchange_weak(uuid_copy, { 0xc34d62f8, 0x8b76, 0x425c, 0x99e88c4bd60f227c }, sat::memory_order_acq_rel);
```

