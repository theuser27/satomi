# satomi
### s(imple)atomi(c)

Completely lock-less constexpr C++20 header replacement for `<atomic>` 

## Why does this exist?
TL;DR: portable lock-less 16 byte atomics don't exist at the time of writing. 

Every compiler has a different opinion on lock-less 16 byte atomics and they rarely align with the others. Some (Clang) support it but it is hidden behind a compiler flag (`-mcx16`), others (MSVC) don't guarantee it because of [ABI breakage](https://developercommunity.visualstudio.com/t/optimize-stdatomic-for-16-byte-types-use-interlock/498970#T-N1528823) (but it's enabled in atomic_ref), and others still (GCC) [don't even honour compiler flags](https://gcc.gnu.org/bugzilla/show_bug.cgi?id=80878) to force generation of desired assembly and the only way to get the correct behaviour is to use the old `__sync` builtins, which the `__atomic` builtins were supposed to replace. For a more in-depth analysis I recommend reading [Timur Doumler's blog post](https://timur.audio/dwcas-in-c) on the matter.

This library was conceived to alleviate this issue.

---

If you already know how to use atomics, the API should look familiar. There are however slight differences (+ some opinions on how atomics should be used). 

1. Memory ordering is passed as a template parameter to avoid unnecessary codegen.
2. No operators are overloaded to discourage the bad habit of treating atomics like regular variables.

## Warnings and Caveats
1. Only x86_64 and arm64 are supported for now.
2. On macOS wait and notify_one/notify_all functions are not implemented yet.
3. Currently only objects with power-of-2 sizes are supported where padding bits **WILL** participate in CAS operations (would like to change this in the future).
4. Objects larger than what the CPU architecture allows for CAS operations (16 bytes) are not supported since they require locks (might change this in the future).
5. When using the free functions or atomic_ref to do atomic operations you have to make sure your variables are properly aligned to their own size (meaning `address of object` % `size of object` == 0). If alignment isn't honoured the functions WILL abort the program because you will get UB otherwise. The `atomic` template aligns the data to its own size or `alignas(sizeof(T)) T object{};`[^1].
6. On linux this library currently depends on libc for atomic intrisincs for <= 8 bytes, which are universally lock-less, and `long syscall(long, ...)` to support wait and notify primitives (will most likely change this in the future).

[^1]: Technically 16 byte atomics only need to be 8 byte aligned to work though.


## Examples
```c++
namespace sat = satomi;

sat::atomic a = 1;
a.fetch_add<sat::memory_order_relaxed>(1);
a.fetch_sub<sat::memory_order_acq_rel>(2);
int b = a.load<sat::memory_order_acquire>();

uint16_t would_like_to_be_atomic = 0;
sat::atomic_store<sat::memory_order_seq_cst>(would_like_to_be_atomic, uint16_t(5));
uint16_t atomically_loaded = sat::atomic_load<sat::memory_order_relaxed>(would_like_to_be_atomic);
sat::atomic_compare_exchange_strong<sat::memory_order_acq_rel>(would_like_to_be_atomic, atomically_loaded, uint16_t(2));

sat::atomic<double> c{};
c.fetch_add<>(32.0);
auto d = c.load<sat::memory_order_acquire>();
// some math...
c.store<sat::memory_order_release>(d);

struct broken_up_uuid_t
{
  uint32_t part_1;
  uint16_t part_2;
  uint16_t part_3;
  uint64_t part_4;
} uuid = { 0x56264c8d, 0xbb85, 0x44dc, 0xb3ddf6926baad9ee };

sat::atomic_ref uuid_ref{ uuid };
auto uuid_copy = uuid_ref.load<sat::memory_order_relaxed>();
uuid_ref.compare_exchange_weak<sat::memory_order_acq_release>(uuid_copy, { 0xc34d62f8, 0x8b76, 0x425c, 0x99e88c4bd60f227c });
```

