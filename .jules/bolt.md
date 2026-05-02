## 2024-05-02 - O(N) single-pass iteration is better than O(5N) vector allocations
**Learning:** In Rust, doing multiple `iter().filter(...).collect::<Vec<_>>()` just to get lengths is an anti-pattern. It allocates multiple vectors and iterates over the array 5 times.
**Action:** Use a single loop with mutable counters or use `fold` to count different categories in a single pass with O(1) memory.
