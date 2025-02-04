# Memory allocator in C
## Description
Memory allocator written in C language. It allows to allocate, reallocate and free memory.
## Author
[@Blindeen](https://www.github.com/Blindeen)
## Features
* Allocation
* Reallocation
* Freeing
## Usage
```c
#include "heap.h"

int main() {
    heap_setup();

    void *ptr = heap_malloc(10);
    if(ptr == NULL)
    {
        return -1;
    }

    void *tmp = heap_realloc(ptr, 100);
    if(tmp == NULL)
    {
        heap_free(ptr);
        return -1;
    }
    ptr = tmp;

    heap_free(ptr);

    heap_clean();
    return 0;
}
```
