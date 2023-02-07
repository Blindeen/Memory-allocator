#include "heap.h"

int main() {
    heap_setup();

    void *ptr = heap_malloc(10); //instead of malloc we can use calloc to set 0 for allocated memory
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
