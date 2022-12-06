#include <string.h>
#include <stdint.h>
#include <math.h>
#include "heap.h"
#include "custom_unistd.h"

#define FENCE_LENGTH 16
#define PAGE_SIZE 4096
#define NUMBER 420

struct memory_manager_t memoryManager;

int heap_setup(void)
{
    memoryManager.memory_start = custom_sbrk(PAGE_SIZE);
    if(*(int *)memoryManager.memory_start == -1)
    {
        return -1;
    }

    memoryManager.memory_size = PAGE_SIZE;
    memoryManager.first_memory_chunk = NULL;

    return 0;
}

void heap_clean(void)
{
    memset(memoryManager.memory_start, 0, memoryManager.memory_size);
    custom_sbrk(-(intptr_t )memoryManager.memory_size);
    memoryManager.memory_size = 0;
    memoryManager.memory_start = NULL;
    memoryManager.first_memory_chunk = NULL;
}

void* heap_malloc(size_t size)
{
    if(heap_validate() || !size)
    {
        return NULL;
    }

    struct memory_chunk_t *chunk = memoryManager.memory_start;
    if(!memoryManager.first_memory_chunk)
    {
        if(memoryManager.memory_size < size + sizeof(struct memory_chunk_t) + 2 * FENCE_LENGTH)
        {
            long double add_size = (long double)(size + sizeof(struct memory_chunk_t) + 2 * FENCE_LENGTH)/(long double)PAGE_SIZE;
            add_size = ceill(add_size);
            if(custom_sbrk((intptr_t)(add_size * PAGE_SIZE)) == (void *)-1)
            {
                return NULL;
            }
            memoryManager.memory_size += (size_t)(add_size * PAGE_SIZE);
        }

        chunk->size = size;
        chunk->prev = NULL;
        chunk->next = NULL;
        chunk->free = 0;

        memset((char *)chunk + sizeof(struct memory_chunk_t), '#', FENCE_LENGTH);
        memset((char *)chunk + sizeof(struct memory_chunk_t) + FENCE_LENGTH + chunk->size, '#', FENCE_LENGTH);

        memoryManager.first_memory_chunk = chunk;

        set_checksum();
        return (void *)((char *)chunk + sizeof(struct memory_chunk_t) + FENCE_LENGTH);
    }
    else
    {
        struct memory_chunk_t *ptr = memoryManager.first_memory_chunk;
        while(ptr)
        {
            if(ptr->size >= size && ptr->free)
            {
                ptr->size = size;
                ptr->free = 0;
                memset((char *)ptr + sizeof(struct memory_chunk_t) + FENCE_LENGTH + ptr->size, '#', FENCE_LENGTH);
                set_checksum();

                return (void *)((char *)ptr + sizeof(struct memory_chunk_t) + FENCE_LENGTH);
            }

            if (ptr->next)
            {
                size_t space = (char *)ptr->next - (char *)ptr - sizeof(struct memory_chunk_t) - ptr->size - FENCE_LENGTH * 2;
                if (sizeof(struct memory_chunk_t) + size + FENCE_LENGTH * 2 <= space)
                {
                    struct memory_chunk_t *new = (struct memory_chunk_t *) ((char *) ptr +
                                                                            sizeof(struct memory_chunk_t) + ptr->size +
                                                                            FENCE_LENGTH * 2);
                    new->size = size;
                    new->prev = ptr;
                    new->next = ptr->next;
                    ptr->next->prev = new;
                    ptr->next = new;
                    new->free = 0;
                    memset((char *)new + sizeof(struct memory_chunk_t), '#', FENCE_LENGTH);
                    memset((char *)new + sizeof(struct memory_chunk_t) + FENCE_LENGTH + new->size, '#', FENCE_LENGTH);
                    set_checksum();
                    return (void *)((char *)new + sizeof(struct memory_chunk_t) + FENCE_LENGTH);
                }
            }
            else
            {
                size_t allocated_memory = (size_t)(((char *)ptr + sizeof(struct memory_chunk_t) + ptr->size + 2 * FENCE_LENGTH) - (char *)memoryManager.memory_start);
                if(memoryManager.memory_size - allocated_memory < size + sizeof(struct memory_chunk_t) + 2 * FENCE_LENGTH)
                {
                    long double add_size = (long double)(size + sizeof(struct memory_chunk_t) + 2 * FENCE_LENGTH)/(long double)PAGE_SIZE;
                    add_size = ceill(add_size);
                    if(custom_sbrk((intptr_t)(add_size * PAGE_SIZE)) == (void *)-1)
                    {
                        return NULL;
                    }

                    memoryManager.memory_size += (size_t)(add_size * PAGE_SIZE);
                }

                ptr->next = (struct memory_chunk_t *)((char *)ptr + sizeof(struct memory_chunk_t) + ptr->size + 2 * FENCE_LENGTH);
                ptr->next->prev = ptr;
                ptr->next->next = NULL;
                ptr->next->size = size;
                ptr->next->free = 0;

                memset((char *)ptr->next + sizeof(struct memory_chunk_t), '#', FENCE_LENGTH);
                memset((char *)ptr->next + sizeof(struct memory_chunk_t) + FENCE_LENGTH + ptr->next->size, '#', FENCE_LENGTH);

                set_checksum();
                return (void *)((char *)ptr->next + sizeof(struct memory_chunk_t) + FENCE_LENGTH);
            }

            ptr = ptr->next;
        }
    }

    return NULL;
}

void* heap_calloc(size_t number, size_t size)
{
    void *mem = heap_malloc(number * size);
    if(mem)
    {
        memset(mem, 0, number * size);
    }

    return mem;
}

void* heap_realloc(void* memblock, size_t count)
{
    if(heap_validate())
    {
        return NULL;
    }

    if(!memblock)
    {
        return heap_malloc(count);
    }

    if (get_pointer_type(memblock) != pointer_valid)
    {
        return NULL;
    }

    if(!count)
    {
        heap_free(memblock);
        return NULL;
    }

    struct memory_chunk_t *ptr = memoryManager.first_memory_chunk;
    while(ptr)
    {
        if(((char *)ptr + sizeof(struct memory_chunk_t) + FENCE_LENGTH) == (char *)memblock)
        {
            if(ptr->size == count)
            {
                return memblock;
            }

            if(count < ptr->size)
            {
                ptr->size = count;
                memset((char *)ptr + sizeof(struct memory_chunk_t) + FENCE_LENGTH + ptr->size, '#', FENCE_LENGTH);
                set_checksum();

                return memblock;
            }

            if (!ptr->next)
            {
                size_t allocated_memory = (size_t)(((char *)ptr + sizeof(struct memory_chunk_t) + ptr->size + 2 * FENCE_LENGTH) - (char *)memoryManager.memory_start);
                if(memoryManager.memory_size - allocated_memory < count - ptr->size)
                {
                    long double add_size = (long double)(count - ptr->size)/(long double)PAGE_SIZE; // This line has been change to (count - ptr->size)
                    add_size = ceill(add_size);
                    if(custom_sbrk((intptr_t)(add_size * PAGE_SIZE)) == (void *)-1)
                    {
                        return NULL;
                    }

                    memoryManager.memory_size += (size_t)(add_size * PAGE_SIZE);
                }

                ptr->size = count;
                memset((char *)ptr + sizeof(struct memory_chunk_t) + FENCE_LENGTH + ptr->size, '#', FENCE_LENGTH);
                set_checksum();

                return memblock;
            }

            if((char *)ptr->next - (char *)ptr - sizeof(struct memory_chunk_t) - FENCE_LENGTH * 2 >= count)
            {
                ptr->size = count;
                ptr->free = 0;
                memset((char *)ptr + sizeof(struct memory_chunk_t) + FENCE_LENGTH + ptr->size, '#', FENCE_LENGTH);
                set_checksum();

                return memblock;
            }
            else if(ptr->next->free && (char *)ptr->next->next - (char *)ptr - sizeof(struct memory_chunk_t) - FENCE_LENGTH * 2 >= count)
            {
                ptr->size = (size_t)((char *)ptr->next - (char *)ptr - sizeof(struct memory_chunk_t) - FENCE_LENGTH * 2);
                ptr->size = ptr->size + ptr->next->size + sizeof(struct memory_chunk_t) + 2 * FENCE_LENGTH;
                ptr->size = count;
                ptr->next = ptr->next->next;
                ptr->next->prev = ptr;
                ptr->free = 0;

                memset((char *)ptr + sizeof(struct memory_chunk_t) + FENCE_LENGTH + ptr->size, '#', FENCE_LENGTH);
                set_checksum();

                return memblock;
            }
        }
        ptr = ptr->next;
    }

    ptr = memoryManager.first_memory_chunk;
    while (ptr)
    {
        if (ptr->free && ptr->size >= count)
        {
            ptr->free = 0;
            ptr->size = count;
            struct memory_chunk_t* old_chunk = (struct memory_chunk_t *) ((char *) memblock -
                                                                          sizeof(struct memory_chunk_t) -
                                                                          FENCE_LENGTH);
            memcpy((char *)ptr + sizeof(struct memory_chunk_t) + FENCE_LENGTH, memblock, old_chunk->size);
            memset((char *)ptr + sizeof(struct memory_chunk_t) + FENCE_LENGTH + ptr->size, '#', FENCE_LENGTH);
            set_checksum();
            heap_free(memblock);
            return (void *)((char *)ptr + sizeof(struct memory_chunk_t) + FENCE_LENGTH);
        }

        ptr = ptr->next;
    }

    void *new_ptr = heap_malloc(count);
    if (!new_ptr)
    {
        return NULL;
    }
    struct memory_chunk_t* old_chunk = (struct memory_chunk_t *) ((char *) memblock -
                                                                  sizeof(struct memory_chunk_t) -
                                                                  FENCE_LENGTH);
    memcpy((char *)new_ptr, memblock, old_chunk->size);
    set_checksum();
    heap_free(memblock);
    return new_ptr;
}

void heap_free(void* memblock)
{
    if(get_pointer_type(memblock) == pointer_valid)
    {
        size_t taken_chunks = 0;
        struct memory_chunk_t *ptr = memoryManager.first_memory_chunk;
        while(ptr)
        {
            if(((char *)ptr + sizeof(struct memory_chunk_t) + FENCE_LENGTH) == (char *)memblock)
            {
                if(ptr == memoryManager.first_memory_chunk && !ptr->next)
                {
                    memoryManager.first_memory_chunk = NULL;
                    break;
                }

                if(ptr->next)
                {
                    if(ptr->size != (size_t)((char *)ptr->next - (char *)(ptr) - sizeof(struct memory_chunk_t) - 2 * FENCE_LENGTH))
                    {
                        ptr->size = (size_t)((char *)ptr->next - (char *)(ptr) - sizeof(struct memory_chunk_t) - 2 * FENCE_LENGTH);
                    }
                }
                else
                {
                    ptr->prev->next = NULL;
                    if (ptr->prev->free)
                    {
                        if (ptr->prev->prev)
                        {
                            ptr->prev->prev->next = NULL;
                        }
                    }
                    break;
                }

                ptr->free = 1;

                if((ptr->prev && ptr->prev->free) && (ptr->next && ptr->next->free))
                {
                    ptr->prev->size = ptr->prev->size + ptr->size + ptr->next->size + 4 * FENCE_LENGTH + 2 * sizeof(struct memory_chunk_t);
                    ptr->prev->next = ptr->next->next;
                    ptr->next->next->prev = ptr->prev;
                    ptr->prev->free = 1;
                }
                else if(ptr->prev && ptr->prev->free)
                {
                    ptr->prev->size = ptr->prev->size + ptr->size + sizeof(struct memory_chunk_t) + 2 * FENCE_LENGTH;
                    ptr->prev->next = ptr->next;
                    ptr->next->prev = ptr->prev;
                    ptr->prev->free = 1;

                }
                else if(ptr->next && ptr->next->free)
                {
                    ptr->size = ptr->size + ptr->next->size + sizeof(struct memory_chunk_t) + 2 * FENCE_LENGTH;
                    ptr->next = ptr->next->next;
                    ptr->next->prev = ptr;
                    ptr->free = 1;
                }
            }
            else
            {
                if(!ptr->free)
                {
                    taken_chunks += 1;
                }
            }

            ptr = ptr->next;
        }

        if(!taken_chunks)
        {
            memoryManager.first_memory_chunk = NULL;
        }
    }

    set_checksum();
}

size_t heap_get_largest_used_block_size(void)
{
    if(heap_validate() || !memoryManager.first_memory_chunk || !memoryManager.memory_start)
    {
        return 0;
    }

    struct memory_chunk_t *ptr = memoryManager.first_memory_chunk;
    size_t max = 0;

    while(ptr)
    {
        if(!ptr->free)
        {
            if(ptr->size > max)
            {
                max = ptr->size;
            }
        }

        ptr = ptr->next;
    }

    return max;
}

enum pointer_type_t get_pointer_type(const void* const pointer)
{
    if(!pointer)
    {
        return pointer_null;
    }

    if(heap_validate())
    {
        return pointer_heap_corrupted;
    }

    struct memory_chunk_t *ptr = memoryManager.first_memory_chunk;
    while(ptr)
    {
        if(!ptr->free)
        {
            for(size_t i = 0; i < sizeof(struct memory_chunk_t); ++i)
            {
                if((char *)pointer == (char *)ptr+i)
                {
                    return pointer_control_block;
                }
            }

            for(size_t i = 0; i < FENCE_LENGTH; ++i)
            {
                if((char *)pointer == (char *)ptr + sizeof(struct memory_chunk_t)+i)
                {
                    return pointer_inside_fences;
                }
            }

            if((char *)pointer == ((char *)ptr + sizeof(struct memory_chunk_t) + FENCE_LENGTH))
            {
                return pointer_valid;
            }

            for(size_t i = 1; i < ptr->size; ++i)
            {
                if((char *)pointer == (char *)ptr + sizeof(struct memory_chunk_t) + FENCE_LENGTH + i)
                {
                    return pointer_inside_data_block;
                }
            }

            for(size_t i = 0; i < FENCE_LENGTH; ++i)
            {
                if((char *)pointer == (char *)ptr + sizeof(struct memory_chunk_t) + FENCE_LENGTH + ptr->size + i)
                {
                    return pointer_inside_fences;
                }
            }
        }
        ptr = ptr->next;
    }

    return pointer_unallocated;
}

int heap_validate(void)
{
    if(!memoryManager.memory_start)
    {
        return 2;
    }

    struct memory_chunk_t *ptr = memoryManager.first_memory_chunk;
    while(ptr)
    {
        if(ptr->checksum != checksum(ptr))
        {
            return 3;
        }
        if(ptr->free && ptr->free != 1)
        {
            return 3;
        }
        if(!ptr->free)
        {


            if(!ptr->size || ptr->size > memoryManager.memory_size)
            {
                return 3;
            }

            if(ptr->prev && ptr->prev->next != ptr)
            {
                return 3;
            }

            if(ptr->next && ptr->next->prev != ptr)
            {
                return 3;
            }

            for(size_t i = 0; i < FENCE_LENGTH; ++i)
            {
                if(*((char *)ptr + sizeof(struct memory_chunk_t) + i) != '#')
                {
                    return 1;
                }
            }

            for(size_t i = 0; i < FENCE_LENGTH; ++i)
            {
                if(*((char *)ptr + sizeof(struct memory_chunk_t) + FENCE_LENGTH + ptr->size + i) != '#')
                {
                    return 1;
                }
            }
        }
        ptr = ptr->next;
    }

    return 0;
}

unsigned int checksum(struct memory_chunk_t *chunk)
{
    if(!chunk)
    {
        return 0;
    }

    unsigned int check_sum = NUMBER;

    check_sum ^= ((uintptr_t)chunk->prev & 0xffffffff);
    check_sum ^= (((uintptr_t)chunk->prev >> 32) & 0xffffffff);
    check_sum ^= ((uintptr_t)chunk->next & 0xffffffff);
    check_sum ^= (((uintptr_t)chunk->next >> 32) & 0xffffffff);
    check_sum ^= chunk->size;

    return check_sum;
}

void set_checksum(void)
{
    struct memory_chunk_t *chunk = memoryManager.first_memory_chunk;
    while (chunk)
    {
        chunk->checksum = checksum(chunk);
        chunk = chunk->next;
    }
}

unsigned int allocated_chunks_amount(void)
{
    struct memory_chunk_t *ptr = memoryManager.first_memory_chunk;
    unsigned int amount = 0;
    while(ptr)
    {
        if(!ptr->free)
            ++amount;
        ptr = ptr->next;
    }

    return amount;
}
