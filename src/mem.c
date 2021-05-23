
#include "mem.h"
#include "stdlib.h"
#include "string.h"
#include <pthread.h>
#include <stdio.h>

static BYTE _ram[RAM_SIZE];

static struct
{
  uint32_t proc; // ID of process currently uses this page
  int index;     // Index of the page in the list of pages allocated
                 // to the process.
  int next;      // The next page in the list. -1 if it is the last
                 // page.
} _mem_stat[NUM_PAGES];

static pthread_mutex_t mem_lock;

void init_mem(void)
{
  memset(_mem_stat, 0, sizeof(*_mem_stat) * NUM_PAGES);
  memset(_ram, 0, sizeof(BYTE) * RAM_SIZE);
  pthread_mutex_init(&mem_lock, NULL);
}

/* get offset of the virtual address */
static addr_t get_offset(addr_t addr)
{
  return addr & ~((~0U) << OFFSET_LEN);
}

/* get the first layer index */
static addr_t get_first_lv(addr_t addr)
{
  return addr >> (OFFSET_LEN + PAGE_LEN);
}

/* get the second layer index */
static addr_t get_second_lv(addr_t addr)
{
  return (addr >> OFFSET_LEN) - (get_first_lv(addr) << PAGE_LEN);
}

/* Search for page table table from the a segment table */
static struct page_table_t *get_page_table(
    addr_t index, // Segment level index
    struct seg_table_t *seg_table)
{ // first level table

  /*
   * Given the segment index [index], you must go through each
   * row of the segment table [seg_table] and check if the v_index
   * field of the row is equal to the index
   */

  int i;
  for (i = 0; i < seg_table->size; i++)
  {
    // Enter your code here
    if (seg_table->table[i].v_index == index)
      return seg_table->table[i].pages;
  }
  return NULL;
}

/*
 * Translate virtual address to physical address. If [virtual_addr] is valid,
 * return 1 and write its physical counterpart to [physical_addr].
 * Otherwise, return 0
 */
static int translate(
    addr_t virtual_addr,   // Given virtual address
    addr_t *physical_addr, // Physical address to be returned
    struct pcb_t *proc)
{ // Process uses given virtual address

  /* Offset of the virtual address */
  addr_t offset = get_offset(virtual_addr);
  /* The first layer index */
  addr_t first_lv = get_first_lv(virtual_addr);
  /* The second layer index */
  addr_t second_lv = get_second_lv(virtual_addr);

  /* Search in the first level */
  struct page_table_t *page_table = NULL;
  page_table = get_page_table(first_lv, proc->seg_table);
  if (page_table == NULL)
    return 0;

  int i;
  for (i = 0; i < page_table->size; i++)
  {
    if (page_table->table[i].v_index == second_lv)
    {
      /*
       * Concatenate the offset of the virtual addess
       * to [p_index] field of page_table->table[i] to
       * produce the correct physical address and save it to
       * [*physical_addr]
       */

      *physical_addr = (page_table->table[i].p_index << OFFSET_LEN) | offset;
      return 1;
    }
  }
  return 0;
}

addr_t alloc_mem(uint32_t size, struct pcb_t *proc)
{
  pthread_mutex_lock(&mem_lock);

  addr_t head_ptr = 0;
  uint32_t req_page = (size % PAGE_SIZE == 0) ? size / PAGE_SIZE : size / PAGE_SIZE + 1; // Number of pages we will use
  int mem_avail = 0;

  /*
   * First we must check if the amount of free memory in
   * virtual address space and physical address space is
   * large enough to represent the amount of required
   * memory. If so, set 1 to [mem_avail].
   * Hint: check [proc] bit in each page of _mem_stat
   * to know whether this page has been used by a process.
   * For virtual memory space, check bp (break pointer).
   */

  /* iterate over frames, note the indices of free frames
   * while also counting for physical space */
  uint32_t free_page = 0;
  int free_frames[req_page];
  int i = 0, j = 0;
  while (free_page < req_page && i < NUM_PAGES)
  {
    if (_mem_stat[i].proc == 0)
    {
      free_page += 1;
      free_frames[j] = i;
      j += 1;
    }
    i += 1;
  }

  // * Minimum space required
  if (free_page >= req_page)
    mem_avail = 1;

  if (mem_avail)
  {
    /* We could allocate new memory region to the process */
    head_ptr = proc->bp;
    proc->bp = head_ptr + req_page * PAGE_SIZE;

    /*
     * Update status of physical pages which will be allocated
     * to [proc] in _mem_stat. Tasks to do:
     * 	- Update [proc], [index], and [next] field
     * 	- Add entries to segment table page tables of [proc]
     * 	  to ensure accesses to allocated memory slot is
     * 	  valid.
     */

    /* physical
     * update index, next and proc in frames with saved indices */
    for (j = 0; j < req_page; j++)
    {
      int frame_idx = free_frames[j];
      _mem_stat[frame_idx].proc = proc->pid;
      _mem_stat[frame_idx].index = j;
      _mem_stat[frame_idx].next = -1;

      if (j < req_page - 1)
        _mem_stat[frame_idx].next = free_frames[j + 1];
    }

    /* virtual
     * infer 1st and 2nd lv index, use them to search for seg and
     * page with matching v_index
     * if there isn't any, alloc/assign to a new one at (size - 1)
     * for both tables, then assign the values needed
     */
    addr_t itr_ptr = head_ptr;
    for (j = 0; j < req_page; j++)
    {
      addr_t first_lv = get_first_lv(itr_ptr);
      addr_t second_lv = get_second_lv(itr_ptr);
      struct seg_table_t *seg_table = proc->seg_table;
      struct page_table_t *page_table = get_page_table(first_lv, seg_table);

      // create new entry
      if (page_table == NULL)
      {
        int seg_size = seg_table->size;
        seg_table->table[seg_size].v_index = first_lv;
        page_table = (struct page_table_t *)malloc(sizeof(struct page_table_t));
        seg_table->table[seg_size].pages = page_table;
        page_table->size = 0;
        seg_table->size++;
      }

      // assign values
      int page_size = page_table->size;
      page_table->table[page_size].v_index = second_lv;
      page_table->table[page_size].p_index = free_frames[j];
      page_table->size++;

      itr_ptr += PAGE_SIZE;
    }
  }
  pthread_mutex_unlock(&mem_lock);

  return head_ptr;
}

int free_mem(addr_t address, struct pcb_t *proc)
{
  /*
   * Release memory region allocated by [proc]. The first byte of
   * this region is indicated by [address]. Task to do:
   * 	- Set flag [proc] of physical page use by the memory block
   * 	  back to zero to indicate that it is free.
   * 	- Remove unused entries in segment table and page tables of
   * 	  the process [proc].
   * 	- Remember to use lock to protect the memory from other
   * 	  processes.
   */

  pthread_mutex_lock(&mem_lock);

  // swap return values?
  addr_t p_addr;
  addr_t v_addr = address;
  if (translate(v_addr, &p_addr, proc) == 0)
    return 1;

  /* mark frames in _mem_stat as unused
   * count how many were marked */
  int freed_pages = 0;
  int p_index = (p_addr >> OFFSET_LEN);
  while (p_index != -1)
  {
    _mem_stat[p_index].proc = 0;
    freed_pages += 1;
    p_index = _mem_stat[p_index].next;
  }

  v_addr += PAGE_SIZE * freed_pages;

  /*
   * Preventing fragmentation:
   * We are removing page entries of the process
   * hence bumping all pages forward to maintain contiguity
   * Uses new_v_addr to get the location of the destination and
   * old_v_addr for the source through, achieved by getting
   * their first and second levels
   */
  if (proc->bp != v_addr)
  {
    addr_t new_v_addr = address; // Address of next data chunk after dealloc this process
    addr_t old_v_addr = v_addr;  // Address of next data chunk

    // move one page up at a time
    while (proc->bp != old_v_addr)
    {
      // retrieve their first and second levels
      addr_t new_first_lv = get_first_lv(new_v_addr);
      addr_t new_second_lv = get_second_lv(new_v_addr);
      addr_t old_first_lv = get_first_lv(old_v_addr);
      addr_t old_second_lv = get_second_lv(old_v_addr);

      /* locate the dest and src page based on levels
       * use their normal indices to move */
      struct seg_table_t *seg_table = proc->seg_table;
      struct page_table_t *new_page_table = get_page_table(new_first_lv, seg_table);
      struct page_table_t *old_page_table = get_page_table(old_first_lv, seg_table);
      if (new_page_table != NULL && old_page_table != NULL)
      {
        int new_page_index;
        int old_page_index;

        for (new_page_index = 0; new_page_index < new_page_table->size; new_page_index++)
          if (new_page_table->table[new_page_index].v_index == new_second_lv)
            break;
        for (old_page_index = 0; old_page_index < old_page_table->size; old_page_index++)
          if (old_page_table->table[old_page_index].v_index == old_second_lv)
            break;

        new_page_table->table[new_page_index].p_index = old_page_table->table[old_page_index].p_index;
        new_page_table->table[new_page_index].v_index = new_second_lv;
      }

      // update registers that hold old addresses
      for (int i = 0; i < 10; i++)
      {
        if (proc->regs[i] == old_v_addr)
        {
          proc->regs[i] = new_v_addr;
          break;
        }
      }

      new_v_addr += PAGE_SIZE;
      old_v_addr += PAGE_SIZE;
    }
  }

  // decreases size and free page_table if empty afterwards
  int tmp = freed_pages;
  while (freed_pages > 0)
  {
    int seg_size = proc->seg_table->size;
    struct seg_table_t *seg_table = proc->seg_table;
    struct page_table_t *page_table = get_page_table(seg_size - 1, seg_table);
    if (page_table != NULL)
    {
      page_table->size--;
      if (page_table->size == 0)
      {
        free(page_table);
        seg_table->size--;
      }
    }
    freed_pages--;
  }

  // update bp
  proc->bp -= tmp * PAGE_SIZE;

  pthread_mutex_unlock(&mem_lock);

  return 0;
}

int read_mem(addr_t address, struct pcb_t *proc, BYTE *data)
{
  addr_t physical_addr;
  if (translate(address, &physical_addr, proc))
  {
    *data = _ram[physical_addr];
    return 0;
  }
  else
  {
    return 1;
  }
}

int write_mem(addr_t address, struct pcb_t *proc, BYTE data)
{
  addr_t physical_addr;
  if (translate(address, &physical_addr, proc))
  {
    _ram[physical_addr] = data;
    return 0;
  }
  else
  {
    return 1;
  }
}

void dump(void)
{
  int i;
  for (i = 0; i < NUM_PAGES; i++)
  {
    if (_mem_stat[i].proc != 0)
    {
      printf("%03d: ", i);
      printf("%05x-%05x - PID: %02d (idx %03d, nxt: %03d)\n",
             i << OFFSET_LEN,
             ((i + 1) << OFFSET_LEN) - 1,
             _mem_stat[i].proc,
             _mem_stat[i].index,
             _mem_stat[i].next);
      int j;
      for (j = i << OFFSET_LEN;
           j < ((i + 1) << OFFSET_LEN) - 1;
           j++)
      {

        if (_ram[j] != 0)
        {
          printf("\t%05x: %02x\n", j, _ram[j]);
        }
      }
    }
  }
}
