
#include "mem.h"
#include "stdlib.h"
#include "string.h"
#include <pthread.h>
#include <stdio.h>

#define DEBUG 0

static BYTE _ram[RAM_SIZE];

static struct {
	uint32_t proc;	// ID of process currently uses this page
	int index;	// Index of the page in the list of pages allocated
			// to the process.
	int next;	// The next page in the list. -1 if it is the last
			// page.
} _mem_stat [NUM_PAGES];

static pthread_mutex_t mem_lock;

void init_mem(void) {
	memset(_mem_stat, 0, sizeof(*_mem_stat) * NUM_PAGES);
	memset(_ram, 0, sizeof(BYTE) * RAM_SIZE);
	pthread_mutex_init(&mem_lock, NULL);
}

/* get offset of the virtual address */
static addr_t get_offset(addr_t addr) {
	return addr & ~((~0U) << OFFSET_LEN);
}

/* get the first layer index */
static addr_t get_first_lv(addr_t addr) {
	return addr >> (OFFSET_LEN + PAGE_LEN);
}

/* get the second layer index */
static addr_t get_second_lv(addr_t addr) {
	return (addr >> OFFSET_LEN) - (get_first_lv(addr) << PAGE_LEN);
}

/* Search for page table table from the a segment table */
static struct page_table_t * get_page_table(
		addr_t index, 	// Segment level index
		struct seg_table_t * seg_table) { // first level table
	
	/*
	 * TODO: Given the Segment index [index], you must go through each
	 * row of the segment table [seg_table] and check if the v_index
	 * field of the row is equal to the index
	 *
	 * */

	int i;
	for (i = 0; i < seg_table->size; i++) {
		// Enter your code here
		if (seg_table->table[i].v_index == index)
		  return seg_table->table[i].pages;
	}
	return NULL;
}

/* Translate virtual address to physical address. If [virtual_addr] is valid,
 * return 1 and write its physical counterpart to [physical_addr].
 * Otherwise, return 0 */
static int translate(
		addr_t virtual_addr, 	// Given virtual address
		addr_t * physical_addr, // Physical address to be returned
		struct pcb_t * proc) {  // Process uses given virtual address

	if (DEBUG) printf("translate() invoked\n");

	/* Offset of the virtual address */
	addr_t offset = get_offset(virtual_addr);
	/* The first layer index */
	addr_t first_lv = get_first_lv(virtual_addr);
	/* The second layer index */
	addr_t second_lv = get_second_lv(virtual_addr);
	
	if (DEBUG) printf("Got: seg v_index = %d, page v_index = %d\n", (int)first_lv, (int)second_lv);
	
	/* Search in the first level */
	struct page_table_t * page_table = NULL;
	page_table = get_page_table(first_lv, proc->seg_table);
	if (page_table == NULL) {
		return 0;
	}

	int i;
	for (i = 0; i < page_table->size; i++) {
		if (DEBUG) printf("Page %d out of %d, v_index: %d\n", i, page_table->size, (int)page_table->table[i].v_index);
		if (page_table->table[i].v_index == second_lv) {
			/* TODO: Concatenate the offset of the virtual addess
			 * to [p_index] field of page_table->table[i] to 
			 * produce the correct physical address and save it to
			 * [*physical_addr]  */
			*physical_addr = (page_table->table[i].p_index << OFFSET_LEN)
			                 + offset;
			return 1;
		}
	}
	return 0;	
}

addr_t alloc_mem(uint32_t size, struct pcb_t * proc) {
	if (DEBUG) printf("alloc_mem() invoked\n");
	pthread_mutex_lock(&mem_lock);
	addr_t ret_mem = 0;
	/* TODO: Allocate [size] byte in the memory for the
	 * process [proc] and save the address of the first
	 * byte in the allocated memory region to [ret_mem].
	 * */

	uint32_t num_pages = (size % PAGE_SIZE == 0) ? size / PAGE_SIZE :
	size / PAGE_SIZE + 1; // Number of pages we will use
	if (DEBUG) printf("Pages needed: %d\n", num_pages);
	int mem_avail = 0; // We could allocate new memory region or not?

	/* First we must check if the amount of free memory in
	 * virtual address space and physical address space is
	 * large enough to represent the amount of required 
	 * memory. If so, set 1 to [mem_avail].
	 * Hint: check [proc] bit in each page of _mem_stat
	 * to know whether this page has been used by a process.
	 * For virtual memory space, check bp (break pointer).
	 * */
	
	// iterate over frames, note the indices of free frames
	// while also counting
	
	uint32_t free_pages = 0;
	int free_page_index[num_pages];
	int j = 0;
	int i = 0;
	while (free_pages < num_pages && i < NUM_PAGES)
	{
		if (_mem_stat[i].proc == 0)
		{
			free_pages += 1;
			free_page_index[j] = i;
			if (DEBUG) printf("Found free frame at index %d\n", free_page_index[j]);
			j += 1;
		}
		i += 1;
	}
	if (free_pages == num_pages)
	{
		if ((1 << ADDRESS_SIZE) - proc->bp >= num_pages * PAGE_SIZE)
			mem_avail = 1;
	}
	
	if (mem_avail) {
		/* We could allocate new memory region to the process */
		ret_mem = proc->bp;
		//printf("bp: %d\n", (int)proc->bp);
		proc->bp += num_pages * PAGE_SIZE;
		/* Update status of physical pages which will be allocated
		 * to [proc] in _mem_stat. Tasks to do:
		 * 	- Update [proc], [index], and [next] field
		 * 	- Add entries to segment table page tables of [proc]
		 * 	  to ensure accesses to allocated memory slot is
		 * 	  valid. */
		 
		// physical
		// update index, next and proc in frames with saved indices
		for (j = 0; j < num_pages; j++)
		{
			int curr_frame_index = free_page_index[j];
			_mem_stat[curr_frame_index].index = j;
			_mem_stat[curr_frame_index].next = -1;
			_mem_stat[curr_frame_index].proc = proc->pid;
			if (j != num_pages - 1)
			{
				_mem_stat[curr_frame_index].next = free_page_index[j + 1];
			}
		}
		// virtual
		// infer 1st and 2nd lv index, use them to search for seg and page with matching
		// v_index
		// if there isn't any, alloc/assign to a new one at size - 1 for both tables
		addr_t old_bp = ret_mem;
		//printf("bp: %d\n", (int)ret_mem);
		for (j = 0; j < num_pages; j++)
		{
			addr_t first_lv = get_first_lv(old_bp);
			addr_t second_lv = get_second_lv(old_bp);
			if (DEBUG) printf("page: %d, %d, %d\n", (int)old_bp, (int)first_lv, (int)second_lv);
			struct seg_table_t* seg_table = proc->seg_table;
			struct page_table_t* page_table = get_page_table(first_lv, seg_table);
			
			if (page_table == NULL) // create a new segment
			{
				int seg_size = seg_table->size;
				seg_table->table[seg_size].v_index = first_lv;
				page_table = seg_table->table[seg_size].pages = malloc(sizeof(struct page_table_t));
				page_table->size = 0;
				seg_table->size++;
			}
			
			int page_size = page_table->size;
			page_table->table[page_size].v_index = second_lv;
			page_table->table[page_size].p_index = free_page_index[j];
			page_table->size++;
			
			old_bp += PAGE_SIZE;
		}
		
	}
	pthread_mutex_unlock(&mem_lock);
	dump();
	return ret_mem;
}

int free_mem(addr_t address, struct pcb_t * proc) {
	/*TODO: Release memory region allocated by [proc]. The first byte of
	 * this region is indicated by [address]. Task to do:
	 * 	- Set flag [proc] of physical page use by the memory block
	 * 	  back to zero to indicate that it is free.
	 * 	- Remove unused entries in segment table and page tables of
	 * 	  the process [proc].
	 * 	- Remember to use lock to protect the memory from other
	 * 	  processes.  */
	if (DEBUG) printf("free_mem() invoked\n");
	pthread_mutex_lock(&mem_lock);
	
	// swap return values? 
	addr_t p_addr;
	addr_t v_addr = address;
	if (translate(v_addr, &p_addr, proc) == 0)
	{
		return 1;
	}
	
	// physical
	int freed_pages = 0;
	int p_index = (p_addr >> OFFSET_LEN);
	while (p_index != -1)
	{
		//printf("%d", p_index);
		_mem_stat[p_index].proc = 0;
		p_index = _mem_stat[p_index].next;
		freed_pages += 1;
		//printf("%d", p_index);
	}
	if (DEBUG) printf("Physical done, freed %d pages\n", freed_pages);
	
	// virtual
	int future_bump = (v_addr + freed_pages * PAGE_SIZE != proc->bp)? 1 : 0;
	
	for (int i = 0; i < freed_pages; i++)
	{
		addr_t first_lv = get_first_lv(v_addr);
		addr_t second_lv = get_second_lv(v_addr);
		
		struct seg_table_t* seg_table = proc->seg_table;
		struct page_table_t* page_table = get_page_table(first_lv, seg_table);
		if (page_table != NULL)
		{
			for (int j = 0; i < page_table->size; j++)
			{
				if (page_table->table[j].v_index == second_lv)
				{
					//page_table->table[j].p_index = -1;
					//page_table->table[j].v_index = -1;
					if (!future_bump)
					{
						page_table->size--; //conflict with line 288, 295
					}
					break;
				}
			}
			v_addr += PAGE_SIZE;
		}
	}
	if (DEBUG) printf("Virtual done\n");
	
	if (proc->bp != v_addr) // not the last page, bump everything up
	{
		addr_t new_v_addr = address;
		addr_t old_v_addr = v_addr;
		int swapped_pages = 0;
		while (old_v_addr != proc->bp)
		{
			addr_t new_first_lv = get_first_lv(new_v_addr);
			addr_t new_second_lv = get_second_lv(new_v_addr);
			addr_t old_first_lv = get_first_lv(old_v_addr);
			addr_t old_second_lv = get_second_lv(old_v_addr);
			
			//printf("n2l: %d, o2l: %d\n", new_second_lv, old_second_lv);
			
			struct seg_table_t* seg_table = proc->seg_table;
			struct page_table_t* new_page_table = get_page_table(new_first_lv, seg_table);
			struct page_table_t* old_page_table = get_page_table(old_first_lv, seg_table);
			if (new_page_table != NULL && old_page_table != NULL)
			{
				int new_page_index;
				int old_page_index;
				for (new_page_index = 0; new_page_index < new_page_table->size; new_page_index++)
				{
					if (new_page_table->table[new_page_index].v_index == new_second_lv)
					{
						break;
					}
				}
				for (old_page_index = 0; old_page_index < old_page_table->size; old_page_index++)
				{
					if (old_page_table->table[old_page_index].v_index == old_second_lv)
					{
						break;
					}
				}
				//printf("nid: %d, oid: %d\n", new_page_index, old_page_index);
				new_page_table->table[new_page_index].p_index = old_page_table->table[old_page_index].p_index;
				new_page_table->table[new_page_index].v_index = new_second_lv;
				//old_page_table->table[old_page_index].p_index = -1;
				//old_page_table->table[old_page_index].v_index = -1;
				swapped_pages++;
			}

			for (int i = 0; i < 10; i++)
			{
				if (proc->regs[i] == old_v_addr)
				{
					proc->regs[i] = new_v_addr;
					if (DEBUG) printf("Updated register %d\n", i);
					//printf("New address: %d", new_v_addr);
					break;
				}
			}
				
			new_v_addr += PAGE_SIZE;
			old_v_addr += PAGE_SIZE;
		}
		if (DEBUG) printf("Bumping done\n");
		
		int tmp = freed_pages;
		
		while (freed_pages > 0)
		{
			int seg_size = proc->seg_table->size;
			struct seg_table_t* seg_table = proc->seg_table;
			struct page_table_t* page_table = get_page_table(seg_size - 1, seg_table);
			if (page_table != NULL)
			{
				page_table->size--;
				//printf("page size: %d\n", page_table->size);
				if (page_table->size == 0)
				{
					free(page_table);
					seg_table->size--;
				}
			}
			freed_pages--;
		}
		freed_pages = tmp;
		//printf("Removing empty pages done\n");
	}
	//printf("bp: %d\n", (int)proc->bp);
	proc->bp -= freed_pages * PAGE_SIZE;
	if (DEBUG) printf("after free_mem, bp: %d\n", (int)proc->bp);
	
	pthread_mutex_unlock(&mem_lock);
	
	dump();
	
	return 0;
}

int read_mem(addr_t address, struct pcb_t * proc, BYTE * data) {
	addr_t physical_addr;
	if (translate(address, &physical_addr, proc)) {
		*data = _ram[physical_addr];
		return 0;
	}else{
		return 1;
	}
}

int write_mem(addr_t address, struct pcb_t * proc, BYTE data) {
	if (DEBUG) printf("write_mem() invoked with args: %d, %d\n", (int)address, (int)data);
	addr_t physical_addr;
	if (translate(address, &physical_addr, proc)) {
		_ram[physical_addr] = data;
		return 0;
	}else{
		return 1;
	}
}

void dump(void) {
	int i;
	for (i = 0; i < NUM_PAGES; i++) {
		if (_mem_stat[i].proc != 0) {
			printf("%03d: ", i);
			printf("%05x-%05x - PID: %02d (idx %03d, nxt: %03d)\n",
				i << OFFSET_LEN,
				((i + 1) << OFFSET_LEN) - 1,
				_mem_stat[i].proc,
				_mem_stat[i].index,
				_mem_stat[i].next
			);
			int j;
			for (	j = i << OFFSET_LEN;
				j < ((i+1) << OFFSET_LEN) - 1;
				j++) {
				
				if (_ram[j] != 0) {
					printf("\t%05x: %02x\n", j, _ram[j]);
				}
					
			}
		}
	}
}

