/* Copyright (c) 2017-2018, The Regents of the University of California (Regents).
 * All Rights Reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the Regents nor the
 *    names of its contributors may be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * IN NO EVENT SHALL REGENTS BE LIABLE TO ANY PARTY FOR DIRECT, INDIRECT,
 * SPECIAL, INCIDENTAL, OR CONSEQUENTIAL DAMAGES, INCLUDING LOST PROFITS, ARISING
 * OUT OF THE USE OF THIS SOFTWARE AND ITS DOCUMENTATION, EVEN IF REGENTS HAS
 * BEEN ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * REGENTS SPECIFICALLY DISCLAIMS ANY WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE. THE SOFTWARE AND ACCOMPANYING DOCUMENTATION, IF ANY, PROVIDED
 * HEREUNDER IS PROVIDED "AS IS". REGENTS HAS NO OBLIGATION TO PROVIDE
 * MAINTENANCE, SUPPORT, UPDATES, ENHANCEMENTS, OR MODIFICATIONS.
 */ 

#include <linux/types.h>
#include <linux/printk.h>
#include <linux/slab.h>
#include <asm/page.h>

#include "epm.h"

int epm_init(struct Epm *epm, size_t size)
{
        vaddr_t epm_vaddr = 0;
        unsigned long required_pages = 0;
        unsigned long page_order = 0;
        unsigned long count = 0;
        
        required_pages = PAGE_UP(size)/PAGE_SIZE;
        page_order = ilog2(required_pages - 1) + 1;
        count = (0x1) << page_order;
        
        if (page_order > MAX_ORDER) {
                return -EINVAL;
        }
        
        epm_vaddr = (vaddr_t) __get_free_pages(GFP_HIGHUSER, page_order);
        
        if (!epm_vaddr) {
                printk(KERN_ERR "keystone_drv: failed to allocate %lu pages\r\n", required_pages);
                return -ENOMEM;
        }
        
        memset((void *)epm_vaddr, 0, PAGE_SIZE * required_pages);
        
        epm->root_page_table = (void *) epm_vaddr;
        epm->ptr = epm_vaddr;
        epm->pa = __pa(epm_vaddr);
        epm->order = page_order;
        epm->size = count * PAGE_SIZE;
        
        return 0;
}

void epm_deinit(struct Epm *epm)
{
        if (!epm->ptr || !epm->size) {
                return;
        }
        
        free_pages(epm->ptr, epm->order);
}
        
        
        
                

