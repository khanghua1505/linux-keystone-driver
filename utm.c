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
#include <linux/kernel.h>
#include <linux/slab.h>
#include <asm/page.h>

#include "utm.h"

int utm_init(struct Utm *utm, size_t size)
{
        unsigned long required_pages = 0;
        unsigned long page_order = 0;
        unsigned long count = 0;
        
        required_pages = PAGE_UP(size)/PAGE_SIZE;
        page_order = ilog2(required_pages - 1) + 1;
        count = (0x1) << page_order;
        
        utm->order = page_order;
        
        //! Note: Currently, UTM does not utilize CMA.
        utm->ptr = (vaddr_t) __get_free_pages(GFP_HIGHUSER, page_order);
        if (utm->ptr == (vaddr_t) NULL) {
                return -ENOMEM;
        }
        
        utm->size = count * PAGE_SIZE;
        if (utm->size != size) {
                printk(KERN_WARNING "keystone_drv: shared buffer size \
                        is not multiple of PAGE_SIZE\r\n");
        }
         
        return 0;
        
}

int utm_deinit(struct Utm *utm)
{
        if (utm->ptr != (vaddr_t) NULL) {
                free_pages((vaddr_t) utm->ptr, utm->order);
                utm->root_page_table = NULL;
                utm->ptr = (vaddr_t) NULL;
                utm->size = 0;
                utm->order = 0;
        }
        
        return 0;
}


