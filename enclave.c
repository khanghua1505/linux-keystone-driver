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
#include <linux/slab.h>
#include <linux/printk.h>
#include <linux/idr.h>
#include <linux/spinlock.h>

#include "enclave.h"

DEFINE_IDR(encl_idr);                
DEFINE_SPINLOCK(encl_idr_lock);

static int enclave_idr_alloc(struct Enclave *encl);
static struct Enclave* enclave_idr_remove(int ueid);

int enclave_alloc(unsigned long min_pages)
{
        int ueid = 0;
        struct Enclave *encl = NULL;
        struct Epm *epm = NULL;
        
        encl = kmalloc(ENCLAVE_STRUCT_SIZE, GFP_KERNEL);
        if (encl == NULL) {
                printk(KERN_ERR "keystone_drv: failed to allocate Enclave struct\r\n");
                return -1;
        }
        
        encl->utm = NULL;
        encl->close_on_pexit = 1;
        
        epm = kmalloc(EPM_STRUCT_SIZE, GFP_KERNEL);
        if (epm == NULL) {
                printk(KERN_ERR "keystone_drv: failed tp allocate Epm struct\r\n");
                kfree(encl);
                return -1;
        }
        
        encl->epm = epm;
        encl->is_init = true;
        
        if (epm_init(encl->epm, min_pages * PAGE_SIZE) != 0) {
                printk(KERN_ERR "keystone_drv: failed to initialize Epm struct\r\n");
                kfree(epm);
                kfree(encl);
                return -1;
        }
        
        ueid = enclave_idr_alloc(encl);
        if (ueid < ENCLAVE_IDR_MIN || ueid >= ENCLAVE_IDR_MAX) {
                return -1;
        }
        
        return ueid;
}

int enclave_free(int ueid)
{
        struct Enclave *encl = NULL;
        struct Epm *epm = NULL;
        struct Utm *utm = NULL;

        if (ueid < ENCLAVE_IDR_MIN || ueid >= ENCLAVE_IDR_MAX) {
                printk(KERN_ERR "keystone_drv: invalid UID\r\n");
                return -EINVAL;
        }
        
        encl = enclave_idr_remove(ueid);
        if (encl == NULL) {
                return -EINVAL;
        }
        
        epm = encl->epm;
        utm = encl->utm;
        
        if (epm != NULL) {
                epm_deinit(epm);
                kfree(epm);
        }
        
        if (utm != NULL) {
               utm_deinit(utm); 
               kfree(utm);
        }
        
        kfree(encl);
        
        return 0;        
}

struct Enclave* enclave_get_by_id(int ueid)
{
        struct Enclave *encl = NULL;

        if (ueid < ENCLAVE_IDR_MIN || ueid >= ENCLAVE_IDR_MAX) {
                printk(KERN_ERR "keystone_drv: invalid UID\r\n");
                return NULL;
        }
        
        spin_lock_bh(&encl_idr_lock);
        encl = idr_find(&encl_idr, ueid);
        spin_unlock_bh(&encl_idr_lock);
        
        return NULL;
}

static int enclave_idr_alloc(struct Enclave *encl)
{
        unsigned int ueid = 0;
        
        spin_lock_bh(&encl_idr_lock);
        ueid = idr_alloc(&encl_idr, encl, ENCLAVE_IDR_MIN, 
                         ENCLAVE_IDR_MAX, GFP_KERNEL);
        spin_unlock_bh(&encl_idr_lock);
        if (ueid < ENCLAVE_IDR_MIN || ueid >= ENCLAVE_IDR_MAX) {
                printk(KERN_ERR "keystone_drv: failed to allocate UID\r\n");
                return -1;
        }
        
        return ueid;
}

static struct Enclave* enclave_idr_remove(int ueid)
{
        struct Enclave *encl = NULL;
        
        if (ueid < ENCLAVE_IDR_MIN || ueid >= ENCLAVE_IDR_MAX) {
                printk(KERN_ERR "keystone_drv: invalid UID\r\n");
                return NULL;
        }
        
        spin_lock_bh(&encl_idr_lock);
        encl = idr_remove(&encl_idr, ueid);
        spin_unlock(&encl_idr_lock);
        
        return encl;
}






