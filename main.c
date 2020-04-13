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
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/miscdevice.h>
#include <linux/dma-mapping.h>
#include <asm/sbi.h>

#include "enclave.h"
#include "keystone.h"
#include "defines.h"

#define DRIVER_VERSION_CODE      100420
#define DRIVER_VERSION           MAKE_VERSION(0,1,0)
#define DRIVER_VERSION_STRING    "0.1.0"
#define DRIVER_DESCRIPTION       "Keystone enclave driver"
#define DRIVER_NAME              "keystone_enclave"
#define DRIVER_PERMISSION        0666

int keystone_open(struct inode *inode, struct file *filp);
int keystone_release(struct inode *inode, struct file *filp);
int keystone_mmap(struct file *filp, struct vm_area_struct *vma);
long keystone_unlocked_ioctl(struct file *filp, unsigned int cmd, 
                             unsigned long args);

struct file_operations keystone_fops = 
{
        .owner = THIS_MODULE,
        .mmap = keystone_mmap,
        .unlocked_ioctl = keystone_unlocked_ioctl,
        .open = keystone_open,
        .release = keystone_release,
};

struct miscdevice keystone_drv = 
{
        .minor = MISC_DYNAMIC_MINOR,
        .name = DRIVER_NAME,
        .fops = &keystone_fops,
        .mode = DRIVER_PERMISSION,
};

static int __init keystone_init(void)
{
        int err = 0;
        
        err = misc_register(&keystone_drv);
        if (err < 0) {
                printk(KERN_ERR "keystone_drv: misc_register() failed\r\n");
                return err;
        }
        
        keystone_drv.this_device->coherent_dma_mask = DMA_BIT_MASK(32);
        printk(KERN_INFO "keystone: " DRIVER_DESCRIPTION " v" DRIVER_VERSION_STRING "\r\n");
        
        return err;
}

static void __exit keystone_exit(void)
{
        misc_deregister(&keystone_drv);
        printk(KERN_INFO "keystone_drv: driver exit\r\n");
}

int keystone_mmap(struct file *filp, struct vm_area_struct *vma)
{
        int *ueid_ptr = 0;
        unsigned long vsize, psize;
        paddr_t paddr;
        struct Utm *utm = NULL;
        struct Epm *epm = NULL;
        struct Enclave *encl = NULL;
        
        ueid_ptr =  (int *) filp->private_data;
        
        encl = enclave_get_by_id(*ueid_ptr);
        if (encl == NULL) {
                return -EINVAL;
        }
        
        utm = encl->utm;
        epm = encl->epm;
        vsize = vma->vm_end - vma->vm_start;
        
        if (encl->is_init) {
                if (vsize > PAGE_SIZE) {
                        return -EINVAL;
                }
                
                paddr = __pa(epm->root_page_table) + (vma->vm_pgoff << PAGE_SHIFT);
                remap_pfn_range(vma, vma->vm_start, paddr >> PAGE_SHIFT, 
                                vsize, vma->vm_page_prot);
        } else {
                psize = utm->size;
                if (vsize > psize) {
                        return -EINVAL;
                }
                
                remap_pfn_range(vma, vma->vm_start, __pa(utm->ptr) >> PAGE_SHIFT,
                                vsize, vma->vm_page_prot);
        }
        
        return 0;
}

int keystone_open(struct inode *inode, struct file *filp)
{
        int *ueid_ptr = kmalloc(sizeof(int), GFP_KERNEL);
        if (ueid_ptr == NULL) {
                return -ENOMEM;
        }
        
        *ueid_ptr = 0;
        
        filp->private_data = ueid_ptr;
        
        return 0;
}

int keystone_release(struct inode *inode, struct file *filp)
{
        int retval = 0;
        int ueid = 0;
        struct Enclave *encl = NULL;
        
        if (filp->private_data == NULL) {
                return 0;
        }
        
        ueid = *((int *) filp->private_data);
        kfree(filp->private_data);
        
        encl = enclave_idr_remove(ueid);
        if (encl == NULL) {
                return 0;
        }
        
        if (encl->close_on_pexit) {
                retval = SBI_CALL_1(KEYSTONE_SBI_DESTROY_ENCLAVE, encl->eid);
                if (retval != 0) {
                        printk(KERN_ERR "keystone_drv: cannot destroy enclave\r\n");
                        return retval;
                }
                
                enclave_free(encl);
        }
        
        return 0;
}

module_init(keystone_init);
module_exit(keystone_exit);

MODULE_VERSION(DRIVER_VERSION_STRING);
MODULE_DESCRIPTION(DRIVER_DESCRIPTION);
MODULE_AUTHOR("Khang Hua <khanghua1505@gmail.com>");
MODULE_LICENSE("Dual BSD/GPL");
                
