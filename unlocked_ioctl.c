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
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <asm/sbi.h>

#include "keystone.h"

static int ioctl_create_enclave(struct file *filp, unsigned long args)
{
        struct keystone_ioctl_create_enclave_args *encl_args = NULL;
        int encl_id = 0;
        struct Enclave *encl = NULL;
        
        encl_args = (struct keystone_ioctl_create_enclave_args *) args;
        encl_id = enclave_alloc(encl_args->min_pages);
        if (encl_id < 0) {
                return -ENOMEM;
        }

        encl = enclave_get_by_id(encl_id);
        
        encl_args->pt_ptr = __pa(encl->epm->root_page_table);
        encl_args->epm_size = encl->epm->size;
        encl_args->eid = encl_id;
        
        filp->private_data = (void *) &encl->eid;
        
        return 0;
}

static int ioctl_finalize_enclave(struct file *filp, unsigned long args)
{
        int retval = 0;
        struct Enclave *encl = NULL;
        struct keystone_ioctl_create_enclave_args *ioctl_args = NULL;
        struct keystone_sbi_create_enclave_args sbi_args;
        
        ioctl_args = (struct keystone_ioctl_create_enclave_args *) args;
        
        encl = enclave_get_by_id(ioctl_args->eid);
        if (encl == NULL) {
                printk(KERN_ERR "keystone_drv: invalid enclave id\r\n");
                return -EINVAL;
        }
        
        encl->is_init = false;
        
        sbi_args.epm_region.paddr = encl->epm->pa;
        sbi_args.epm_region.size = encl->epm->size;
        
        if (encl->utm) {
                sbi_args.utm_region.paddr = __pa(encl->utm->ptr);
                sbi_args.utm_region.size = encl->utm->size;
        } else {
                sbi_args.utm_region.paddr = 0;
                sbi_args.utm_region.size = 0;
        }
        
        sbi_args.runtime_paddr = ioctl_args->runtime_paddr;
        sbi_args.user_paddr = ioctl_args->user_paddr;
        sbi_args.free_paddr = ioctl_args->free_paddr;
        sbi_args.params = ioctl_args->params;
        sbi_args.eid_pptr = (__u64 *) __pa(&encl->eid);
        
        retval = SBI_CALL_1(KEYSTONE_SBI_CREATE_ENCLAVE, __pa(&sbi_args));
        if (retval != 0) {
                printk(KERN_ERR "keystone_drv SBI call failed\r\n");
                enclave_free(ioctl_args->eid);
                return -ENOSYS;
        }
        
        return retval;
}

static int ioctl_run_enclave(struct file *filp, unsigned long args)
{
        int retval = 0;
        int ueid = 0;
        struct Enclave *encl = NULL;
        struct keystone_ioctl_run_enclave_args *ioctl_args = NULL;
        
        ioctl_args = (struct keystone_ioctl_run_enclave_args *) args;
        
        ueid = ioctl_args->eid;
        encl = enclave_get_by_id(ueid);
        if (encl == NULL) {
                printk(KERN_ERR "Invalid enclave id\r\n");
                return -EINVAL;
        }
        
        retval = SBI_CALL_1(KEYSTONE_SBI_RUN_ENCLAVE, encl->eid);
        if (retval != 0) {
                printk(KERN_ERR "keystone_drv SBI call failed\r\n");
                return -ENOSYS;
        }
        
        return retval;
}

static int ioctl_utm_init(struct file *filp, unsigned long args)
{
        int retval = 0;
        struct Enclave *encl = NULL;
        struct Utm *utm = NULL;
        size_t untrusted_size = 0;
        struct keystone_ioctl_create_enclave_args *ioctl_args = NULL;
        
        ioctl_args = (struct keystone_ioctl_create_enclave_args *) args;
        
        untrusted_size = ioctl_args->params.untrusted_size;
        
        encl = enclave_get_by_id(ioctl_args->eid);
        if (encl == NULL) {
                printk(KERN_ERR "Invalid enclave id\r\n");
                return -EINVAL;
        }
        
        utm = kmalloc(UTM_STRUCT_SIZE, GFP_KERNEL);
        if (utm == NULL) {
                return -ENOMEM;
        }
        
        retval = utm_init(utm, untrusted_size);
        if (retval != 0) {
                return -ENOSYS;
        }
        
        encl->utm = utm;
        ioctl_args->utm_free_ptr = __pa(utm->ptr);

        return retval;
}

static int ioctl_destroy_enclave(struct file *filp, unsigned long args)
{
        int retval = 0;
        int ueid = 0;
        struct Enclave *encl = NULL;
        struct keystone_ioctl_create_enclave_args *ioctl_args = NULL;
        
        ioctl_args = (struct keystone_ioctl_create_enclave_args *) args;
        
        ueid = ioctl_args->eid;
        
        encl = enclave_get_by_id(ueid);
        if (encl == NULL) {
                printk(KERN_ERR "Invalid enclave id\r\n");
                return -EINVAL;
        }
        
        retval = SBI_CALL_1(KEYSTONE_SBI_DESTROY_ENCLAVE, encl->eid);
        if (retval != 0) {
                printk(KERN_ERR "keystone_drv: cannot destroy enclave\r\n");
                return retval;
        }
        
        enclave_free(encl->eid);
        
        return 0;
}

static int ioctl_resume_enclave(struct file *filp, unsigned long args)
{
        int retval = 0;
        int ueid = 0;
        struct Enclave *encl = NULL;
        struct keystone_ioctl_run_enclave_args *ioctl_args = NULL;
        
        ioctl_args = (struct keystone_ioctl_run_enclave_args *) args;
        
        ueid = ioctl_args->eid;
        
        encl = enclave_get_by_id(ueid);
        if (encl == NULL)  {
                printk(KERN_ERR "Invalid enclave id\r\n");
                return -EINVAL;
        }
        
        retval = SBI_CALL_1(KEYSTONE_SBI_RESUME_ENCLAVE, encl->eid);
        if (retval != 0) {
                printk(KERN_ERR "keystone_drv: cannot destroy enclave\r\n");
                return retval;
        }
        
        return retval;
}

long keystone_unlocked_ioctl(struct file *filp, unsigned int cmd, 
                             unsigned long args)
{
        int retval = 0;
        size_t args_size = 0;
        __u8 *buffer = NULL;
        
        if (!args) {
                return -EINVAL;
        }
        
        args_size = _IOC_SIZE(cmd);
        
        buffer = (__u8 *) kmalloc(args_size, GFP_KERNEL);
        if (buffer == NULL) {
                return -ENOMEM;
        }
        
        retval = copy_from_user(buffer, (void __user *)args, args_size);
        if (retval != 0) {
                return -EFAULT;
        }
        
        switch (cmd) {
        case KEYSTONE_IOC_CREATE_ENCLAVE:
                ioctl_create_enclave(filp, (unsigned long) buffer);
                break;
        case KEYSTONE_IOC_FINALIZE_ENCLAVE:
                ioctl_finalize_enclave(filp, (unsigned long) buffer);
                break;
        case KEYSTONE_IOC_DESTROY_ENCLAVE:
                ioctl_destroy_enclave(filp, (unsigned long) buffer);
                break;
        case KEYSTONE_IOC_RUN_ENCLAVE:
                ioctl_run_enclave(filp, (unsigned long) buffer);
                break;
        case KEYSTONE_IOC_RESUME_ENCLAVE:
                ioctl_resume_enclave(filp, (unsigned long) buffer);
                break;
        case KEYSTONE_IOC_UTM_INIT:
                ioctl_utm_init(filp, (unsigned long) buffer);
                break;
        default:
                return -ENOSYS;
        }
        
        retval = copy_to_user((void __user *)args, buffer, args_size);
        if (retval != 0) {
                return -EFAULT;
        }
        
        return retval;
}
