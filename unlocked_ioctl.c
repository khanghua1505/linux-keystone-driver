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

int ioctl_create_enclave(struct file *filp, unsigned long args)
{
        int *ueid_ptr = NULL;
        struct Enclave *encl = NULL;
        struct keystone_ioctl_create_enclave_args  \
                *ioctl_create_encl_args = NULL;
                
        ueid_ptr = (int *) filp->private_data;
        
        ioctl_create_encl_args =  \
                (struct keystone_ioctl_create_enclave_args *) args;
        
        encl = enclave_create(ioctl_create_encl_args->min_pages);
        if (encl == NULL) {
                return -ENOMEM;
        }

        ioctl_create_encl_args->pt_ptr = __pa(encl->epm->root_page_table);
        ioctl_create_encl_args->epm_size = encl->epm->size;
        ioctl_create_encl_args->ueid = enclave_idr_alloc(encl); 
               
        *ueid_ptr = ioctl_create_encl_args->ueid;
        
        return 0;
}

int ioctl_finalize_enclave(struct file *filp, unsigned long args)
{
        int retval = 0;
        struct Enclave *encl = NULL;
        struct keystone_sbi_create_enclave_args sbi_create_encl_args;
        struct keystone_ioctl_create_enclave_args *ioctl_create_encl_args = NULL;
        
        ioctl_create_encl_args = \
                (struct keystone_ioctl_create_enclave_args *) args;
        
        encl = enclave_get_by_id(ioctl_create_encl_args->ueid);
        if (encl == NULL) {
                printk(KERN_ERR "keystone: invalid enclave id\r\n");
                return -EINVAL;
        }
        
        encl->is_init = false;
        
        sbi_create_encl_args.epm_region.paddr = encl->epm->pa;
        sbi_create_encl_args.epm_region.size = encl->epm->size;
        
        if (encl->utm) {
                sbi_create_encl_args.utm_region.paddr = __pa(encl->utm->ptr);
                sbi_create_encl_args.utm_region.size = encl->utm->size;
        } else {
                sbi_create_encl_args.utm_region.paddr = 0;
                sbi_create_encl_args.utm_region.size = 0;
        }
        
        sbi_create_encl_args.runtime_paddr = ioctl_create_encl_args->runtime_paddr;
        sbi_create_encl_args.user_paddr = ioctl_create_encl_args->user_paddr;
        sbi_create_encl_args.free_paddr = ioctl_create_encl_args->free_paddr;
        sbi_create_encl_args.params = ioctl_create_encl_args->params;
        
        sbi_create_encl_args.eid_pptr = (uint64_t *) __pa(&encl->eid);
        
        retval = SBI_CALL_1(KEYSTONE_SBI_CREATE_ENCLAVE, __pa(&sbi_create_encl_args));
        if (retval != 0) {
                printk(KERN_ERR "keystone_drv: create enclave sbi call failed\r\n");
                enclave_free(encl);
                return retval;
        }
        
        return retval;
}

int ioctl_run_enclave(struct file *filp, unsigned long args)
{
        int retval = 0;
        struct Enclave *encl = NULL;
        struct keystone_ioctl_run_enclave_args *ioctl_run_encl_args = NULL;
        
        ioctl_run_encl_args =  \
                (struct keystone_ioctl_run_enclave_args *) args;
        
        encl = enclave_get_by_id(ioctl_run_encl_args->ueid);
        if (encl == NULL) {
                return -EINVAL;
        }
        
        retval = SBI_CALL_1(KEYSTONE_SBI_RUN_ENCLAVE, encl->eid);

        return retval;
}

int ioctl_utm_init(struct file *filp, unsigned long args)
{
        int retval = 0;
        size_t untrusted_size = 0;
        struct Enclave *encl = NULL;
        struct Utm *utm = NULL;
        struct keystone_ioctl_create_enclave_args *ioctl_create_encl_args = NULL;
        
        ioctl_create_encl_args =  \
                (struct keystone_ioctl_create_enclave_args *) args;
                
        untrusted_size = ioctl_create_encl_args->params.untrusted_size;
        
        encl = enclave_get_by_id(ioctl_create_encl_args->ueid);
        if (encl == NULL) {
                return -EINVAL;
        }
        
        utm = (struct Utm *) kmalloc(UTM_STRUCT_SIZE, GFP_KERNEL);
        if (utm == NULL) {
                return -ENOMEM;
        }
        
        retval = utm_init(utm, untrusted_size);
        if (retval != 0) {
                return retval;
        }
        
        encl->utm = utm;
        ioctl_create_encl_args->utm_free_ptr = __pa(utm->ptr);

        return retval;
}

int ioctl_destroy_enclave(struct file *filp, unsigned long args)
{
        int retval = 0;
        uint64_t eid = 0;
        struct Enclave *encl = NULL;
        struct keystone_ioctl_create_enclave_args *ioctl_create_encl_args = NULL;
        
        ioctl_create_encl_args =  \
                (struct keystone_ioctl_create_enclave_args *) args;
        
        encl = enclave_idr_remove(ioctl_create_encl_args->ueid);
        if (encl == NULL) {
                return -EINVAL;
        }
        
        retval = SBI_CALL_1(KEYSTONE_SBI_DESTROY_ENCLAVE, eid);
        if (retval != 0) {
                return retval;
        }
        
        eid = encl->eid;
        enclave_free(encl);
        
        return retval;
}

int ioctl_resume_enclave(struct file *filp, unsigned long args)
{
        int retval = 0;
        struct Enclave *encl = NULL;
        struct keystone_ioctl_run_enclave_args *ioctl_run_encl_args = NULL;
        
        ioctl_run_encl_args = (struct keystone_ioctl_run_enclave_args *) args;
        
        encl = enclave_get_by_id(ioctl_run_encl_args->ueid);
        if (encl == NULL)  {
                return -EINVAL;
        }
        
        retval = SBI_CALL_1(KEYSTONE_SBI_RESUME_ENCLAVE, encl->eid);
        
        return retval;
}

long keystone_unlocked_ioctl(struct file *filp, unsigned int cmd, 
                             unsigned long args)
{
        int retval = 0;
        size_t args_size = 0;
        uint8_t buffer[512];
        
        if (!args) {
                return -EINVAL;
        }
        
        args_size = _IOC_SIZE(cmd);
        args_size = args_size > sizeof(buffer) ? sizeof(buffer) : args_size;
        
        retval = copy_from_user(buffer, (void __user *)args, args_size);
        if (retval != 0) {
                return -EFAULT;
        }
        
        switch (cmd) {
        case KEYSTONE_IOC_CREATE_ENCLAVE:
                retval = ioctl_create_enclave(filp, (unsigned long) buffer);
                break;
        case KEYSTONE_IOC_FINALIZE_ENCLAVE:
                retval = ioctl_finalize_enclave(filp, (unsigned long) buffer);
                break;
        case KEYSTONE_IOC_DESTROY_ENCLAVE:
                retval = ioctl_destroy_enclave(filp, (unsigned long) buffer);
                break;
        case KEYSTONE_IOC_RUN_ENCLAVE:
                retval = ioctl_run_enclave(filp, (unsigned long) buffer);
                break;
        case KEYSTONE_IOC_RESUME_ENCLAVE:
                retval = ioctl_resume_enclave(filp, (unsigned long) buffer);
                break;
        case KEYSTONE_IOC_UTM_INIT:
                retval = ioctl_utm_init(filp, (unsigned long) buffer);
                break;
        default:
                return -ENOSYS;
        }
        
        if (copy_to_user((void __user *)args, buffer, args_size) != 0) {
                printk(KERN_DEBUG "copy to user failed\r\n");
                return -EFAULT;
        }
        
        return retval;
}
