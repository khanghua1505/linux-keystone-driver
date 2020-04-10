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

#ifndef _KEYSTONE_H_
#define _KEYSTONE_H_

#include <linux/types.h>
#include <linux/ioctl.h>

#include "enclave.h"

#define KEYSTONE_SBI_CREATE_ENCLAVE     (101)
#define KEYSTONE_SBI_DESTROY_ENCLAVE    (102)
#define KEYSTONE_SBI_RUN_ENCLAVE        (105)
#define KEYSTONE_SBI_STOP_ENCLAVE       (106)
#define KEYSTONE_SBI_RESUME_ENCLAVE     (107)

#define KEYSTONE_IOC_MAGIC      (0xa4)
#define KEYSTONE_IOC_CREATE_ENCLAVE \
    _IOR(KEYSTONE_IOC_MAGIC, 0x00, struct keystone_ioctl_create_enclave_args)
#define KEYSTONE_IOC_DESTROY_ENCLAVE \
    _IOW(KEYSTONE_IOC_MAGIC, 0x01, struct keystone_ioctl_create_enclave_args)
#define KEYSTONE_IOC_RUN_ENCLAVE \
    _IOR(KEYSTONE_IOC_MAGIC, 0x04, struct keystone_ioctl_run_enclave_args)
#define KEYSTONE_IOC_RESUME_ENCLAVE \
    _IOR(KEYSTONE_IOC_MAGIC, 0x05, struct keystone_ioctl_run_enclave_args)
#define KEYSTONE_IOC_FINALIZE_ENCLAVE \
    _IOR(KEYSTONE_IOC_MAGIC, 0x06, struct keystone_ioctl_create_enclave_args)
#define KEYSTONE_IOC_UTM_INIT \
    _IOR(KEYSTONE_IOC_MAGIC, 0x07, struct keystone_ioctl_create_enclave_args)

struct runtime_params
{
        __u64 runtime_entry;
        __u64 user_entry;
        __u64 untrusted_ptr;
        __u64 untrusted_size;
};

struct keystone_ioctl_create_enclave_args
{
        __u64 eid;              /* Enclave id. */
        __u64 min_pages;        /* Min pages required. */
        __u64 runtime_vaddr;    /* Runtime virtual memory. */
        __u64 user_vaddr;       /* User virtual memory. */
        __u64 pt_ptr;
        __u64 utm_free_ptr;
        
        /* Use for hash */
        __u64 epm_paddr;
        __u64 utm_paddr;
        __u64 runtime_paddr;
        __u64 user_paddr;
        __u64 free_paddr;
        __u64 epm_size;
        __u64 utm_size;
        
        /* Runtim parameters */
        struct runtime_params params;
};

struct keystone_ioctl_run_enclave_args
{
        __u64 eid;
        __u64 entry;
        __u64 args_ptr;
        __u64 args_size;
        __u64 ret;
};

struct keystone_sbi_pregion
{
        paddr_t paddr;
        size_t size;
};

struct keystone_sbi_create_enclave_args
{
        struct keystone_sbi_pregion epm_region;
        struct keystone_sbi_pregion utm_region;
        
        paddr_t runtime_paddr;
        paddr_t user_paddr;
        paddr_t free_paddr;
        
        struct runtime_params params;
        
        __u64 *eid_pptr;
};

#endif  // _KEYSTONE_H_
