OVERLAY_DIR=../buildroot_overlay
DRIVER = keystone-driver.ko

ifneq ($(KERNELRELEASE),)
	keystone-driver-y := \
		enclave.o \
		epm.o \
		main.o \
		utm.o \
		unlocked_ioctl.o
	obj-m += keystone-driver.o
else

PWD := $(shell pwd)
KDIR := $(PWD)/../linux

default:
	$(MAKE) -C $(KDIR) ARCH=riscv SUBDIRS=$(PWD) modules

copy:
	cp $(DRIVER) $(OVERLAY_DIR)
endif

clean:
	rm -rvf *.o *.ko *.order *.symvers *.mod.c .tmp_versions .*o.cmd
