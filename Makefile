# SPDX-License-Identifier: GPL-2.0
# mpt3sas makefile
# obj-$(CONFIG_SCSI_MPT3SAS) += mpt3sas.o
# mpt3sas-y +=  mpt3sas_base.o     \
# 		mpt3sas_config.o \
# 		mpt3sas_scsih.o      \
# 		mpt3sas_transport.o     \
# 		mpt3sas_ctl.o	\
# 		mpt3sas_trigger_diag.o \
# 		mpt3sas_warpdrive.o \
# 		mpt3sas_debugfs.o \

ifneq  ($(KERNELRELEASE),)
	obj-m += leapsas.o
	leapsas-objs := mpt3sas_base.o   \
		mpt3sas_config.o \
		mpt3sas_scsih.o      \
		mpt3sas_transport.o
else
	KERNEL_DIR = /lib/modules/$(shell uname -r)/build
endif

all:
	$(MAKE) -C $(KERNEL_DIR) M=$(PWD) modules

init:
#	ensure remove original driver
	systemctl stop tgt
	sudo rmmod mpt3sas 

install:
	sudo insmod leapsas.ko

uninstall:
	sudo rmmod leapsas

ddtest:
	sudo dd if=/dev/sda of=/dev/sda bs=1M count=1024
	
.PHONY:clean
clean:
	$(MAKE) -C $(KERNEL_DIR) M=$(PWD) clean