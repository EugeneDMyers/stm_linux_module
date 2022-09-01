PWD=$(shell pwd)
VER=$(shell uname -r)
KERNEL_BUILD=/lib/modules/$(VER)/build
# Later if you want to package the module binary you can provide an INSTALL_ROOT
# INSTALL_ROOT=/tmp/install-root

obj-m+=dual_monitor_mode.o

KVERSION=$(shell uname -r)

all:
	make -C /lib/modules/$(KVERSION)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(KVERSION)/build M=$(PWD) clean

install:
	$(MAKE) -C $(KERNEL_BUILD) M=$(PWD) \
		INSTALL_MOD_PATH=$(INSTALL_ROOT) modules_install
