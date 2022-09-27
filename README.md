# stm_linux_module
Linux STM support

First cut on Linux support for the STM.

This module takes the steps to start and stop the STM.  It also handles cases where the platform goes into hybernation and suspend and shutdown.

Has been tested on Purism Librem 14 (5.10.120) and Purism Server (4.19.0)

KVM needs to be patched to make this module work - KVM manages the VMX or virtual machine mode of the processor in Linux. It brings the processors into VMX only when a virtual machine is created and when all virtual machines are dealocated, KVM will then take the processor out of VMX mode.  These patches ensure that KVM does not take the processor out of VMX while the STM is active.

VMX mode is required for the STM to function. The DMM module creates a VM via KVM and bumps a KVM counter (kvm_usage_count) to ensure that KVM does not take the procesor out of VMX.  Otherwise, if the processor if brought out of VMX when the STM is active a GP fault will occur, causing the kernel to panic.

linux_stm_patches.patch will patch Linux v5.10.120, other versions may require some alteration of the patches.

installation:

(1) Patch KVM. Since KVM has to be patched the Linux kernel will need to be rebuilt.

(2) in stm_linux_module:

make
sudo make install
sudo modprobe dual_monitor_mode

assumes:

(1) firmware with STM.  For example coreboot configured with STM support
(2) Linux development systme:
	(a) install linux header files for the linux version - see "The Linux Kernel Module Programmin Guide" sections 1.4 through 1.7 for more information. on how to build Linux kernel modules.

