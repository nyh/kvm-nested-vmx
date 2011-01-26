/*
 * Kernel-based Virtual Machine driver for Linux
 *
 * This module enables machines with Intel VT-x extensions to run virtual
 * machines without emulation or binary translation.
 *
 * Copyright (C) 2006 Qumranet, Inc.
 * Copyright 2010 Red Hat, Inc. and/or its affiliates.
 *
 * Authors:
 *   Avi Kivity   <avi@qumranet.com>
 *   Yaniv Kamay  <yaniv@qumranet.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 *
 */

#include "irq.h"
#include "mmu.h"

#include <linux/kvm_host.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/highmem.h>
#include <linux/sched.h>
#include <linux/moduleparam.h>
#include <linux/ftrace_event.h>
#include <linux/slab.h>
#include <linux/tboot.h>
#include "kvm_cache_regs.h"
#include "x86.h"

#include <asm/io.h>
#include <asm/desc.h>
#include <asm/vmx.h>
#include <asm/virtext.h>
#include <asm/mce.h>
#include <asm/i387.h>
#include <asm/xcr.h>

#include "trace.h"

#define __ex(x) __kvm_handle_fault_on_reboot(x)

MODULE_AUTHOR("Qumranet");
MODULE_LICENSE("GPL");

static int __read_mostly bypass_guest_pf = 1;
module_param(bypass_guest_pf, bool, S_IRUGO);

static int __read_mostly enable_vpid = 1;
module_param_named(vpid, enable_vpid, bool, 0444);

static int __read_mostly flexpriority_enabled = 1;
module_param_named(flexpriority, flexpriority_enabled, bool, S_IRUGO);

static int __read_mostly enable_ept = 1;
module_param_named(ept, enable_ept, bool, S_IRUGO);

static int __read_mostly enable_unrestricted_guest = 1;
module_param_named(unrestricted_guest,
			enable_unrestricted_guest, bool, S_IRUGO);

static int __read_mostly emulate_invalid_guest_state = 0;
module_param(emulate_invalid_guest_state, bool, S_IRUGO);

static int __read_mostly vmm_exclusive = 1;
module_param(vmm_exclusive, bool, S_IRUGO);

static int __read_mostly yield_on_hlt = 1;
module_param(yield_on_hlt, bool, S_IRUGO);

/*
 * If nested=1, nested virtualization is supported, i.e., a guest may use
 * VMX and be a hypervisor for its own guests. If nested=0, a guest may not
 * use VMX instructions.
 */
static int __read_mostly nested = 0;
module_param(nested, bool, S_IRUGO);

#define KVM_GUEST_CR0_MASK_UNRESTRICTED_GUEST				\
	(X86_CR0_WP | X86_CR0_NE | X86_CR0_NW | X86_CR0_CD)
#define KVM_GUEST_CR0_MASK						\
	(KVM_GUEST_CR0_MASK_UNRESTRICTED_GUEST | X86_CR0_PG | X86_CR0_PE)
#define KVM_VM_CR0_ALWAYS_ON_UNRESTRICTED_GUEST				\
	(X86_CR0_WP | X86_CR0_NE)
#define KVM_VM_CR0_ALWAYS_ON						\
	(KVM_VM_CR0_ALWAYS_ON_UNRESTRICTED_GUEST | X86_CR0_PG | X86_CR0_PE)
#define KVM_CR4_GUEST_OWNED_BITS				      \
	(X86_CR4_PVI | X86_CR4_DE | X86_CR4_PCE | X86_CR4_OSFXSR      \
	 | X86_CR4_OSXMMEXCPT)

#define KVM_PMODE_VM_CR4_ALWAYS_ON (X86_CR4_PAE | X86_CR4_VMXE)
#define KVM_RMODE_VM_CR4_ALWAYS_ON (X86_CR4_VME | X86_CR4_PAE | X86_CR4_VMXE)

#define RMODE_GUEST_OWNED_EFLAGS_BITS (~(X86_EFLAGS_IOPL | X86_EFLAGS_VM))

/*
 * These 2 parameters are used to config the controls for Pause-Loop Exiting:
 * ple_gap:    upper bound on the amount of time between two successive
 *             executions of PAUSE in a loop. Also indicate if ple enabled.
 *             According to test, this time is usually smaller than 128 cycles.
 * ple_window: upper bound on the amount of time a guest is allowed to execute
 *             in a PAUSE loop. Tests indicate that most spinlocks are held for
 *             less than 2^12 cycles
 * Time is measured based on a counter that runs at the same rate as the TSC,
 * refer SDM volume 3b section 21.6.13 & 22.1.3.
 */
#define KVM_VMX_DEFAULT_PLE_GAP    128
#define KVM_VMX_DEFAULT_PLE_WINDOW 4096
static int ple_gap = KVM_VMX_DEFAULT_PLE_GAP;
module_param(ple_gap, int, S_IRUGO);

static int ple_window = KVM_VMX_DEFAULT_PLE_WINDOW;
module_param(ple_window, int, S_IRUGO);

#define NR_AUTOLOAD_MSRS 1
#define NESTED_MAX_VMCS 256

struct vmcs {
	u32 revision_id;
	u32 abort;
	char data[0];
};

struct shared_msr_entry {
	unsigned index;
	u64 data;
	u64 mask;
};

/*
 * vmcs_fields is a structure used in nested VMX for holding a copy of all
 * standard VMCS fields. It is used for emulating a VMCS for L1 (see struct
 * vmcs12), and also for easier access to VMCS data (see vmcs01_fields).
 */
struct __packed vmcs_fields {
	u16 virtual_processor_id;
	u16 guest_es_selector;
	u16 guest_cs_selector;
	u16 guest_ss_selector;
	u16 guest_ds_selector;
	u16 guest_fs_selector;
	u16 guest_gs_selector;
	u16 guest_ldtr_selector;
	u16 guest_tr_selector;
	u16 host_es_selector;
	u16 host_cs_selector;
	u16 host_ss_selector;
	u16 host_ds_selector;
	u16 host_fs_selector;
	u16 host_gs_selector;
	u16 host_tr_selector;
	u64 io_bitmap_a;
	u64 io_bitmap_b;
	u64 msr_bitmap;
	u64 vm_exit_msr_store_addr;
	u64 vm_exit_msr_load_addr;
	u64 vm_entry_msr_load_addr;
	u64 tsc_offset;
	u64 virtual_apic_page_addr;
	u64 apic_access_addr;
	u64 ept_pointer;
	u64 guest_physical_address;
	u64 vmcs_link_pointer;
	u64 guest_ia32_debugctl;
	u64 guest_ia32_pat;
	u64 guest_pdptr0;
	u64 guest_pdptr1;
	u64 guest_pdptr2;
	u64 guest_pdptr3;
	u64 host_ia32_pat;
	u32 pin_based_vm_exec_control;
	u32 cpu_based_vm_exec_control;
	u32 exception_bitmap;
	u32 page_fault_error_code_mask;
	u32 page_fault_error_code_match;
	u32 cr3_target_count;
	u32 vm_exit_controls;
	u32 vm_exit_msr_store_count;
	u32 vm_exit_msr_load_count;
	u32 vm_entry_controls;
	u32 vm_entry_msr_load_count;
	u32 vm_entry_intr_info_field;
	u32 vm_entry_exception_error_code;
	u32 vm_entry_instruction_len;
	u32 tpr_threshold;
	u32 secondary_vm_exec_control;
	u32 vm_instruction_error;
	u32 vm_exit_reason;
	u32 vm_exit_intr_info;
	u32 vm_exit_intr_error_code;
	u32 idt_vectoring_info_field;
	u32 idt_vectoring_error_code;
	u32 vm_exit_instruction_len;
	u32 vmx_instruction_info;
	u32 guest_es_limit;
	u32 guest_cs_limit;
	u32 guest_ss_limit;
	u32 guest_ds_limit;
	u32 guest_fs_limit;
	u32 guest_gs_limit;
	u32 guest_ldtr_limit;
	u32 guest_tr_limit;
	u32 guest_gdtr_limit;
	u32 guest_idtr_limit;
	u32 guest_es_ar_bytes;
	u32 guest_cs_ar_bytes;
	u32 guest_ss_ar_bytes;
	u32 guest_ds_ar_bytes;
	u32 guest_fs_ar_bytes;
	u32 guest_gs_ar_bytes;
	u32 guest_ldtr_ar_bytes;
	u32 guest_tr_ar_bytes;
	u32 guest_interruptibility_info;
	u32 guest_activity_state;
	u32 guest_sysenter_cs;
	u32 host_ia32_sysenter_cs;
	unsigned long cr0_guest_host_mask;
	unsigned long cr4_guest_host_mask;
	unsigned long cr0_read_shadow;
	unsigned long cr4_read_shadow;
	unsigned long cr3_target_value0;
	unsigned long cr3_target_value1;
	unsigned long cr3_target_value2;
	unsigned long cr3_target_value3;
	unsigned long exit_qualification;
	unsigned long guest_linear_address;
	unsigned long guest_cr0;
	unsigned long guest_cr3;
	unsigned long guest_cr4;
	unsigned long guest_es_base;
	unsigned long guest_cs_base;
	unsigned long guest_ss_base;
	unsigned long guest_ds_base;
	unsigned long guest_fs_base;
	unsigned long guest_gs_base;
	unsigned long guest_ldtr_base;
	unsigned long guest_tr_base;
	unsigned long guest_gdtr_base;
	unsigned long guest_idtr_base;
	unsigned long guest_dr7;
	unsigned long guest_rsp;
	unsigned long guest_rip;
	unsigned long guest_rflags;
	unsigned long guest_pending_dbg_exceptions;
	unsigned long guest_sysenter_esp;
	unsigned long guest_sysenter_eip;
	unsigned long host_cr0;
	unsigned long host_cr3;
	unsigned long host_cr4;
	unsigned long host_fs_base;
	unsigned long host_gs_base;
	unsigned long host_tr_base;
	unsigned long host_gdtr_base;
	unsigned long host_idtr_base;
	unsigned long host_ia32_sysenter_esp;
	unsigned long host_ia32_sysenter_eip;
	unsigned long host_rsp;
	unsigned long host_rip;
};

/*
 * struct vmcs12 describes the state that our guest hypervisor (L1) keeps for a
 * single nested guest (L2), hence the name vmcs12. Any VMX implementation has
 * a VMCS structure, and vmcs12 is our emulated VMX's VMCS. This structure is
 * stored in guest memory specified by VMPTRLD, but is opaque to the guest,
 * which must access it using VMREAD/VMWRITE/VMCLEAR instructions. More
 * than one of these structures may exist, if L1 runs multiple L2 guests.
 * nested_vmx_run() will use the data here to build a vmcs02: a VMCS for the
 * underlying hardware which will be used to run L2.
 * This structure is packed in order to preserve the binary content after live
 * migration. If there are changes in the content or layout, VMCS12_REVISION
 * must be changed.
 */
struct __packed vmcs12 {
	/* According to the Intel spec, a VMCS region must start with the
	 * following two fields. Then follow implementation-specific data.
	 */
	u32 revision_id;
	u32 abort;

	struct vmcs_fields fields;

	bool launch_state; /* set to 0 by VMCLEAR, to 1 by VMLAUNCH */
};

/*
 * VMCS12_REVISION is an arbitrary id that should be changed if the content or
 * layout of struct vmcs12 is changed. MSR_IA32_VMX_BASIC returns this id, and
 * VMPTRLD verifies that the VMCS region that L1 is loading contains this id.
 */
#define VMCS12_REVISION 0x11e57ed0

/*
 * When we temporarily switch a vcpu's VMCS (e.g., stop using an L1's VMCS
 * while we use L2's VMCS), and wish to save the previous VMCS, we must also
 * remember on which CPU it was last loaded (vcpu->cpu), so when we return to
 * using this VMCS we'll know if we're now running on a different CPU and need
 * to clear the VMCS on the old CPU, and load it on the new one. Additionally,
 * we need to remember whether this VMCS was launched (vmx->launched), so when
 * we return to it we know if to VMLAUNCH or to VMRESUME it (we cannot deduce
 * this from other state, because it's possible that this VMCS had once been
 * launched, but has since been cleared after a CPU switch, and now
 * vmx->launch is 0.
 */
struct saved_vmcs {
	struct vmcs *vmcs;
	int cpu;
	int launched;
};

/*
 * A cache keeping a VMCS (vmcs02) for each loaded vmcs12. In addition to the
 * VMCS, we need information on its state - see struct saved_vmcs above.
 */
struct vmcs_list {
	struct list_head list;
	gpa_t vmcs12_addr;
	struct saved_vmcs vmcs02;
};

/*
 * The nested_vmx structure is part of vcpu_vmx, and holds information we need
 * for correct emulation of VMX (i.e., nested VMX) on this vcpu. For example,
 * the current VMCS set by L1, a list of the VMCSs used to run the active
 * L2 guests on the hardware, and more.
 */
struct nested_vmx {
	/* Has the level1 guest done vmxon? */
	bool vmxon;

	/* The guest-physical address of the current VMCS L1 keeps for L2 */
	gpa_t current_vmptr;
	/* The host-usable pointer to the above */
	struct page *current_vmcs12_page;
	struct vmcs12 *current_vmcs12;

	/* list of real (hardware) VMCS, one for each L2 guest of L1 */
	struct list_head vmcs02_list; /* a vmcs_list */
	int vmcs02_num;

	/* Saving the VMCS that we used for running L1 */
	struct saved_vmcs saved_vmcs01;
	struct vmcs_fields *vmcs01_fields;
	/* L2 must run next, and mustn't decide to exit to L1. */
	bool nested_run_pending;
	/* true if last exit was of L2, and had a valid idt_vectoring_info */
	bool valid_idt_vectoring_info;
	/* These are saved if valid_idt_vectoring_info */
	u32 vm_exit_instruction_len, idt_vectoring_error_code;
};

struct vcpu_vmx {
	struct kvm_vcpu       vcpu;
	struct list_head      local_vcpus_link;
	unsigned long         host_rsp;
	int                   launched;
	u8                    fail;
	u32                   exit_intr_info;
	u32                   idt_vectoring_info;
	struct shared_msr_entry *guest_msrs;
	int                   nmsrs;
	int                   save_nmsrs;
#ifdef CONFIG_X86_64
	u64 		      msr_host_kernel_gs_base;
	u64 		      msr_guest_kernel_gs_base;
#endif
	struct vmcs          *vmcs;
	struct msr_autoload {
		unsigned nr;
		struct vmx_msr_entry guest[NR_AUTOLOAD_MSRS];
		struct vmx_msr_entry host[NR_AUTOLOAD_MSRS];
	} msr_autoload;
	struct {
		int           loaded;
		u16           fs_sel, gs_sel, ldt_sel;
		int           gs_ldt_reload_needed;
		int           fs_reload_needed;
	} host_state;
	struct {
		int vm86_active;
		ulong save_rflags;
		struct kvm_save_segment {
			u16 selector;
			unsigned long base;
			u32 limit;
			u32 ar;
		} tr, es, ds, fs, gs;
	} rmode;
	int vpid;
	bool emulation_required;

	/* Support for vnmi-less CPUs */
	int soft_vnmi_blocked;
	ktime_t entry_time;
	s64 vnmi_blocked_time;
	u32 exit_reason;

	bool rdtscp_enabled;

	/* Support for a guest hypervisor (nested VMX) */
	struct nested_vmx nested;
};

static inline struct vcpu_vmx *to_vmx(struct kvm_vcpu *vcpu)
{
	return container_of(vcpu, struct vcpu_vmx, vcpu);
}

#define VMCS_FIELDS_OFFSET(x) offsetof(struct vmcs_fields, x)
#define FIELD(number, name)	[number] = VMCS_FIELDS_OFFSET(name)
#define FIELD64(number, name)	[number] = VMCS_FIELDS_OFFSET(name), \
				[number##_HIGH] = VMCS_FIELDS_OFFSET(name)+4

static unsigned short vmcs_field_to_offset_table[] = {
	FIELD(VIRTUAL_PROCESSOR_ID, virtual_processor_id),
	FIELD(GUEST_ES_SELECTOR, guest_es_selector),
	FIELD(GUEST_CS_SELECTOR, guest_cs_selector),
	FIELD(GUEST_SS_SELECTOR, guest_ss_selector),
	FIELD(GUEST_DS_SELECTOR, guest_ds_selector),
	FIELD(GUEST_FS_SELECTOR, guest_fs_selector),
	FIELD(GUEST_GS_SELECTOR, guest_gs_selector),
	FIELD(GUEST_LDTR_SELECTOR, guest_ldtr_selector),
	FIELD(GUEST_TR_SELECTOR, guest_tr_selector),
	FIELD(HOST_ES_SELECTOR, host_es_selector),
	FIELD(HOST_CS_SELECTOR, host_cs_selector),
	FIELD(HOST_SS_SELECTOR, host_ss_selector),
	FIELD(HOST_DS_SELECTOR, host_ds_selector),
	FIELD(HOST_FS_SELECTOR, host_fs_selector),
	FIELD(HOST_GS_SELECTOR, host_gs_selector),
	FIELD(HOST_TR_SELECTOR, host_tr_selector),
	FIELD64(IO_BITMAP_A, io_bitmap_a),
	FIELD64(IO_BITMAP_B, io_bitmap_b),
	FIELD64(MSR_BITMAP, msr_bitmap),
	FIELD64(VM_EXIT_MSR_STORE_ADDR, vm_exit_msr_store_addr),
	FIELD64(VM_EXIT_MSR_LOAD_ADDR, vm_exit_msr_load_addr),
	FIELD64(VM_ENTRY_MSR_LOAD_ADDR, vm_entry_msr_load_addr),
	FIELD64(TSC_OFFSET, tsc_offset),
	FIELD64(VIRTUAL_APIC_PAGE_ADDR, virtual_apic_page_addr),
	FIELD64(APIC_ACCESS_ADDR, apic_access_addr),
	FIELD64(EPT_POINTER, ept_pointer),
	FIELD64(GUEST_PHYSICAL_ADDRESS, guest_physical_address),
	FIELD64(VMCS_LINK_POINTER, vmcs_link_pointer),
	FIELD64(GUEST_IA32_DEBUGCTL, guest_ia32_debugctl),
	FIELD64(GUEST_IA32_PAT, guest_ia32_pat),
	FIELD64(GUEST_PDPTR0, guest_pdptr0),
	FIELD64(GUEST_PDPTR1, guest_pdptr1),
	FIELD64(GUEST_PDPTR2, guest_pdptr2),
	FIELD64(GUEST_PDPTR3, guest_pdptr3),
	FIELD64(HOST_IA32_PAT, host_ia32_pat),
	FIELD(PIN_BASED_VM_EXEC_CONTROL, pin_based_vm_exec_control),
	FIELD(CPU_BASED_VM_EXEC_CONTROL, cpu_based_vm_exec_control),
	FIELD(EXCEPTION_BITMAP, exception_bitmap),
	FIELD(PAGE_FAULT_ERROR_CODE_MASK, page_fault_error_code_mask),
	FIELD(PAGE_FAULT_ERROR_CODE_MATCH, page_fault_error_code_match),
	FIELD(CR3_TARGET_COUNT, cr3_target_count),
	FIELD(VM_EXIT_CONTROLS, vm_exit_controls),
	FIELD(VM_EXIT_MSR_STORE_COUNT, vm_exit_msr_store_count),
	FIELD(VM_EXIT_MSR_LOAD_COUNT, vm_exit_msr_load_count),
	FIELD(VM_ENTRY_CONTROLS, vm_entry_controls),
	FIELD(VM_ENTRY_MSR_LOAD_COUNT, vm_entry_msr_load_count),
	FIELD(VM_ENTRY_INTR_INFO_FIELD, vm_entry_intr_info_field),
	FIELD(VM_ENTRY_EXCEPTION_ERROR_CODE, vm_entry_exception_error_code),
	FIELD(VM_ENTRY_INSTRUCTION_LEN, vm_entry_instruction_len),
	FIELD(TPR_THRESHOLD, tpr_threshold),
	FIELD(SECONDARY_VM_EXEC_CONTROL, secondary_vm_exec_control),
	FIELD(VM_INSTRUCTION_ERROR, vm_instruction_error),
	FIELD(VM_EXIT_REASON, vm_exit_reason),
	FIELD(VM_EXIT_INTR_INFO, vm_exit_intr_info),
	FIELD(VM_EXIT_INTR_ERROR_CODE, vm_exit_intr_error_code),
	FIELD(IDT_VECTORING_INFO_FIELD, idt_vectoring_info_field),
	FIELD(IDT_VECTORING_ERROR_CODE, idt_vectoring_error_code),
	FIELD(VM_EXIT_INSTRUCTION_LEN, vm_exit_instruction_len),
	FIELD(VMX_INSTRUCTION_INFO, vmx_instruction_info),
	FIELD(GUEST_ES_LIMIT, guest_es_limit),
	FIELD(GUEST_CS_LIMIT, guest_cs_limit),
	FIELD(GUEST_SS_LIMIT, guest_ss_limit),
	FIELD(GUEST_DS_LIMIT, guest_ds_limit),
	FIELD(GUEST_FS_LIMIT, guest_fs_limit),
	FIELD(GUEST_GS_LIMIT, guest_gs_limit),
	FIELD(GUEST_LDTR_LIMIT, guest_ldtr_limit),
	FIELD(GUEST_TR_LIMIT, guest_tr_limit),
	FIELD(GUEST_GDTR_LIMIT, guest_gdtr_limit),
	FIELD(GUEST_IDTR_LIMIT, guest_idtr_limit),
	FIELD(GUEST_ES_AR_BYTES, guest_es_ar_bytes),
	FIELD(GUEST_CS_AR_BYTES, guest_cs_ar_bytes),
	FIELD(GUEST_SS_AR_BYTES, guest_ss_ar_bytes),
	FIELD(GUEST_DS_AR_BYTES, guest_ds_ar_bytes),
	FIELD(GUEST_FS_AR_BYTES, guest_fs_ar_bytes),
	FIELD(GUEST_GS_AR_BYTES, guest_gs_ar_bytes),
	FIELD(GUEST_LDTR_AR_BYTES, guest_ldtr_ar_bytes),
	FIELD(GUEST_TR_AR_BYTES, guest_tr_ar_bytes),
	FIELD(GUEST_INTERRUPTIBILITY_INFO, guest_interruptibility_info),
	FIELD(GUEST_ACTIVITY_STATE, guest_activity_state),
	FIELD(GUEST_SYSENTER_CS, guest_sysenter_cs),
	FIELD(HOST_IA32_SYSENTER_CS, host_ia32_sysenter_cs),
	FIELD(CR0_GUEST_HOST_MASK, cr0_guest_host_mask),
	FIELD(CR4_GUEST_HOST_MASK, cr4_guest_host_mask),
	FIELD(CR0_READ_SHADOW, cr0_read_shadow),
	FIELD(CR4_READ_SHADOW, cr4_read_shadow),
	FIELD(CR3_TARGET_VALUE0, cr3_target_value0),
	FIELD(CR3_TARGET_VALUE1, cr3_target_value1),
	FIELD(CR3_TARGET_VALUE2, cr3_target_value2),
	FIELD(CR3_TARGET_VALUE3, cr3_target_value3),
	FIELD(EXIT_QUALIFICATION, exit_qualification),
	FIELD(GUEST_LINEAR_ADDRESS, guest_linear_address),
	FIELD(GUEST_CR0, guest_cr0),
	FIELD(GUEST_CR3, guest_cr3),
	FIELD(GUEST_CR4, guest_cr4),
	FIELD(GUEST_ES_BASE, guest_es_base),
	FIELD(GUEST_CS_BASE, guest_cs_base),
	FIELD(GUEST_SS_BASE, guest_ss_base),
	FIELD(GUEST_DS_BASE, guest_ds_base),
	FIELD(GUEST_FS_BASE, guest_fs_base),
	FIELD(GUEST_GS_BASE, guest_gs_base),
	FIELD(GUEST_LDTR_BASE, guest_ldtr_base),
	FIELD(GUEST_TR_BASE, guest_tr_base),
	FIELD(GUEST_GDTR_BASE, guest_gdtr_base),
	FIELD(GUEST_IDTR_BASE, guest_idtr_base),
	FIELD(GUEST_DR7, guest_dr7),
	FIELD(GUEST_RSP, guest_rsp),
	FIELD(GUEST_RIP, guest_rip),
	FIELD(GUEST_RFLAGS, guest_rflags),
	FIELD(GUEST_PENDING_DBG_EXCEPTIONS, guest_pending_dbg_exceptions),
	FIELD(GUEST_SYSENTER_ESP, guest_sysenter_esp),
	FIELD(GUEST_SYSENTER_EIP, guest_sysenter_eip),
	FIELD(HOST_CR0, host_cr0),
	FIELD(HOST_CR3, host_cr3),
	FIELD(HOST_CR4, host_cr4),
	FIELD(HOST_FS_BASE, host_fs_base),
	FIELD(HOST_GS_BASE, host_gs_base),
	FIELD(HOST_TR_BASE, host_tr_base),
	FIELD(HOST_GDTR_BASE, host_gdtr_base),
	FIELD(HOST_IDTR_BASE, host_idtr_base),
	FIELD(HOST_IA32_SYSENTER_ESP, host_ia32_sysenter_esp),
	FIELD(HOST_IA32_SYSENTER_EIP, host_ia32_sysenter_eip),
	FIELD(HOST_RSP, host_rsp),
	FIELD(HOST_RIP, host_rip),
};
static const int max_vmcs_field = ARRAY_SIZE(vmcs_field_to_offset_table);

static inline short vmcs_field_to_offset(unsigned long field)
{

	if (field >= max_vmcs_field || vmcs_field_to_offset_table[field] == 0)
		return -1;
	return vmcs_field_to_offset_table[field];
}

static inline struct vmcs_fields *get_vmcs12_fields(struct kvm_vcpu *vcpu)
{
	return &(to_vmx(vcpu)->nested.current_vmcs12->fields);
}

static inline struct vmcs12 *get_vmcs12(struct kvm_vcpu *vcpu)
{
	return to_vmx(vcpu)->nested.current_vmcs12;
}

static struct page *nested_get_page(struct kvm_vcpu *vcpu, gpa_t addr)
{
	struct page *page = gfn_to_page(vcpu->kvm, addr >> PAGE_SHIFT);
	if (is_error_page(page)) {
		kvm_release_page_clean(page);
		return NULL;
	}
	return page;
}

static void nested_release_page(struct page *page)
{
	kvm_release_page_dirty(page);
}

static void nested_release_page_clean(struct page *page)
{
	kvm_release_page_clean(page);
}

static int init_rmode(struct kvm *kvm);
static u64 construct_eptp(unsigned long root_hpa);
static void kvm_cpu_vmxon(u64 addr);
static void kvm_cpu_vmxoff(void);
static void vmx_set_cr3(struct kvm_vcpu *vcpu, unsigned long cr3);

static DEFINE_PER_CPU(struct vmcs *, vmxarea);
static DEFINE_PER_CPU(struct vmcs *, current_vmcs);
static DEFINE_PER_CPU(struct list_head, vcpus_on_cpu);
static DEFINE_PER_CPU(struct desc_ptr, host_gdt);

static unsigned long *vmx_io_bitmap_a;
static unsigned long *vmx_io_bitmap_b;
static unsigned long *vmx_msr_bitmap_legacy;
static unsigned long *vmx_msr_bitmap_longmode;

static bool cpu_has_load_ia32_efer;

static DECLARE_BITMAP(vmx_vpid_bitmap, VMX_NR_VPIDS);
static DEFINE_SPINLOCK(vmx_vpid_lock);

static struct vmcs_config {
	int size;
	int order;
	u32 revision_id;
	u32 pin_based_exec_ctrl;
	u32 cpu_based_exec_ctrl;
	u32 cpu_based_2nd_exec_ctrl;
	u32 vmexit_ctrl;
	u32 vmentry_ctrl;
} vmcs_config;

static struct vmx_capability {
	u32 ept;
	u32 vpid;
} vmx_capability;

#define VMX_SEGMENT_FIELD(seg)					\
	[VCPU_SREG_##seg] = {                                   \
		.selector = GUEST_##seg##_SELECTOR,		\
		.base = GUEST_##seg##_BASE,		   	\
		.limit = GUEST_##seg##_LIMIT,		   	\
		.ar_bytes = GUEST_##seg##_AR_BYTES,	   	\
	}

static struct kvm_vmx_segment_field {
	unsigned selector;
	unsigned base;
	unsigned limit;
	unsigned ar_bytes;
} kvm_vmx_segment_fields[] = {
	VMX_SEGMENT_FIELD(CS),
	VMX_SEGMENT_FIELD(DS),
	VMX_SEGMENT_FIELD(ES),
	VMX_SEGMENT_FIELD(FS),
	VMX_SEGMENT_FIELD(GS),
	VMX_SEGMENT_FIELD(SS),
	VMX_SEGMENT_FIELD(TR),
	VMX_SEGMENT_FIELD(LDTR),
};

static u64 host_efer;

static void ept_save_pdptrs(struct kvm_vcpu *vcpu);

/*
 * Keep MSR_STAR at the end, as setup_msrs() will try to optimize it
 * away by decrementing the array size.
 */
static const u32 vmx_msr_index[] = {
#ifdef CONFIG_X86_64
	MSR_SYSCALL_MASK, MSR_LSTAR, MSR_CSTAR,
#endif
	MSR_EFER, MSR_TSC_AUX, MSR_STAR,
};
#define NR_VMX_MSR ARRAY_SIZE(vmx_msr_index)

static inline bool is_page_fault(u32 intr_info)
{
	return (intr_info & (INTR_INFO_INTR_TYPE_MASK | INTR_INFO_VECTOR_MASK |
			     INTR_INFO_VALID_MASK)) ==
		(INTR_TYPE_HARD_EXCEPTION | PF_VECTOR | INTR_INFO_VALID_MASK);
}

static inline bool is_no_device(u32 intr_info)
{
	return (intr_info & (INTR_INFO_INTR_TYPE_MASK | INTR_INFO_VECTOR_MASK |
			     INTR_INFO_VALID_MASK)) ==
		(INTR_TYPE_HARD_EXCEPTION | NM_VECTOR | INTR_INFO_VALID_MASK);
}

static inline bool is_invalid_opcode(u32 intr_info)
{
	return (intr_info & (INTR_INFO_INTR_TYPE_MASK | INTR_INFO_VECTOR_MASK |
			     INTR_INFO_VALID_MASK)) ==
		(INTR_TYPE_HARD_EXCEPTION | UD_VECTOR | INTR_INFO_VALID_MASK);
}

static inline bool is_external_interrupt(u32 intr_info)
{
	return (intr_info & (INTR_INFO_INTR_TYPE_MASK | INTR_INFO_VALID_MASK))
		== (INTR_TYPE_EXT_INTR | INTR_INFO_VALID_MASK);
}

static inline bool is_machine_check(u32 intr_info)
{
	return (intr_info & (INTR_INFO_INTR_TYPE_MASK | INTR_INFO_VECTOR_MASK |
			     INTR_INFO_VALID_MASK)) ==
		(INTR_TYPE_HARD_EXCEPTION | MC_VECTOR | INTR_INFO_VALID_MASK);
}

static inline bool cpu_has_vmx_msr_bitmap(void)
{
	return vmcs_config.cpu_based_exec_ctrl & CPU_BASED_USE_MSR_BITMAPS;
}

static inline bool cpu_has_vmx_tpr_shadow(void)
{
	return vmcs_config.cpu_based_exec_ctrl & CPU_BASED_TPR_SHADOW;
}

static inline bool vm_need_tpr_shadow(struct kvm *kvm)
{
	return (cpu_has_vmx_tpr_shadow()) && (irqchip_in_kernel(kvm));
}

static inline bool cpu_has_secondary_exec_ctrls(void)
{
	return vmcs_config.cpu_based_exec_ctrl &
		CPU_BASED_ACTIVATE_SECONDARY_CONTROLS;
}

static inline bool cpu_has_vmx_virtualize_apic_accesses(void)
{
	return vmcs_config.cpu_based_2nd_exec_ctrl &
		SECONDARY_EXEC_VIRTUALIZE_APIC_ACCESSES;
}

static inline bool cpu_has_vmx_flexpriority(void)
{
	return cpu_has_vmx_tpr_shadow() &&
		cpu_has_vmx_virtualize_apic_accesses();
}

static inline bool cpu_has_vmx_ept_execute_only(void)
{
	return vmx_capability.ept & VMX_EPT_EXECUTE_ONLY_BIT;
}

static inline bool cpu_has_vmx_eptp_uncacheable(void)
{
	return vmx_capability.ept & VMX_EPTP_UC_BIT;
}

static inline bool cpu_has_vmx_eptp_writeback(void)
{
	return vmx_capability.ept & VMX_EPTP_WB_BIT;
}

static inline bool cpu_has_vmx_ept_2m_page(void)
{
	return vmx_capability.ept & VMX_EPT_2MB_PAGE_BIT;
}

static inline bool cpu_has_vmx_ept_1g_page(void)
{
	return vmx_capability.ept & VMX_EPT_1GB_PAGE_BIT;
}

static inline bool cpu_has_vmx_ept_4levels(void)
{
	return vmx_capability.ept & VMX_EPT_PAGE_WALK_4_BIT;
}

static inline bool cpu_has_vmx_invept_individual_addr(void)
{
	return vmx_capability.ept & VMX_EPT_EXTENT_INDIVIDUAL_BIT;
}

static inline bool cpu_has_vmx_invept_context(void)
{
	return vmx_capability.ept & VMX_EPT_EXTENT_CONTEXT_BIT;
}

static inline bool cpu_has_vmx_invept_global(void)
{
	return vmx_capability.ept & VMX_EPT_EXTENT_GLOBAL_BIT;
}

static inline bool cpu_has_vmx_invvpid_single(void)
{
	return vmx_capability.vpid & VMX_VPID_EXTENT_SINGLE_CONTEXT_BIT;
}

static inline bool cpu_has_vmx_invvpid_global(void)
{
	return vmx_capability.vpid & VMX_VPID_EXTENT_GLOBAL_CONTEXT_BIT;
}

static inline bool cpu_has_vmx_ept(void)
{
	return vmcs_config.cpu_based_2nd_exec_ctrl &
		SECONDARY_EXEC_ENABLE_EPT;
}

static inline bool cpu_has_vmx_unrestricted_guest(void)
{
	return vmcs_config.cpu_based_2nd_exec_ctrl &
		SECONDARY_EXEC_UNRESTRICTED_GUEST;
}

static inline bool cpu_has_vmx_ple(void)
{
	return vmcs_config.cpu_based_2nd_exec_ctrl &
		SECONDARY_EXEC_PAUSE_LOOP_EXITING;
}

static inline bool vm_need_virtualize_apic_accesses(struct kvm *kvm)
{
	return flexpriority_enabled && irqchip_in_kernel(kvm);
}

static inline bool cpu_has_vmx_vpid(void)
{
	return vmcs_config.cpu_based_2nd_exec_ctrl &
		SECONDARY_EXEC_ENABLE_VPID;
}

static inline bool cpu_has_vmx_rdtscp(void)
{
	return vmcs_config.cpu_based_2nd_exec_ctrl &
		SECONDARY_EXEC_RDTSCP;
}

static inline bool cpu_has_virtual_nmis(void)
{
	return vmcs_config.pin_based_exec_ctrl & PIN_BASED_VIRTUAL_NMIS;
}

static inline bool cpu_has_vmx_wbinvd_exit(void)
{
	return vmcs_config.cpu_based_2nd_exec_ctrl &
		SECONDARY_EXEC_WBINVD_EXITING;
}

static inline bool report_flexpriority(void)
{
	return flexpriority_enabled;
}

static inline bool nested_cpu_has_vmx_tpr_shadow(struct kvm_vcpu *vcpu)
{
	return cpu_has_vmx_tpr_shadow() &&
		(get_vmcs12_fields(vcpu)->cpu_based_vm_exec_control &
		CPU_BASED_TPR_SHADOW);
}

static inline bool nested_cpu_has_secondary_exec_ctrls(struct kvm_vcpu *vcpu)
{
	return cpu_has_secondary_exec_ctrls() &&
		(get_vmcs12_fields(vcpu)->cpu_based_vm_exec_control &
		CPU_BASED_ACTIVATE_SECONDARY_CONTROLS);
}

static inline bool nested_vm_need_virtualize_apic_accesses(struct kvm_vcpu
							   *vcpu)
{
	return nested_cpu_has_secondary_exec_ctrls(vcpu) &&
		(get_vmcs12_fields(vcpu)->secondary_vm_exec_control &
		SECONDARY_EXEC_VIRTUALIZE_APIC_ACCESSES);
}

static inline bool nested_cpu_has_vmx_msr_bitmap(struct kvm_vcpu *vcpu)
{
	return get_vmcs12_fields(vcpu)->cpu_based_vm_exec_control &
		CPU_BASED_USE_MSR_BITMAPS;
}

static inline bool is_exception(u32 intr_info)
{
	return (intr_info & (INTR_INFO_INTR_TYPE_MASK | INTR_INFO_VALID_MASK))
		== (INTR_TYPE_HARD_EXCEPTION | INTR_INFO_VALID_MASK);
}

static void nested_vmx_vmexit(struct kvm_vcpu *vcpu, bool is_interrupt);

static int __find_msr_index(struct vcpu_vmx *vmx, u32 msr)
{
	int i;

	for (i = 0; i < vmx->nmsrs; ++i)
		if (vmx_msr_index[vmx->guest_msrs[i].index] == msr)
			return i;
	return -1;
}

static inline void __invvpid(int ext, u16 vpid, gva_t gva)
{
    struct {
	u64 vpid : 16;
	u64 rsvd : 48;
	u64 gva;
    } operand = { vpid, 0, gva };

    asm volatile (__ex(ASM_VMX_INVVPID)
		  /* CF==1 or ZF==1 --> rc = -1 */
		  "; ja 1f ; ud2 ; 1:"
		  : : "a"(&operand), "c"(ext) : "cc", "memory");
}

static inline void __invept(int ext, u64 eptp, gpa_t gpa)
{
	struct {
		u64 eptp, gpa;
	} operand = {eptp, gpa};

	asm volatile (__ex(ASM_VMX_INVEPT)
			/* CF==1 or ZF==1 --> rc = -1 */
			"; ja 1f ; ud2 ; 1:\n"
			: : "a" (&operand), "c" (ext) : "cc", "memory");
}

static struct shared_msr_entry *find_msr_entry(struct vcpu_vmx *vmx, u32 msr)
{
	int i;

	i = __find_msr_index(vmx, msr);
	if (i >= 0)
		return &vmx->guest_msrs[i];
	return NULL;
}

static void vmcs_clear(struct vmcs *vmcs)
{
	u64 phys_addr = __pa(vmcs);
	u8 error;

	asm volatile (__ex(ASM_VMX_VMCLEAR_RAX) "; setna %0"
		      : "=qm"(error) : "a"(&phys_addr), "m"(phys_addr)
		      : "cc", "memory");
	if (error)
		printk(KERN_ERR "kvm: vmclear fail: %p/%llx\n",
		       vmcs, phys_addr);
}

static void vmcs_load(struct vmcs *vmcs)
{
	u64 phys_addr = __pa(vmcs);
	u8 error;

	asm volatile (__ex(ASM_VMX_VMPTRLD_RAX) "; setna %0"
			: "=qm"(error) : "a"(&phys_addr), "m"(phys_addr)
			: "cc", "memory");
	if (error)
		printk(KERN_ERR "kvm: vmptrld %p/%llx failed\n",
		       vmcs, phys_addr);
}

static void __vcpu_clear(void *arg)
{
	struct vcpu_vmx *vmx = arg;
	int cpu = raw_smp_processor_id();

	if (vmx->vcpu.cpu == cpu)
		vmcs_clear(vmx->vmcs);
	if (per_cpu(current_vmcs, cpu) == vmx->vmcs)
		per_cpu(current_vmcs, cpu) = NULL;
	/* TODO: currently, local_vcpus_link is just for L1 VMCSs */
	if (!is_guest_mode(&vmx->vcpu))
		list_del(&vmx->local_vcpus_link);
	vmx->vcpu.cpu = -1;
	vmx->launched = 0;
}

static void vcpu_clear(struct vcpu_vmx *vmx)
{
	if (vmx->vcpu.cpu == -1)
		return;
	smp_call_function_single(vmx->vcpu.cpu, __vcpu_clear, vmx, 1);
}

static inline void vpid_sync_vcpu_single(struct vcpu_vmx *vmx)
{
	if (vmx->vpid == 0)
		return;

	if (cpu_has_vmx_invvpid_single())
		__invvpid(VMX_VPID_EXTENT_SINGLE_CONTEXT, vmx->vpid, 0);
}

static inline void vpid_sync_vcpu_global(void)
{
	if (cpu_has_vmx_invvpid_global())
		__invvpid(VMX_VPID_EXTENT_ALL_CONTEXT, 0, 0);
}

static inline void vpid_sync_context(struct vcpu_vmx *vmx)
{
	if (cpu_has_vmx_invvpid_single())
		vpid_sync_vcpu_single(vmx);
	else
		vpid_sync_vcpu_global();
}

static inline void ept_sync_global(void)
{
	if (cpu_has_vmx_invept_global())
		__invept(VMX_EPT_EXTENT_GLOBAL, 0, 0);
}

static inline void ept_sync_context(u64 eptp)
{
	if (enable_ept) {
		if (cpu_has_vmx_invept_context())
			__invept(VMX_EPT_EXTENT_CONTEXT, eptp, 0);
		else
			ept_sync_global();
	}
}

static inline void ept_sync_individual_addr(u64 eptp, gpa_t gpa)
{
	if (enable_ept) {
		if (cpu_has_vmx_invept_individual_addr())
			__invept(VMX_EPT_EXTENT_INDIVIDUAL_ADDR,
					eptp, gpa);
		else
			ept_sync_context(eptp);
	}
}

static unsigned long vmcs_readl(unsigned long field)
{
	unsigned long value = 0;

	asm volatile (__ex(ASM_VMX_VMREAD_RDX_RAX)
		      : "+a"(value) : "d"(field) : "cc");
	return value;
}

static u16 vmcs_read16(unsigned long field)
{
	return vmcs_readl(field);
}

static u32 vmcs_read32(unsigned long field)
{
	return vmcs_readl(field);
}

static u64 vmcs_read64(unsigned long field)
{
#ifdef CONFIG_X86_64
	return vmcs_readl(field);
#else
	return vmcs_readl(field) | ((u64)vmcs_readl(field+1) << 32);
#endif
}

static noinline void vmwrite_error(unsigned long field, unsigned long value)
{
	printk(KERN_ERR "vmwrite error: reg %lx value %lx (err %d)\n",
	       field, value, vmcs_read32(VM_INSTRUCTION_ERROR));
	dump_stack();
}

static void vmcs_writel(unsigned long field, unsigned long value)
{
	u8 error;

	asm volatile (__ex(ASM_VMX_VMWRITE_RAX_RDX) "; setna %0"
		       : "=q"(error) : "a"(value), "d"(field) : "cc");
	if (unlikely(error))
		vmwrite_error(field, value);
}

static void vmcs_write16(unsigned long field, u16 value)
{
	vmcs_writel(field, value);
}

static void vmcs_write32(unsigned long field, u32 value)
{
	vmcs_writel(field, value);
}

static void vmcs_write64(unsigned long field, u64 value)
{
	vmcs_writel(field, value);
#ifndef CONFIG_X86_64
	asm volatile ("");
	vmcs_writel(field+1, value >> 32);
#endif
}

static void vmcs_clear_bits(unsigned long field, u32 mask)
{
	vmcs_writel(field, vmcs_readl(field) & ~mask);
}

static void vmcs_set_bits(unsigned long field, u32 mask)
{
	vmcs_writel(field, vmcs_readl(field) | mask);
}

static void update_exception_bitmap(struct kvm_vcpu *vcpu)
{
	u32 eb;

	eb = (1u << PF_VECTOR) | (1u << UD_VECTOR) | (1u << MC_VECTOR) |
	     (1u << NM_VECTOR) | (1u << DB_VECTOR);
	if ((vcpu->guest_debug &
	     (KVM_GUESTDBG_ENABLE | KVM_GUESTDBG_USE_SW_BP)) ==
	    (KVM_GUESTDBG_ENABLE | KVM_GUESTDBG_USE_SW_BP))
		eb |= 1u << BP_VECTOR;
	if (to_vmx(vcpu)->rmode.vm86_active)
		eb = ~0;
	if (enable_ept)
		eb &= ~(1u << PF_VECTOR); /* bypass_guest_pf = 0 */
	if (vcpu->fpu_active)
		eb &= ~(1u << NM_VECTOR);

	/* When we are running a nested L2 guest and L1 specified for it a
	 * certain exception bitmap, we must trap the same exceptions and pass
	 * them to L1. When running L2, we will only handle the exceptions
	 * specified above if L1 did not want them.
	 */
	if (is_guest_mode(vcpu))
		eb |= get_vmcs12_fields(vcpu)->exception_bitmap;

	vmcs_write32(EXCEPTION_BITMAP, eb);
}

static void clear_atomic_switch_msr(struct vcpu_vmx *vmx, unsigned msr)
{
	unsigned i;
	struct msr_autoload *m = &vmx->msr_autoload;

	if (msr == MSR_EFER && cpu_has_load_ia32_efer) {
		vmcs_clear_bits(VM_ENTRY_CONTROLS, VM_ENTRY_LOAD_IA32_EFER);
		vmcs_clear_bits(VM_EXIT_CONTROLS, VM_EXIT_LOAD_IA32_EFER);
		return;
	}

	for (i = 0; i < m->nr; ++i)
		if (m->guest[i].index == msr)
			break;

	if (i == m->nr)
		return;
	--m->nr;
	m->guest[i] = m->guest[m->nr];
	m->host[i] = m->host[m->nr];
	vmcs_write32(VM_ENTRY_MSR_LOAD_COUNT, m->nr);
	vmcs_write32(VM_EXIT_MSR_LOAD_COUNT, m->nr);
}

static void add_atomic_switch_msr(struct vcpu_vmx *vmx, unsigned msr,
				  u64 guest_val, u64 host_val)
{
	unsigned i;
	struct msr_autoload *m = &vmx->msr_autoload;

	if (msr == MSR_EFER && cpu_has_load_ia32_efer) {
		vmcs_write64(GUEST_IA32_EFER, guest_val);
		vmcs_write64(HOST_IA32_EFER, host_val);
		vmcs_set_bits(VM_ENTRY_CONTROLS, VM_ENTRY_LOAD_IA32_EFER);
		vmcs_set_bits(VM_EXIT_CONTROLS, VM_EXIT_LOAD_IA32_EFER);
		return;
	}

	for (i = 0; i < m->nr; ++i)
		if (m->guest[i].index == msr)
			break;

	if (i == m->nr) {
		++m->nr;
		vmcs_write32(VM_ENTRY_MSR_LOAD_COUNT, m->nr);
		vmcs_write32(VM_EXIT_MSR_LOAD_COUNT, m->nr);
	}

	m->guest[i].index = msr;
	m->guest[i].value = guest_val;
	m->host[i].index = msr;
	m->host[i].value = host_val;
}

static void reload_tss(void)
{
	/*
	 * VT restores TR but not its size.  Useless.
	 */
	struct desc_ptr *gdt = &__get_cpu_var(host_gdt);
	struct desc_struct *descs;

	descs = (void *)gdt->address;
	descs[GDT_ENTRY_TSS].type = 9; /* available TSS */
	load_TR_desc();
}

static bool update_transition_efer(struct vcpu_vmx *vmx, int efer_offset)
{
	u64 guest_efer;
	u64 ignore_bits;

	guest_efer = vmx->vcpu.arch.efer;

	/*
	 * NX is emulated; LMA and LME handled by hardware; SCE meaninless
	 * outside long mode
	 */
	ignore_bits = EFER_NX | EFER_SCE;
#ifdef CONFIG_X86_64
	ignore_bits |= EFER_LMA | EFER_LME;
	/* SCE is meaningful only in long mode on Intel */
	if (guest_efer & EFER_LMA)
		ignore_bits &= ~(u64)EFER_SCE;
#endif
	guest_efer &= ~ignore_bits;
	guest_efer |= host_efer & ignore_bits;
	vmx->guest_msrs[efer_offset].data = guest_efer;
	vmx->guest_msrs[efer_offset].mask = ~ignore_bits;

	clear_atomic_switch_msr(vmx, MSR_EFER);
	/* On ept, can't emulate nx, and must switch nx atomically */
	if (enable_ept && ((vmx->vcpu.arch.efer ^ host_efer) & EFER_NX)) {
		guest_efer = vmx->vcpu.arch.efer;
		if (!(guest_efer & EFER_LMA))
			guest_efer &= ~EFER_LME;
		add_atomic_switch_msr(vmx, MSR_EFER, guest_efer, host_efer);
		return false;
	}

	return true;
}

static unsigned long segment_base(u16 selector)
{
	struct desc_ptr *gdt = &__get_cpu_var(host_gdt);
	struct desc_struct *d;
	unsigned long table_base;
	unsigned long v;

	if (!(selector & ~3))
		return 0;

	table_base = gdt->address;

	if (selector & 4) {           /* from ldt */
		u16 ldt_selector = kvm_read_ldt();

		if (!(ldt_selector & ~3))
			return 0;

		table_base = segment_base(ldt_selector);
	}
	d = (struct desc_struct *)(table_base + (selector & ~7));
	v = get_desc_base(d);
#ifdef CONFIG_X86_64
       if (d->s == 0 && (d->type == 2 || d->type == 9 || d->type == 11))
               v |= ((unsigned long)((struct ldttss_desc64 *)d)->base3) << 32;
#endif
	return v;
}

static inline unsigned long kvm_read_tr_base(void)
{
	u16 tr;
	asm("str %0" : "=g"(tr));
	return segment_base(tr);
}

static void vmx_save_host_state(struct kvm_vcpu *vcpu)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);
	int i;

	if (vmx->host_state.loaded)
		return;

	vmx->host_state.loaded = 1;
	/*
	 * Set host fs and gs selectors.  Unfortunately, 22.2.3 does not
	 * allow segment selectors with cpl > 0 or ti == 1.
	 */
	vmx->host_state.ldt_sel = kvm_read_ldt();
	vmx->host_state.gs_ldt_reload_needed = vmx->host_state.ldt_sel;
	savesegment(fs, vmx->host_state.fs_sel);
	if (!(vmx->host_state.fs_sel & 7)) {
		vmcs_write16(HOST_FS_SELECTOR, vmx->host_state.fs_sel);
		vmx->host_state.fs_reload_needed = 0;
	} else {
		vmcs_write16(HOST_FS_SELECTOR, 0);
		vmx->host_state.fs_reload_needed = 1;
	}
	savesegment(gs, vmx->host_state.gs_sel);
	if (!(vmx->host_state.gs_sel & 7))
		vmcs_write16(HOST_GS_SELECTOR, vmx->host_state.gs_sel);
	else {
		vmcs_write16(HOST_GS_SELECTOR, 0);
		vmx->host_state.gs_ldt_reload_needed = 1;
	}

#ifdef CONFIG_X86_64
	vmcs_writel(HOST_FS_BASE, read_msr(MSR_FS_BASE));
	vmcs_writel(HOST_GS_BASE, read_msr(MSR_GS_BASE));
#else
	vmcs_writel(HOST_FS_BASE, segment_base(vmx->host_state.fs_sel));
	vmcs_writel(HOST_GS_BASE, segment_base(vmx->host_state.gs_sel));
#endif

#ifdef CONFIG_X86_64
	rdmsrl(MSR_KERNEL_GS_BASE, vmx->msr_host_kernel_gs_base);
	if (is_long_mode(&vmx->vcpu))
		wrmsrl(MSR_KERNEL_GS_BASE, vmx->msr_guest_kernel_gs_base);
#endif
	for (i = 0; i < vmx->save_nmsrs; ++i)
		kvm_set_shared_msr(vmx->guest_msrs[i].index,
				   vmx->guest_msrs[i].data,
				   vmx->guest_msrs[i].mask);
}

static void __vmx_load_host_state(struct vcpu_vmx *vmx)
{
	if (!vmx->host_state.loaded)
		return;

	++vmx->vcpu.stat.host_state_reload;
	vmx->host_state.loaded = 0;
#ifdef CONFIG_X86_64
	if (is_long_mode(&vmx->vcpu))
		rdmsrl(MSR_KERNEL_GS_BASE, vmx->msr_guest_kernel_gs_base);
#endif
	if (vmx->host_state.gs_ldt_reload_needed) {
		kvm_load_ldt(vmx->host_state.ldt_sel);
#ifdef CONFIG_X86_64
		load_gs_index(vmx->host_state.gs_sel);
#else
		loadsegment(gs, vmx->host_state.gs_sel);
#endif
	}
	if (vmx->host_state.fs_reload_needed)
		loadsegment(fs, vmx->host_state.fs_sel);
	reload_tss();
#ifdef CONFIG_X86_64
	wrmsrl(MSR_KERNEL_GS_BASE, vmx->msr_host_kernel_gs_base);
#endif
	if (current_thread_info()->status & TS_USEDFPU)
		clts();
	load_gdt(&__get_cpu_var(host_gdt));
}

static void vmx_load_host_state(struct vcpu_vmx *vmx)
{
	preempt_disable();
	__vmx_load_host_state(vmx);
	preempt_enable();
}

/*
 * Switches to specified vcpu, until a matching vcpu_put(), but assumes
 * vcpu mutex is already taken.
 */
static void vmx_vcpu_load(struct kvm_vcpu *vcpu, int cpu)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);
	u64 phys_addr = __pa(per_cpu(vmxarea, cpu));

	if (!vmm_exclusive)
		kvm_cpu_vmxon(phys_addr);
	else if (vcpu->cpu != cpu)
		vcpu_clear(vmx);

	if (per_cpu(current_vmcs, cpu) != vmx->vmcs) {
		per_cpu(current_vmcs, cpu) = vmx->vmcs;
		vmcs_load(vmx->vmcs);
	}

	if (vcpu->cpu != cpu) {
		struct desc_ptr *gdt = &__get_cpu_var(host_gdt);
		unsigned long sysenter_esp;

		kvm_make_request(KVM_REQ_TLB_FLUSH, vcpu);
		local_irq_disable();
		/* TODO: currently, local_vcpus_link is just for L1 VMCSs */
		if (!is_guest_mode(&vmx->vcpu))
			list_add(&vmx->local_vcpus_link,
				 &per_cpu(vcpus_on_cpu, cpu));
		local_irq_enable();

		/*
		 * Linux uses per-cpu TSS and GDT, so set these when switching
		 * processors.
		 */
		vmcs_writel(HOST_TR_BASE, kvm_read_tr_base()); /* 22.2.4 */
		vmcs_writel(HOST_GDTR_BASE, gdt->address);   /* 22.2.4 */

		rdmsrl(MSR_IA32_SYSENTER_ESP, sysenter_esp);
		vmcs_writel(HOST_IA32_SYSENTER_ESP, sysenter_esp); /* 22.2.3 */
	}
}

static void vmx_vcpu_put(struct kvm_vcpu *vcpu)
{
	__vmx_load_host_state(to_vmx(vcpu));
	if (!vmm_exclusive) {
		__vcpu_clear(to_vmx(vcpu));
		kvm_cpu_vmxoff();
	}
}

static void vmx_fpu_activate(struct kvm_vcpu *vcpu)
{
	ulong cr0;

	if (vcpu->fpu_active)
		return;
	vcpu->fpu_active = 1;
	cr0 = vmcs_readl(GUEST_CR0);
	cr0 &= ~(X86_CR0_TS | X86_CR0_MP);
	cr0 |= kvm_read_cr0_bits(vcpu, X86_CR0_TS | X86_CR0_MP);
	vmcs_writel(GUEST_CR0, cr0);
	vcpu->arch.cr0_guest_owned_bits = X86_CR0_TS;
	if (is_guest_mode(vcpu)) {
		/* While we (L0) no longer care about NM exceptions or cr0.TS
		 * changes, our guest hypervisor (L1) might care in which case
		 * we must trap them for it.
		 */
		u32 eb = vmcs_read32(EXCEPTION_BITMAP) & ~(1u << NM_VECTOR);
		struct vmcs_fields *vmcs12 = get_vmcs12_fields(vcpu);
		eb |= vmcs12->exception_bitmap;
		vcpu->arch.cr0_guest_owned_bits &= ~vmcs12->cr0_guest_host_mask;
		vmcs_write32(EXCEPTION_BITMAP, eb);
	} else
		update_exception_bitmap(vcpu);
	vmcs_writel(CR0_GUEST_HOST_MASK, ~vcpu->arch.cr0_guest_owned_bits);
}

static void vmx_decache_cr0_guest_bits(struct kvm_vcpu *vcpu);

static void vmx_fpu_deactivate(struct kvm_vcpu *vcpu)
{
	/* Note that there is no vcpu->fpu_active = 0 here. The caller must
	 * set this *before* calling this function.
	 */
	vmx_decache_cr0_guest_bits(vcpu);
	vmcs_set_bits(GUEST_CR0, X86_CR0_TS | X86_CR0_MP);
	vmcs_write32(EXCEPTION_BITMAP,
		vmcs_read32(EXCEPTION_BITMAP) | (1u << NM_VECTOR));
	vcpu->arch.cr0_guest_owned_bits = 0;
	vmcs_writel(CR0_GUEST_HOST_MASK, ~vcpu->arch.cr0_guest_owned_bits);
	if (is_guest_mode(vcpu))
		/* Unfortunately in nested mode we play with arch.cr0's PG
		 * bit, so we musn't copy it all, just the relevant TS bit
		 */
		vmcs_writel(CR0_READ_SHADOW,
			(vmcs_readl(CR0_READ_SHADOW) & ~X86_CR0_TS) |
			(vcpu->arch.cr0 & X86_CR0_TS));
	else
		vmcs_writel(CR0_READ_SHADOW, vcpu->arch.cr0);
}

static unsigned long vmx_get_rflags(struct kvm_vcpu *vcpu)
{
	unsigned long rflags, save_rflags;

	rflags = vmcs_readl(GUEST_RFLAGS);
	if (to_vmx(vcpu)->rmode.vm86_active) {
		rflags &= RMODE_GUEST_OWNED_EFLAGS_BITS;
		save_rflags = to_vmx(vcpu)->rmode.save_rflags;
		rflags |= save_rflags & ~RMODE_GUEST_OWNED_EFLAGS_BITS;
	}
	return rflags;
}

static void vmx_set_rflags(struct kvm_vcpu *vcpu, unsigned long rflags)
{
	if (to_vmx(vcpu)->rmode.vm86_active) {
		to_vmx(vcpu)->rmode.save_rflags = rflags;
		rflags |= X86_EFLAGS_IOPL | X86_EFLAGS_VM;
	}
	vmcs_writel(GUEST_RFLAGS, rflags);
}

static u32 vmx_get_interrupt_shadow(struct kvm_vcpu *vcpu, int mask)
{
	u32 interruptibility = vmcs_read32(GUEST_INTERRUPTIBILITY_INFO);
	int ret = 0;

	if (interruptibility & GUEST_INTR_STATE_STI)
		ret |= KVM_X86_SHADOW_INT_STI;
	if (interruptibility & GUEST_INTR_STATE_MOV_SS)
		ret |= KVM_X86_SHADOW_INT_MOV_SS;

	return ret & mask;
}

static void vmx_set_interrupt_shadow(struct kvm_vcpu *vcpu, int mask)
{
	u32 interruptibility_old = vmcs_read32(GUEST_INTERRUPTIBILITY_INFO);
	u32 interruptibility = interruptibility_old;

	interruptibility &= ~(GUEST_INTR_STATE_STI | GUEST_INTR_STATE_MOV_SS);

	if (mask & KVM_X86_SHADOW_INT_MOV_SS)
		interruptibility |= GUEST_INTR_STATE_MOV_SS;
	else if (mask & KVM_X86_SHADOW_INT_STI)
		interruptibility |= GUEST_INTR_STATE_STI;

	if ((interruptibility != interruptibility_old))
		vmcs_write32(GUEST_INTERRUPTIBILITY_INFO, interruptibility);
}

static void skip_emulated_instruction(struct kvm_vcpu *vcpu)
{
	unsigned long rip;

	rip = kvm_rip_read(vcpu);
	rip += vmcs_read32(VM_EXIT_INSTRUCTION_LEN);
	kvm_rip_write(vcpu, rip);

	/* skipping an emulated instruction also counts */
	vmx_set_interrupt_shadow(vcpu, 0);
}

static void vmx_clear_hlt(struct kvm_vcpu *vcpu)
{
	/* Ensure that we clear the HLT state in the VMCS.  We don't need to
	 * explicitly skip the instruction because if the HLT state is set, then
	 * the instruction is already executing and RIP has already been
	 * advanced. */
	if (!yield_on_hlt &&
	    vmcs_read32(GUEST_ACTIVITY_STATE) == GUEST_ACTIVITY_HLT)
		vmcs_write32(GUEST_ACTIVITY_STATE, GUEST_ACTIVITY_ACTIVE);
}

/*
 * KVM wants to inject page-faults which it got to the guest. This function
 * checks whether in a nested guest, we need to inject them to L1 or L2.
 * This function assumes it is called with the exit reason in vmcs02 being
 * a #PF exception (this is the only case in which KVM injects a #PF when L2
 * is running).
 */
static int nested_pf_handled(struct kvm_vcpu *vcpu)
{
	struct vmcs_fields *vmcs12 = get_vmcs12_fields(vcpu);

	/* TODO: also check PFEC_MATCH/MASK, not just EB.PF. */
	if (!(vmcs12->exception_bitmap & PF_VECTOR))
		return 0;

	nested_vmx_vmexit(vcpu, false);
	return 1;
}

static void vmx_queue_exception(struct kvm_vcpu *vcpu, unsigned nr,
				bool has_error_code, u32 error_code,
				bool reinject)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);
	u32 intr_info = nr | INTR_INFO_VALID_MASK;

	if (nr == PF_VECTOR && is_guest_mode(vcpu) &&
		nested_pf_handled(vcpu))
		return;

	if (has_error_code) {
		vmcs_write32(VM_ENTRY_EXCEPTION_ERROR_CODE, error_code);
		intr_info |= INTR_INFO_DELIVER_CODE_MASK;
	}

	if (vmx->rmode.vm86_active) {
		if (kvm_inject_realmode_interrupt(vcpu, nr) != EMULATE_DONE)
			kvm_make_request(KVM_REQ_TRIPLE_FAULT, vcpu);
		return;
	}

	if (kvm_exception_is_soft(nr)) {
		vmcs_write32(VM_ENTRY_INSTRUCTION_LEN,
			     vmx->vcpu.arch.event_exit_inst_len);
		intr_info |= INTR_TYPE_SOFT_EXCEPTION;
	} else
		intr_info |= INTR_TYPE_HARD_EXCEPTION;

	vmcs_write32(VM_ENTRY_INTR_INFO_FIELD, intr_info);
	vmx_clear_hlt(vcpu);
}

static bool vmx_rdtscp_supported(void)
{
	return cpu_has_vmx_rdtscp();
}

/*
 * Swap MSR entry in host/guest MSR entry array.
 */
static void move_msr_up(struct vcpu_vmx *vmx, int from, int to)
{
	struct shared_msr_entry tmp;

	tmp = vmx->guest_msrs[to];
	vmx->guest_msrs[to] = vmx->guest_msrs[from];
	vmx->guest_msrs[from] = tmp;
}

/*
 * Set up the vmcs to automatically save and restore system
 * msrs.  Don't touch the 64-bit msrs if the guest is in legacy
 * mode, as fiddling with msrs is very expensive.
 */
static void setup_msrs(struct vcpu_vmx *vmx)
{
	int save_nmsrs, index;
	unsigned long *msr_bitmap;

	vmx_load_host_state(vmx);
	save_nmsrs = 0;
#ifdef CONFIG_X86_64
	if (is_long_mode(&vmx->vcpu)) {
		index = __find_msr_index(vmx, MSR_SYSCALL_MASK);
		if (index >= 0)
			move_msr_up(vmx, index, save_nmsrs++);
		index = __find_msr_index(vmx, MSR_LSTAR);
		if (index >= 0)
			move_msr_up(vmx, index, save_nmsrs++);
		index = __find_msr_index(vmx, MSR_CSTAR);
		if (index >= 0)
			move_msr_up(vmx, index, save_nmsrs++);
		index = __find_msr_index(vmx, MSR_TSC_AUX);
		if (index >= 0 && vmx->rdtscp_enabled)
			move_msr_up(vmx, index, save_nmsrs++);
		/*
		 * MSR_STAR is only needed on long mode guests, and only
		 * if efer.sce is enabled.
		 */
		index = __find_msr_index(vmx, MSR_STAR);
		if ((index >= 0) && (vmx->vcpu.arch.efer & EFER_SCE))
			move_msr_up(vmx, index, save_nmsrs++);
	}
#endif
	index = __find_msr_index(vmx, MSR_EFER);
	if (index >= 0 && update_transition_efer(vmx, index))
		move_msr_up(vmx, index, save_nmsrs++);

	vmx->save_nmsrs = save_nmsrs;

	if (cpu_has_vmx_msr_bitmap()) {
		if (is_long_mode(&vmx->vcpu))
			msr_bitmap = vmx_msr_bitmap_longmode;
		else
			msr_bitmap = vmx_msr_bitmap_legacy;

		vmcs_write64(MSR_BITMAP, __pa(msr_bitmap));
	}
}

/*
 * reads and returns guest's timestamp counter "register"
 * guest_tsc = host_tsc + tsc_offset    -- 21.3
 */
static u64 guest_read_tsc(void)
{
	u64 host_tsc, tsc_offset;

	rdtscll(host_tsc);
	tsc_offset = vmcs_read64(TSC_OFFSET);
	return host_tsc + tsc_offset;
}

/*
 * writes 'offset' into guest's timestamp counter offset register
 */
static void vmx_write_tsc_offset(struct kvm_vcpu *vcpu, u64 offset)
{
	vmcs_write64(TSC_OFFSET, offset);
	if (is_guest_mode(vcpu))
		/*
		 * We are only changing TSC_OFFSET when L2 is running if for
		 * some reason L1 chose not to trap the TSC MSR. Since
		 * prepare_vmcs12() does not copy tsc_offset, we need to also
		 * set the vmcs12 field here.
		 */
		get_vmcs12_fields(vcpu)->tsc_offset = offset -
			to_vmx(vcpu)->nested.vmcs01_fields->tsc_offset;
}

static void vmx_adjust_tsc_offset(struct kvm_vcpu *vcpu, s64 adjustment)
{
	u64 offset = vmcs_read64(TSC_OFFSET);
	vmcs_write64(TSC_OFFSET, offset + adjustment);
	if (is_guest_mode(vcpu))
		get_vmcs12_fields(vcpu)->tsc_offset += adjustment;
}

static bool guest_cpuid_has_vmx(struct kvm_vcpu *vcpu)
{
	struct kvm_cpuid_entry2 *best = kvm_find_cpuid_entry(vcpu, 1, 0);
	return best && (best->ecx & (1 << (X86_FEATURE_VMX & 31)));
}

/*
 * nested_vmx_allowed() checks whether a guest should be allowed to use VMX
 * instructions and MSRs (i.e., nested VMX). Nested VMX is disabled for
 * all guests if the "nested" module option is off, and can also be disabled
 * for a single guest by disabling its VMX cpuid bit.
 */
static inline bool nested_vmx_allowed(struct kvm_vcpu *vcpu)
{
	return nested && guest_cpuid_has_vmx(vcpu);
}

/*
 * If we allow our guest to use VMX instructions (i.e., nested VMX), we should
 * also let it use VMX-specific MSRs.
 * vmx_get_vmx_msr() and vmx_set_vmx_msr() return 1 when we handled a
 * VMX-specific MSR, or 0 when we haven't (and the caller should handle it
 * like all other MSRs).
 */
static int vmx_get_vmx_msr(struct kvm_vcpu *vcpu, u32 msr_index, u64 *pdata)
{
	u64 vmx_msr = 0;
	u32 vmx_msr_high, vmx_msr_low;

	if (!nested_vmx_allowed(vcpu) && msr_index >= MSR_IA32_VMX_BASIC &&
	    msr_index <= MSR_IA32_VMX_TRUE_ENTRY_CTLS) {
		/*
		 * According to the spec, processors which do not support VMX
		 * should throw a #GP(0) when VMX capability MSRs are read.
		 */
		kvm_queue_exception_e(vcpu, GP_VECTOR, 0);
		return 1;
	}

	switch (msr_index) {
	case MSR_IA32_FEATURE_CONTROL:
		*pdata = 0;
		break;
	case MSR_IA32_VMX_BASIC:
		/*
		 * This MSR reports some information about VMX support of the
		 * processor. We should return information about the VMX we
		 * emulate for the guest, and the VMCS structure we give it -
		 * not about the VMX support of the underlying hardware.
		 * However, some capabilities of the underlying hardware are
		 * used directly by our emulation (e.g., the physical address
		 * width), so these are copied from what the hardware reports.
		 */
		*pdata = VMCS12_REVISION | (((u64)sizeof(struct vmcs12)) << 32);
		rdmsrl(MSR_IA32_VMX_BASIC, vmx_msr);
		*pdata |= vmx_msr &
			(VMX_BASIC_64 | VMX_BASIC_MEM_TYPE | VMX_BASIC_INOUT);
		break;
#define CORE2_PINBASED_CTLS_MUST_BE_ONE	0x00000016
	case MSR_IA32_VMX_TRUE_PINBASED_CTLS:
	case MSR_IA32_VMX_PINBASED_CTLS:
		vmx_msr_low  = CORE2_PINBASED_CTLS_MUST_BE_ONE;
		vmx_msr_high = CORE2_PINBASED_CTLS_MUST_BE_ONE |
				PIN_BASED_EXT_INTR_MASK |
				PIN_BASED_NMI_EXITING |
				PIN_BASED_VIRTUAL_NMIS;
		*pdata = vmx_msr_low | ((u64)vmx_msr_high << 32);
		break;
	case MSR_IA32_VMX_TRUE_PROCBASED_CTLS:
	case MSR_IA32_VMX_PROCBASED_CTLS:
		/* This MSR determines which vm-execution controls the L1
		 * hypervisor may ask, or may not ask, to enable. Normally we
		 * can only allow enabling features which the hardware can
		 * support, but we limit ourselves to allowing only known
		 * features that were tested nested. We allow disabling any
		 * feature (even if the hardware can't disable it).
		 */
		rdmsr(MSR_IA32_VMX_PROCBASED_CTLS, vmx_msr_low, vmx_msr_high);

		vmx_msr_low = 0; /* allow disabling any feature */
		vmx_msr_high &= /* do not expose new untested features */
			CPU_BASED_HLT_EXITING | CPU_BASED_CR3_LOAD_EXITING |
			CPU_BASED_CR3_STORE_EXITING | CPU_BASED_USE_IO_BITMAPS |
			CPU_BASED_MOV_DR_EXITING | CPU_BASED_USE_TSC_OFFSETING |
			CPU_BASED_MWAIT_EXITING | CPU_BASED_MONITOR_EXITING |
			CPU_BASED_INVLPG_EXITING | CPU_BASED_TPR_SHADOW |
#ifdef CONFIG_X86_64
			CPU_BASED_CR8_LOAD_EXITING |
			CPU_BASED_CR8_STORE_EXITING |
#endif
			CPU_BASED_ACTIVATE_SECONDARY_CONTROLS;
		*pdata = vmx_msr_low | ((u64)vmx_msr_high << 32);
		break;
	case MSR_IA32_VMX_TRUE_EXIT_CTLS:
	case MSR_IA32_VMX_EXIT_CTLS:
		*pdata = 0;
#ifdef CONFIG_X86_64
		*pdata |= VM_EXIT_HOST_ADDR_SPACE_SIZE;
#endif
		break;
	case MSR_IA32_VMX_TRUE_ENTRY_CTLS:
	case MSR_IA32_VMX_ENTRY_CTLS:
		*pdata = 0;
		break;
	case MSR_IA32_VMX_PROCBASED_CTLS2:
		*pdata = 0;
		if (vm_need_virtualize_apic_accesses(vcpu->kvm))
			*pdata |= SECONDARY_EXEC_VIRTUALIZE_APIC_ACCESSES;
		break;
	case MSR_IA32_VMX_EPT_VPID_CAP:
		/* Currently, no nested ept or nested vpid */
		*pdata = 0;
		break;
	default:
		return 0;
	}

	return 1;
}

static int vmx_set_vmx_msr(struct kvm_vcpu *vcpu, u32 msr_index, u64 data)
{
	if (!nested_vmx_allowed(vcpu))
		return 0;

	/*
	 * according to the spec, "VMX capability MSRs are read-only; an
	 * attempt to write them (with WRMSR) produces a #GP(0).
	 */
	if (msr_index >= MSR_IA32_VMX_BASIC &&
	    msr_index <= MSR_IA32_VMX_TRUE_ENTRY_CTLS) {
		kvm_queue_exception_e(vcpu, GP_VECTOR, 0);
		return 1;
	} else if (msr_index == MSR_IA32_FEATURE_CONTROL)
		/* TODO: the right thing. */
		return 1;
	else
		return 0;
}
/*
 * Reads an msr value (of 'msr_index') into 'pdata'.
 * Returns 0 on success, non-0 otherwise.
 * Assumes vcpu_load() was already called.
 */
static int vmx_get_msr(struct kvm_vcpu *vcpu, u32 msr_index, u64 *pdata)
{
	u64 data;
	struct shared_msr_entry *msr;

	if (!pdata) {
		printk(KERN_ERR "BUG: get_msr called with NULL pdata\n");
		return -EINVAL;
	}

	switch (msr_index) {
#ifdef CONFIG_X86_64
	case MSR_FS_BASE:
		data = vmcs_readl(GUEST_FS_BASE);
		break;
	case MSR_GS_BASE:
		data = vmcs_readl(GUEST_GS_BASE);
		break;
	case MSR_KERNEL_GS_BASE:
		vmx_load_host_state(to_vmx(vcpu));
		data = to_vmx(vcpu)->msr_guest_kernel_gs_base;
		break;
#endif
	case MSR_EFER:
		return kvm_get_msr_common(vcpu, msr_index, pdata);
	case MSR_IA32_TSC:
		data = guest_read_tsc();
		break;
	case MSR_IA32_SYSENTER_CS:
		data = vmcs_read32(GUEST_SYSENTER_CS);
		break;
	case MSR_IA32_SYSENTER_EIP:
		data = vmcs_readl(GUEST_SYSENTER_EIP);
		break;
	case MSR_IA32_SYSENTER_ESP:
		data = vmcs_readl(GUEST_SYSENTER_ESP);
		break;
	case MSR_TSC_AUX:
		if (!to_vmx(vcpu)->rdtscp_enabled)
			return 1;
		/* Otherwise falls through */
	default:
		vmx_load_host_state(to_vmx(vcpu));
		if (vmx_get_vmx_msr(vcpu, msr_index, pdata))
			return 0;
		msr = find_msr_entry(to_vmx(vcpu), msr_index);
		if (msr) {
			vmx_load_host_state(to_vmx(vcpu));
			data = msr->data;
			break;
		}
		return kvm_get_msr_common(vcpu, msr_index, pdata);
	}

	*pdata = data;
	return 0;
}

/*
 * Writes msr value into into the appropriate "register".
 * Returns 0 on success, non-0 otherwise.
 * Assumes vcpu_load() was already called.
 */
static int vmx_set_msr(struct kvm_vcpu *vcpu, u32 msr_index, u64 data)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);
	struct shared_msr_entry *msr;
	int ret = 0;

	switch (msr_index) {
	case MSR_EFER:
		vmx_load_host_state(vmx);
		ret = kvm_set_msr_common(vcpu, msr_index, data);
		break;
#ifdef CONFIG_X86_64
	case MSR_FS_BASE:
		vmcs_writel(GUEST_FS_BASE, data);
		break;
	case MSR_GS_BASE:
		vmcs_writel(GUEST_GS_BASE, data);
		break;
	case MSR_KERNEL_GS_BASE:
		vmx_load_host_state(vmx);
		vmx->msr_guest_kernel_gs_base = data;
		break;
#endif
	case MSR_IA32_SYSENTER_CS:
		vmcs_write32(GUEST_SYSENTER_CS, data);
		break;
	case MSR_IA32_SYSENTER_EIP:
		vmcs_writel(GUEST_SYSENTER_EIP, data);
		break;
	case MSR_IA32_SYSENTER_ESP:
		vmcs_writel(GUEST_SYSENTER_ESP, data);
		break;
	case MSR_IA32_TSC:
		kvm_write_tsc(vcpu, data);
		break;
	case MSR_IA32_CR_PAT:
		if (vmcs_config.vmentry_ctrl & VM_ENTRY_LOAD_IA32_PAT) {
			vmcs_write64(GUEST_IA32_PAT, data);
			vcpu->arch.pat = data;
			break;
		}
		ret = kvm_set_msr_common(vcpu, msr_index, data);
		break;
	case MSR_TSC_AUX:
		if (!vmx->rdtscp_enabled)
			return 1;
		/* Check reserved bit, higher 32 bits should be zero */
		if ((data >> 32) != 0)
			return 1;
		/* Otherwise falls through */
	default:
		if (vmx_set_vmx_msr(vcpu, msr_index, data))
			break;
		msr = find_msr_entry(vmx, msr_index);
		if (msr) {
			vmx_load_host_state(vmx);
			msr->data = data;
			break;
		}
		ret = kvm_set_msr_common(vcpu, msr_index, data);
	}

	return ret;
}

static void vmx_cache_reg(struct kvm_vcpu *vcpu, enum kvm_reg reg)
{
	__set_bit(reg, (unsigned long *)&vcpu->arch.regs_avail);
	switch (reg) {
	case VCPU_REGS_RSP:
		vcpu->arch.regs[VCPU_REGS_RSP] = vmcs_readl(GUEST_RSP);
		break;
	case VCPU_REGS_RIP:
		vcpu->arch.regs[VCPU_REGS_RIP] = vmcs_readl(GUEST_RIP);
		break;
	case VCPU_EXREG_PDPTR:
		if (enable_ept)
			ept_save_pdptrs(vcpu);
		break;
	default:
		break;
	}
}

static void set_guest_debug(struct kvm_vcpu *vcpu, struct kvm_guest_debug *dbg)
{
	if (vcpu->guest_debug & KVM_GUESTDBG_USE_HW_BP)
		vmcs_writel(GUEST_DR7, dbg->arch.debugreg[7]);
	else
		vmcs_writel(GUEST_DR7, vcpu->arch.dr7);

	update_exception_bitmap(vcpu);
}

static __init int cpu_has_kvm_support(void)
{
	return cpu_has_vmx();
}

static __init int vmx_disabled_by_bios(void)
{
	u64 msr;

	rdmsrl(MSR_IA32_FEATURE_CONTROL, msr);
	if (msr & FEATURE_CONTROL_LOCKED) {
		if (!(msr & FEATURE_CONTROL_VMXON_ENABLED_INSIDE_SMX)
			&& tboot_enabled())
			return 1;
		if (!(msr & FEATURE_CONTROL_VMXON_ENABLED_OUTSIDE_SMX)
			&& !tboot_enabled()) {
			printk(KERN_WARNING "kvm: disable TXT in the BIOS or "
				" activate TXT before enabling KVM\n");
			return 1;
		}
	}

	return 0;
	/* locked but not enabled */
}

static void kvm_cpu_vmxon(u64 addr)
{
	asm volatile (ASM_VMX_VMXON_RAX
			: : "a"(&addr), "m"(addr)
			: "memory", "cc");
}

static int hardware_enable(void *garbage)
{
	int cpu = raw_smp_processor_id();
	u64 phys_addr = __pa(per_cpu(vmxarea, cpu));
	u64 old, test_bits;

	if (read_cr4() & X86_CR4_VMXE)
		return -EBUSY;

	INIT_LIST_HEAD(&per_cpu(vcpus_on_cpu, cpu));
	rdmsrl(MSR_IA32_FEATURE_CONTROL, old);

	test_bits = FEATURE_CONTROL_LOCKED;
	test_bits |= FEATURE_CONTROL_VMXON_ENABLED_OUTSIDE_SMX;
	if (tboot_enabled())
		test_bits |= FEATURE_CONTROL_VMXON_ENABLED_INSIDE_SMX;

	if ((old & test_bits) != test_bits) {
		/* enable and lock */
		wrmsrl(MSR_IA32_FEATURE_CONTROL, old | test_bits);
	}
	write_cr4(read_cr4() | X86_CR4_VMXE); /* FIXME: not cpu hotplug safe */

	if (vmm_exclusive) {
		kvm_cpu_vmxon(phys_addr);
		ept_sync_global();
	}

	store_gdt(&__get_cpu_var(host_gdt));

	return 0;
}

static void vmclear_local_vcpus(void)
{
	int cpu = raw_smp_processor_id();
	struct vcpu_vmx *vmx, *n;

	list_for_each_entry_safe(vmx, n, &per_cpu(vcpus_on_cpu, cpu),
				 local_vcpus_link)
		/* TODO: currently, local_vcpus_link is just for L1 VMCSs */
		if (!is_guest_mode(&vmx->vcpu))
			__vcpu_clear(vmx);
}


/* Just like cpu_vmxoff(), but with the __kvm_handle_fault_on_reboot()
 * tricks.
 */
static void kvm_cpu_vmxoff(void)
{
	asm volatile (__ex(ASM_VMX_VMXOFF) : : : "cc");
}

static void hardware_disable(void *garbage)
{
	if (vmm_exclusive) {
		vmclear_local_vcpus();
		kvm_cpu_vmxoff();
	}
	write_cr4(read_cr4() & ~X86_CR4_VMXE);
}

static __init int adjust_vmx_controls(u32 ctl_min, u32 ctl_opt,
				      u32 msr, u32 *result)
{
	u32 vmx_msr_low, vmx_msr_high;
	u32 ctl = ctl_min | ctl_opt;

	rdmsr(msr, vmx_msr_low, vmx_msr_high);

	ctl &= vmx_msr_high; /* bit == 0 in high word ==> must be zero */
	ctl |= vmx_msr_low;  /* bit == 1 in low word  ==> must be one  */

	/* Ensure minimum (required) set of control bits are supported. */
	if (ctl_min & ~ctl)
		return -EIO;

	*result = ctl;
	return 0;
}

static __init bool allow_1_setting(u32 msr, u32 ctl)
{
	u32 vmx_msr_low, vmx_msr_high;

	rdmsr(msr, vmx_msr_low, vmx_msr_high);
	return vmx_msr_high & ctl;
}

static __init int setup_vmcs_config(struct vmcs_config *vmcs_conf)
{
	u32 vmx_msr_low, vmx_msr_high;
	u32 min, opt, min2, opt2;
	u32 _pin_based_exec_control = 0;
	u32 _cpu_based_exec_control = 0;
	u32 _cpu_based_2nd_exec_control = 0;
	u32 _vmexit_control = 0;
	u32 _vmentry_control = 0;

	min = PIN_BASED_EXT_INTR_MASK | PIN_BASED_NMI_EXITING;
	opt = PIN_BASED_VIRTUAL_NMIS;
	if (adjust_vmx_controls(min, opt, MSR_IA32_VMX_PINBASED_CTLS,
				&_pin_based_exec_control) < 0)
		return -EIO;

	min =
#ifdef CONFIG_X86_64
	      CPU_BASED_CR8_LOAD_EXITING |
	      CPU_BASED_CR8_STORE_EXITING |
#endif
	      CPU_BASED_CR3_LOAD_EXITING |
	      CPU_BASED_CR3_STORE_EXITING |
	      CPU_BASED_USE_IO_BITMAPS |
	      CPU_BASED_MOV_DR_EXITING |
	      CPU_BASED_USE_TSC_OFFSETING |
	      CPU_BASED_MWAIT_EXITING |
	      CPU_BASED_MONITOR_EXITING |
	      CPU_BASED_INVLPG_EXITING;

	if (yield_on_hlt)
		min |= CPU_BASED_HLT_EXITING;

	opt = CPU_BASED_TPR_SHADOW |
	      CPU_BASED_USE_MSR_BITMAPS |
	      CPU_BASED_ACTIVATE_SECONDARY_CONTROLS;
	if (adjust_vmx_controls(min, opt, MSR_IA32_VMX_PROCBASED_CTLS,
				&_cpu_based_exec_control) < 0)
		return -EIO;
#ifdef CONFIG_X86_64
	if ((_cpu_based_exec_control & CPU_BASED_TPR_SHADOW))
		_cpu_based_exec_control &= ~CPU_BASED_CR8_LOAD_EXITING &
					   ~CPU_BASED_CR8_STORE_EXITING;
#endif
	if (_cpu_based_exec_control & CPU_BASED_ACTIVATE_SECONDARY_CONTROLS) {
		min2 = 0;
		opt2 = SECONDARY_EXEC_VIRTUALIZE_APIC_ACCESSES |
			SECONDARY_EXEC_WBINVD_EXITING |
			SECONDARY_EXEC_ENABLE_VPID |
			SECONDARY_EXEC_ENABLE_EPT |
			SECONDARY_EXEC_UNRESTRICTED_GUEST |
			SECONDARY_EXEC_PAUSE_LOOP_EXITING |
			SECONDARY_EXEC_RDTSCP;
		if (adjust_vmx_controls(min2, opt2,
					MSR_IA32_VMX_PROCBASED_CTLS2,
					&_cpu_based_2nd_exec_control) < 0)
			return -EIO;
	}
#ifndef CONFIG_X86_64
	if (!(_cpu_based_2nd_exec_control &
				SECONDARY_EXEC_VIRTUALIZE_APIC_ACCESSES))
		_cpu_based_exec_control &= ~CPU_BASED_TPR_SHADOW;
#endif
	if (_cpu_based_2nd_exec_control & SECONDARY_EXEC_ENABLE_EPT) {
		/* CR3 accesses and invlpg don't need to cause VM Exits when EPT
		   enabled */
		_cpu_based_exec_control &= ~(CPU_BASED_CR3_LOAD_EXITING |
					     CPU_BASED_CR3_STORE_EXITING |
					     CPU_BASED_INVLPG_EXITING);
		rdmsr(MSR_IA32_VMX_EPT_VPID_CAP,
		      vmx_capability.ept, vmx_capability.vpid);
	}

	min = 0;
#ifdef CONFIG_X86_64
	min |= VM_EXIT_HOST_ADDR_SPACE_SIZE;
#endif
	opt = VM_EXIT_SAVE_IA32_PAT | VM_EXIT_LOAD_IA32_PAT;
	if (adjust_vmx_controls(min, opt, MSR_IA32_VMX_EXIT_CTLS,
				&_vmexit_control) < 0)
		return -EIO;

	min = 0;
	opt = VM_ENTRY_LOAD_IA32_PAT;
	if (adjust_vmx_controls(min, opt, MSR_IA32_VMX_ENTRY_CTLS,
				&_vmentry_control) < 0)
		return -EIO;

	rdmsr(MSR_IA32_VMX_BASIC, vmx_msr_low, vmx_msr_high);

	/* IA-32 SDM Vol 3B: VMCS size is never greater than 4kB. */
	if ((vmx_msr_high & 0x1fff) > PAGE_SIZE)
		return -EIO;

#ifdef CONFIG_X86_64
	/* IA-32 SDM Vol 3B: 64-bit CPUs always have VMX_BASIC_MSR[48]==0. */
	if (vmx_msr_high & (1u<<16))
		return -EIO;
#endif

	/* Require Write-Back (WB) memory type for VMCS accesses. */
	if (((vmx_msr_high >> 18) & 15) != 6)
		return -EIO;

	vmcs_conf->size = vmx_msr_high & 0x1fff;
	vmcs_conf->order = get_order(vmcs_config.size);
	vmcs_conf->revision_id = vmx_msr_low;

	vmcs_conf->pin_based_exec_ctrl = _pin_based_exec_control;
	vmcs_conf->cpu_based_exec_ctrl = _cpu_based_exec_control;
	vmcs_conf->cpu_based_2nd_exec_ctrl = _cpu_based_2nd_exec_control;
	vmcs_conf->vmexit_ctrl         = _vmexit_control;
	vmcs_conf->vmentry_ctrl        = _vmentry_control;

	cpu_has_load_ia32_efer =
		allow_1_setting(MSR_IA32_VMX_ENTRY_CTLS,
				VM_ENTRY_LOAD_IA32_EFER)
		&& allow_1_setting(MSR_IA32_VMX_EXIT_CTLS,
				   VM_EXIT_LOAD_IA32_EFER);

	return 0;
}

static struct vmcs *alloc_vmcs_cpu(int cpu)
{
	int node = cpu_to_node(cpu);
	struct page *pages;
	struct vmcs *vmcs;

	pages = alloc_pages_exact_node(node, GFP_KERNEL, vmcs_config.order);
	if (!pages)
		return NULL;
	vmcs = page_address(pages);
	memset(vmcs, 0, vmcs_config.size);
	vmcs->revision_id = vmcs_config.revision_id; /* vmcs revision id */
	return vmcs;
}

static struct vmcs *alloc_vmcs(void)
{
	return alloc_vmcs_cpu(raw_smp_processor_id());
}

static void free_vmcs(struct vmcs *vmcs)
{
	free_pages((unsigned long)vmcs, vmcs_config.order);
}

static void free_kvm_area(void)
{
	int cpu;

	for_each_possible_cpu(cpu) {
		free_vmcs(per_cpu(vmxarea, cpu));
		per_cpu(vmxarea, cpu) = NULL;
	}
}

static __init int alloc_kvm_area(void)
{
	int cpu;

	for_each_possible_cpu(cpu) {
		struct vmcs *vmcs;

		vmcs = alloc_vmcs_cpu(cpu);
		if (!vmcs) {
			free_kvm_area();
			return -ENOMEM;
		}

		per_cpu(vmxarea, cpu) = vmcs;
	}
	return 0;
}

static __init int hardware_setup(void)
{
	if (setup_vmcs_config(&vmcs_config) < 0)
		return -EIO;

	if (boot_cpu_has(X86_FEATURE_NX))
		kvm_enable_efer_bits(EFER_NX);

	if (!cpu_has_vmx_vpid())
		enable_vpid = 0;

	if (!cpu_has_vmx_ept() ||
	    !cpu_has_vmx_ept_4levels()) {
		enable_ept = 0;
		enable_unrestricted_guest = 0;
	}

	if (!cpu_has_vmx_unrestricted_guest())
		enable_unrestricted_guest = 0;

	if (!cpu_has_vmx_flexpriority())
		flexpriority_enabled = 0;

	if (!cpu_has_vmx_tpr_shadow())
		kvm_x86_ops->update_cr8_intercept = NULL;

	if (enable_ept && !cpu_has_vmx_ept_2m_page())
		kvm_disable_largepages();

	if (!cpu_has_vmx_ple())
		ple_gap = 0;

	return alloc_kvm_area();
}

static __exit void hardware_unsetup(void)
{
	free_kvm_area();
}

static void fix_pmode_dataseg(int seg, struct kvm_save_segment *save)
{
	struct kvm_vmx_segment_field *sf = &kvm_vmx_segment_fields[seg];

	if (vmcs_readl(sf->base) == save->base && (save->base & AR_S_MASK)) {
		vmcs_write16(sf->selector, save->selector);
		vmcs_writel(sf->base, save->base);
		vmcs_write32(sf->limit, save->limit);
		vmcs_write32(sf->ar_bytes, save->ar);
	} else {
		u32 dpl = (vmcs_read16(sf->selector) & SELECTOR_RPL_MASK)
			<< AR_DPL_SHIFT;
		vmcs_write32(sf->ar_bytes, 0x93 | dpl);
	}
}

static void enter_pmode(struct kvm_vcpu *vcpu)
{
	unsigned long flags;
	struct vcpu_vmx *vmx = to_vmx(vcpu);

	vmx->emulation_required = 1;
	vmx->rmode.vm86_active = 0;

	vmcs_write16(GUEST_TR_SELECTOR, vmx->rmode.tr.selector);
	vmcs_writel(GUEST_TR_BASE, vmx->rmode.tr.base);
	vmcs_write32(GUEST_TR_LIMIT, vmx->rmode.tr.limit);
	vmcs_write32(GUEST_TR_AR_BYTES, vmx->rmode.tr.ar);

	flags = vmcs_readl(GUEST_RFLAGS);
	flags &= RMODE_GUEST_OWNED_EFLAGS_BITS;
	flags |= vmx->rmode.save_rflags & ~RMODE_GUEST_OWNED_EFLAGS_BITS;
	vmcs_writel(GUEST_RFLAGS, flags);

	vmcs_writel(GUEST_CR4, (vmcs_readl(GUEST_CR4) & ~X86_CR4_VME) |
			(vmcs_readl(CR4_READ_SHADOW) & X86_CR4_VME));

	update_exception_bitmap(vcpu);

	if (emulate_invalid_guest_state)
		return;

	fix_pmode_dataseg(VCPU_SREG_ES, &vmx->rmode.es);
	fix_pmode_dataseg(VCPU_SREG_DS, &vmx->rmode.ds);
	fix_pmode_dataseg(VCPU_SREG_GS, &vmx->rmode.gs);
	fix_pmode_dataseg(VCPU_SREG_FS, &vmx->rmode.fs);

	vmcs_write16(GUEST_SS_SELECTOR, 0);
	vmcs_write32(GUEST_SS_AR_BYTES, 0x93);

	vmcs_write16(GUEST_CS_SELECTOR,
		     vmcs_read16(GUEST_CS_SELECTOR) & ~SELECTOR_RPL_MASK);
	vmcs_write32(GUEST_CS_AR_BYTES, 0x9b);
}

static gva_t rmode_tss_base(struct kvm *kvm)
{
	if (!kvm->arch.tss_addr) {
		struct kvm_memslots *slots;
		gfn_t base_gfn;

		slots = kvm_memslots(kvm);
		base_gfn = slots->memslots[0].base_gfn +
				 kvm->memslots->memslots[0].npages - 3;
		return base_gfn << PAGE_SHIFT;
	}
	return kvm->arch.tss_addr;
}

static void fix_rmode_seg(int seg, struct kvm_save_segment *save)
{
	struct kvm_vmx_segment_field *sf = &kvm_vmx_segment_fields[seg];

	save->selector = vmcs_read16(sf->selector);
	save->base = vmcs_readl(sf->base);
	save->limit = vmcs_read32(sf->limit);
	save->ar = vmcs_read32(sf->ar_bytes);
	vmcs_write16(sf->selector, save->base >> 4);
	vmcs_write32(sf->base, save->base & 0xffff0);
	vmcs_write32(sf->limit, 0xffff);
	vmcs_write32(sf->ar_bytes, 0xf3);
	if (save->base & 0xf)
		printk_once(KERN_WARNING "kvm: segment base is not paragraph"
			    " aligned when entering protected mode (seg=%d)",
			    seg);
}

static void enter_rmode(struct kvm_vcpu *vcpu)
{
	unsigned long flags;
	struct vcpu_vmx *vmx = to_vmx(vcpu);

	if (enable_unrestricted_guest)
		return;

	vmx->emulation_required = 1;
	vmx->rmode.vm86_active = 1;

	vmx->rmode.tr.selector = vmcs_read16(GUEST_TR_SELECTOR);
	vmx->rmode.tr.base = vmcs_readl(GUEST_TR_BASE);
	vmcs_writel(GUEST_TR_BASE, rmode_tss_base(vcpu->kvm));

	vmx->rmode.tr.limit = vmcs_read32(GUEST_TR_LIMIT);
	vmcs_write32(GUEST_TR_LIMIT, RMODE_TSS_SIZE - 1);

	vmx->rmode.tr.ar = vmcs_read32(GUEST_TR_AR_BYTES);
	vmcs_write32(GUEST_TR_AR_BYTES, 0x008b);

	flags = vmcs_readl(GUEST_RFLAGS);
	vmx->rmode.save_rflags = flags;

	flags |= X86_EFLAGS_IOPL | X86_EFLAGS_VM;

	vmcs_writel(GUEST_RFLAGS, flags);
	vmcs_writel(GUEST_CR4, vmcs_readl(GUEST_CR4) | X86_CR4_VME);
	update_exception_bitmap(vcpu);

	if (emulate_invalid_guest_state)
		goto continue_rmode;

	vmcs_write16(GUEST_SS_SELECTOR, vmcs_readl(GUEST_SS_BASE) >> 4);
	vmcs_write32(GUEST_SS_LIMIT, 0xffff);
	vmcs_write32(GUEST_SS_AR_BYTES, 0xf3);

	vmcs_write32(GUEST_CS_AR_BYTES, 0xf3);
	vmcs_write32(GUEST_CS_LIMIT, 0xffff);
	if (vmcs_readl(GUEST_CS_BASE) == 0xffff0000)
		vmcs_writel(GUEST_CS_BASE, 0xf0000);
	vmcs_write16(GUEST_CS_SELECTOR, vmcs_readl(GUEST_CS_BASE) >> 4);

	fix_rmode_seg(VCPU_SREG_ES, &vmx->rmode.es);
	fix_rmode_seg(VCPU_SREG_DS, &vmx->rmode.ds);
	fix_rmode_seg(VCPU_SREG_GS, &vmx->rmode.gs);
	fix_rmode_seg(VCPU_SREG_FS, &vmx->rmode.fs);

continue_rmode:
	kvm_mmu_reset_context(vcpu);
	init_rmode(vcpu->kvm);
}

static void vmx_set_efer(struct kvm_vcpu *vcpu, u64 efer)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);
	struct shared_msr_entry *msr = find_msr_entry(vmx, MSR_EFER);

	if (!msr)
		return;

	/*
	 * Force kernel_gs_base reloading before EFER changes, as control
	 * of this msr depends on is_long_mode().
	 */
	vmx_load_host_state(to_vmx(vcpu));
	vcpu->arch.efer = efer;
	if (efer & EFER_LMA) {
		vmcs_write32(VM_ENTRY_CONTROLS,
			     vmcs_read32(VM_ENTRY_CONTROLS) |
			     VM_ENTRY_IA32E_MODE);
		msr->data = efer;
	} else {
		vmcs_write32(VM_ENTRY_CONTROLS,
			     vmcs_read32(VM_ENTRY_CONTROLS) &
			     ~VM_ENTRY_IA32E_MODE);

		msr->data = efer & ~EFER_LME;
	}
	setup_msrs(vmx);
}

#ifdef CONFIG_X86_64

static void enter_lmode(struct kvm_vcpu *vcpu)
{
	u32 guest_tr_ar;

	guest_tr_ar = vmcs_read32(GUEST_TR_AR_BYTES);
	if ((guest_tr_ar & AR_TYPE_MASK) != AR_TYPE_BUSY_64_TSS) {
		printk(KERN_DEBUG "%s: tss fixup for long mode. \n",
		       __func__);
		vmcs_write32(GUEST_TR_AR_BYTES,
			     (guest_tr_ar & ~AR_TYPE_MASK)
			     | AR_TYPE_BUSY_64_TSS);
	}
	vmx_set_efer(vcpu, vcpu->arch.efer | EFER_LMA);
}

static void exit_lmode(struct kvm_vcpu *vcpu)
{
	vmcs_write32(VM_ENTRY_CONTROLS,
		     vmcs_read32(VM_ENTRY_CONTROLS)
		     & ~VM_ENTRY_IA32E_MODE);
	vmx_set_efer(vcpu, vcpu->arch.efer & ~EFER_LMA);
}

#endif

static void vmx_flush_tlb(struct kvm_vcpu *vcpu)
{
	vpid_sync_context(to_vmx(vcpu));
	if (enable_ept) {
		if (!VALID_PAGE(vcpu->arch.mmu.root_hpa))
			return;
		ept_sync_context(construct_eptp(vcpu->arch.mmu.root_hpa));
	}
}

static void vmx_decache_cr0_guest_bits(struct kvm_vcpu *vcpu)
{
	ulong cr0_guest_owned_bits = vcpu->arch.cr0_guest_owned_bits;

	vcpu->arch.cr0 &= ~cr0_guest_owned_bits;
	vcpu->arch.cr0 |= vmcs_readl(GUEST_CR0) & cr0_guest_owned_bits;
}

static void vmx_decache_cr3(struct kvm_vcpu *vcpu)
{
	if (enable_ept && is_paging(vcpu))
		vcpu->arch.cr3 = vmcs_readl(GUEST_CR3);
	__set_bit(VCPU_EXREG_CR3, (ulong *)&vcpu->arch.regs_avail);
}

static void vmx_decache_cr4_guest_bits(struct kvm_vcpu *vcpu)
{
	ulong cr4_guest_owned_bits = vcpu->arch.cr4_guest_owned_bits;

	vcpu->arch.cr4 &= ~cr4_guest_owned_bits;
	vcpu->arch.cr4 |= vmcs_readl(GUEST_CR4) & cr4_guest_owned_bits;
}

static void ept_load_pdptrs(struct kvm_vcpu *vcpu)
{
	if (!test_bit(VCPU_EXREG_PDPTR,
		      (unsigned long *)&vcpu->arch.regs_dirty))
		return;

	if (is_paging(vcpu) && is_pae(vcpu) && !is_long_mode(vcpu)) {
		vmcs_write64(GUEST_PDPTR0, vcpu->arch.mmu.pdptrs[0]);
		vmcs_write64(GUEST_PDPTR1, vcpu->arch.mmu.pdptrs[1]);
		vmcs_write64(GUEST_PDPTR2, vcpu->arch.mmu.pdptrs[2]);
		vmcs_write64(GUEST_PDPTR3, vcpu->arch.mmu.pdptrs[3]);
	}
}

static void ept_save_pdptrs(struct kvm_vcpu *vcpu)
{
	if (is_paging(vcpu) && is_pae(vcpu) && !is_long_mode(vcpu)) {
		vcpu->arch.mmu.pdptrs[0] = vmcs_read64(GUEST_PDPTR0);
		vcpu->arch.mmu.pdptrs[1] = vmcs_read64(GUEST_PDPTR1);
		vcpu->arch.mmu.pdptrs[2] = vmcs_read64(GUEST_PDPTR2);
		vcpu->arch.mmu.pdptrs[3] = vmcs_read64(GUEST_PDPTR3);
	}

	__set_bit(VCPU_EXREG_PDPTR,
		  (unsigned long *)&vcpu->arch.regs_avail);
	__set_bit(VCPU_EXREG_PDPTR,
		  (unsigned long *)&vcpu->arch.regs_dirty);
}

static int vmx_set_cr4(struct kvm_vcpu *vcpu, unsigned long cr4);

static void ept_update_paging_mode_cr0(unsigned long *hw_cr0,
					unsigned long cr0,
					struct kvm_vcpu *vcpu)
{
	vmx_decache_cr3(vcpu);
	if (!(cr0 & X86_CR0_PG)) {
		/* From paging/starting to nonpaging */
		vmcs_write32(CPU_BASED_VM_EXEC_CONTROL,
			     vmcs_read32(CPU_BASED_VM_EXEC_CONTROL) |
			     (CPU_BASED_CR3_LOAD_EXITING |
			      CPU_BASED_CR3_STORE_EXITING));
		vcpu->arch.cr0 = cr0;
		vmx_set_cr4(vcpu, kvm_read_cr4(vcpu));
	} else if (!is_paging(vcpu)) {
		/* From nonpaging to paging */
		vmcs_write32(CPU_BASED_VM_EXEC_CONTROL,
			     vmcs_read32(CPU_BASED_VM_EXEC_CONTROL) &
			     ~(CPU_BASED_CR3_LOAD_EXITING |
			       CPU_BASED_CR3_STORE_EXITING));
		vcpu->arch.cr0 = cr0;
		vmx_set_cr4(vcpu, kvm_read_cr4(vcpu));
	}

	if (!(cr0 & X86_CR0_WP))
		*hw_cr0 &= ~X86_CR0_WP;
}

static void vmx_set_cr0(struct kvm_vcpu *vcpu, unsigned long cr0)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);
	unsigned long hw_cr0;

	if (enable_unrestricted_guest)
		hw_cr0 = (cr0 & ~KVM_GUEST_CR0_MASK_UNRESTRICTED_GUEST)
			| KVM_VM_CR0_ALWAYS_ON_UNRESTRICTED_GUEST;
	else
		hw_cr0 = (cr0 & ~KVM_GUEST_CR0_MASK) | KVM_VM_CR0_ALWAYS_ON;

	if (vmx->rmode.vm86_active && (cr0 & X86_CR0_PE))
		enter_pmode(vcpu);

	if (!vmx->rmode.vm86_active && !(cr0 & X86_CR0_PE))
		enter_rmode(vcpu);

#ifdef CONFIG_X86_64
	if (vcpu->arch.efer & EFER_LME) {
		if (!is_paging(vcpu) && (cr0 & X86_CR0_PG))
			enter_lmode(vcpu);
		if (is_paging(vcpu) && !(cr0 & X86_CR0_PG))
			exit_lmode(vcpu);
	}
#endif

	if (enable_ept)
		ept_update_paging_mode_cr0(&hw_cr0, cr0, vcpu);

	if (!vcpu->fpu_active)
		hw_cr0 |= X86_CR0_TS | X86_CR0_MP;

	vmcs_writel(CR0_READ_SHADOW, cr0);
	vmcs_writel(GUEST_CR0, hw_cr0);
	vcpu->arch.cr0 = cr0;
}

static u64 construct_eptp(unsigned long root_hpa)
{
	u64 eptp;

	/* TODO write the value reading from MSR */
	eptp = VMX_EPT_DEFAULT_MT |
		VMX_EPT_DEFAULT_GAW << VMX_EPT_GAW_EPTP_SHIFT;
	eptp |= (root_hpa & PAGE_MASK);

	return eptp;
}

static void vmx_set_cr3(struct kvm_vcpu *vcpu, unsigned long cr3)
{
	unsigned long guest_cr3;
	u64 eptp;

	guest_cr3 = cr3;
	if (enable_ept) {
		eptp = construct_eptp(cr3);
		vmcs_write64(EPT_POINTER, eptp);
		guest_cr3 = is_paging(vcpu) ? kvm_read_cr3(vcpu) :
			vcpu->kvm->arch.ept_identity_map_addr;
		ept_load_pdptrs(vcpu);
	}

	vmx_flush_tlb(vcpu);
	vmcs_writel(GUEST_CR3, guest_cr3);
}

static int vmx_set_cr4(struct kvm_vcpu *vcpu, unsigned long cr4)
{
	unsigned long hw_cr4 = cr4 | (to_vmx(vcpu)->rmode.vm86_active ?
		    KVM_RMODE_VM_CR4_ALWAYS_ON : KVM_PMODE_VM_CR4_ALWAYS_ON);

	if (cr4 & X86_CR4_VMXE) {
		/*
		 * To use VMXON (and later other VMX instructions), a guest
		 * must first be able to turn on cr4.VMXE (see handle_vmxon()).
		 * So basically the check on whether to allow nested VMX
		 * is here.
		 */
		if (!nested_vmx_allowed(vcpu))
			return 1;
	} else if (to_vmx(vcpu)->nested.vmxon)
		return 1;

	vcpu->arch.cr4 = cr4;
	if (enable_ept) {
		if (!is_paging(vcpu)) {
			hw_cr4 &= ~X86_CR4_PAE;
			hw_cr4 |= X86_CR4_PSE;
		} else if (!(cr4 & X86_CR4_PAE)) {
			hw_cr4 &= ~X86_CR4_PAE;
		}
	}

	vmcs_writel(CR4_READ_SHADOW, cr4);
	vmcs_writel(GUEST_CR4, hw_cr4);
	return 0;
}

static void vmx_get_segment(struct kvm_vcpu *vcpu,
			    struct kvm_segment *var, int seg)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);
	struct kvm_vmx_segment_field *sf = &kvm_vmx_segment_fields[seg];
	struct kvm_save_segment *save;
	u32 ar;

	if (vmx->rmode.vm86_active
	    && (seg == VCPU_SREG_TR || seg == VCPU_SREG_ES
		|| seg == VCPU_SREG_DS || seg == VCPU_SREG_FS
		|| seg == VCPU_SREG_GS)
	    && !emulate_invalid_guest_state) {
		switch (seg) {
		case VCPU_SREG_TR: save = &vmx->rmode.tr; break;
		case VCPU_SREG_ES: save = &vmx->rmode.es; break;
		case VCPU_SREG_DS: save = &vmx->rmode.ds; break;
		case VCPU_SREG_FS: save = &vmx->rmode.fs; break;
		case VCPU_SREG_GS: save = &vmx->rmode.gs; break;
		default: BUG();
		}
		var->selector = save->selector;
		var->base = save->base;
		var->limit = save->limit;
		ar = save->ar;
		if (seg == VCPU_SREG_TR
		    || var->selector == vmcs_read16(sf->selector))
			goto use_saved_rmode_seg;
	}
	var->base = vmcs_readl(sf->base);
	var->limit = vmcs_read32(sf->limit);
	var->selector = vmcs_read16(sf->selector);
	ar = vmcs_read32(sf->ar_bytes);
use_saved_rmode_seg:
	if ((ar & AR_UNUSABLE_MASK) && !emulate_invalid_guest_state)
		ar = 0;
	var->type = ar & 15;
	var->s = (ar >> 4) & 1;
	var->dpl = (ar >> 5) & 3;
	var->present = (ar >> 7) & 1;
	var->avl = (ar >> 12) & 1;
	var->l = (ar >> 13) & 1;
	var->db = (ar >> 14) & 1;
	var->g = (ar >> 15) & 1;
	var->unusable = (ar >> 16) & 1;
}

static u64 vmx_get_segment_base(struct kvm_vcpu *vcpu, int seg)
{
	struct kvm_vmx_segment_field *sf = &kvm_vmx_segment_fields[seg];
	struct kvm_segment s;

	if (to_vmx(vcpu)->rmode.vm86_active) {
		vmx_get_segment(vcpu, &s, seg);
		return s.base;
	}
	return vmcs_readl(sf->base);
}

static int vmx_get_cpl(struct kvm_vcpu *vcpu)
{
	if (!is_protmode(vcpu))
		return 0;

	if (vmx_get_rflags(vcpu) & X86_EFLAGS_VM) /* if virtual 8086 */
		return 3;

	return vmcs_read16(GUEST_CS_SELECTOR) & 3;
}

static u32 vmx_segment_access_rights(struct kvm_segment *var)
{
	u32 ar;

	if (var->unusable)
		ar = 1 << 16;
	else {
		ar = var->type & 15;
		ar |= (var->s & 1) << 4;
		ar |= (var->dpl & 3) << 5;
		ar |= (var->present & 1) << 7;
		ar |= (var->avl & 1) << 12;
		ar |= (var->l & 1) << 13;
		ar |= (var->db & 1) << 14;
		ar |= (var->g & 1) << 15;
	}
	if (ar == 0) /* a 0 value means unusable */
		ar = AR_UNUSABLE_MASK;

	return ar;
}

static void vmx_set_segment(struct kvm_vcpu *vcpu,
			    struct kvm_segment *var, int seg)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);
	struct kvm_vmx_segment_field *sf = &kvm_vmx_segment_fields[seg];
	u32 ar;

	if (vmx->rmode.vm86_active && seg == VCPU_SREG_TR) {
		vmx->rmode.tr.selector = var->selector;
		vmx->rmode.tr.base = var->base;
		vmx->rmode.tr.limit = var->limit;
		vmx->rmode.tr.ar = vmx_segment_access_rights(var);
		return;
	}
	vmcs_writel(sf->base, var->base);
	vmcs_write32(sf->limit, var->limit);
	vmcs_write16(sf->selector, var->selector);
	if (vmx->rmode.vm86_active && var->s) {
		/*
		 * Hack real-mode segments into vm86 compatibility.
		 */
		if (var->base == 0xffff0000 && var->selector == 0xf000)
			vmcs_writel(sf->base, 0xf0000);
		ar = 0xf3;
	} else
		ar = vmx_segment_access_rights(var);

	/*
	 *   Fix the "Accessed" bit in AR field of segment registers for older
	 * qemu binaries.
	 *   IA32 arch specifies that at the time of processor reset the
	 * "Accessed" bit in the AR field of segment registers is 1. And qemu
	 * is setting it to 0 in the usedland code. This causes invalid guest
	 * state vmexit when "unrestricted guest" mode is turned on.
	 *    Fix for this setup issue in cpu_reset is being pushed in the qemu
	 * tree. Newer qemu binaries with that qemu fix would not need this
	 * kvm hack.
	 */
	if (enable_unrestricted_guest && (seg != VCPU_SREG_LDTR))
		ar |= 0x1; /* Accessed */

	vmcs_write32(sf->ar_bytes, ar);
}

static void vmx_get_cs_db_l_bits(struct kvm_vcpu *vcpu, int *db, int *l)
{
	u32 ar = vmcs_read32(GUEST_CS_AR_BYTES);

	*db = (ar >> 14) & 1;
	*l = (ar >> 13) & 1;
}

static void vmx_get_idt(struct kvm_vcpu *vcpu, struct desc_ptr *dt)
{
	dt->size = vmcs_read32(GUEST_IDTR_LIMIT);
	dt->address = vmcs_readl(GUEST_IDTR_BASE);
}

static void vmx_set_idt(struct kvm_vcpu *vcpu, struct desc_ptr *dt)
{
	vmcs_write32(GUEST_IDTR_LIMIT, dt->size);
	vmcs_writel(GUEST_IDTR_BASE, dt->address);
}

static void vmx_get_gdt(struct kvm_vcpu *vcpu, struct desc_ptr *dt)
{
	dt->size = vmcs_read32(GUEST_GDTR_LIMIT);
	dt->address = vmcs_readl(GUEST_GDTR_BASE);
}

static void vmx_set_gdt(struct kvm_vcpu *vcpu, struct desc_ptr *dt)
{
	vmcs_write32(GUEST_GDTR_LIMIT, dt->size);
	vmcs_writel(GUEST_GDTR_BASE, dt->address);
}

static bool rmode_segment_valid(struct kvm_vcpu *vcpu, int seg)
{
	struct kvm_segment var;
	u32 ar;

	vmx_get_segment(vcpu, &var, seg);
	ar = vmx_segment_access_rights(&var);

	if (var.base != (var.selector << 4))
		return false;
	if (var.limit != 0xffff)
		return false;
	if (ar != 0xf3)
		return false;

	return true;
}

static bool code_segment_valid(struct kvm_vcpu *vcpu)
{
	struct kvm_segment cs;
	unsigned int cs_rpl;

	vmx_get_segment(vcpu, &cs, VCPU_SREG_CS);
	cs_rpl = cs.selector & SELECTOR_RPL_MASK;

	if (cs.unusable)
		return false;
	if (~cs.type & (AR_TYPE_CODE_MASK|AR_TYPE_ACCESSES_MASK))
		return false;
	if (!cs.s)
		return false;
	if (cs.type & AR_TYPE_WRITEABLE_MASK) {
		if (cs.dpl > cs_rpl)
			return false;
	} else {
		if (cs.dpl != cs_rpl)
			return false;
	}
	if (!cs.present)
		return false;

	/* TODO: Add Reserved field check, this'll require a new member in the kvm_segment_field structure */
	return true;
}

static bool stack_segment_valid(struct kvm_vcpu *vcpu)
{
	struct kvm_segment ss;
	unsigned int ss_rpl;

	vmx_get_segment(vcpu, &ss, VCPU_SREG_SS);
	ss_rpl = ss.selector & SELECTOR_RPL_MASK;

	if (ss.unusable)
		return true;
	if (ss.type != 3 && ss.type != 7)
		return false;
	if (!ss.s)
		return false;
	if (ss.dpl != ss_rpl) /* DPL != RPL */
		return false;
	if (!ss.present)
		return false;

	return true;
}

static bool data_segment_valid(struct kvm_vcpu *vcpu, int seg)
{
	struct kvm_segment var;
	unsigned int rpl;

	vmx_get_segment(vcpu, &var, seg);
	rpl = var.selector & SELECTOR_RPL_MASK;

	if (var.unusable)
		return true;
	if (!var.s)
		return false;
	if (!var.present)
		return false;
	if (~var.type & (AR_TYPE_CODE_MASK|AR_TYPE_WRITEABLE_MASK)) {
		if (var.dpl < rpl) /* DPL < RPL */
			return false;
	}

	/* TODO: Add other members to kvm_segment_field to allow checking for other access
	 * rights flags
	 */
	return true;
}

static bool tr_valid(struct kvm_vcpu *vcpu)
{
	struct kvm_segment tr;

	vmx_get_segment(vcpu, &tr, VCPU_SREG_TR);

	if (tr.unusable)
		return false;
	if (tr.selector & SELECTOR_TI_MASK)	/* TI = 1 */
		return false;
	if (tr.type != 3 && tr.type != 11) /* TODO: Check if guest is in IA32e mode */
		return false;
	if (!tr.present)
		return false;

	return true;
}

static bool ldtr_valid(struct kvm_vcpu *vcpu)
{
	struct kvm_segment ldtr;

	vmx_get_segment(vcpu, &ldtr, VCPU_SREG_LDTR);

	if (ldtr.unusable)
		return true;
	if (ldtr.selector & SELECTOR_TI_MASK)	/* TI = 1 */
		return false;
	if (ldtr.type != 2)
		return false;
	if (!ldtr.present)
		return false;

	return true;
}

static bool cs_ss_rpl_check(struct kvm_vcpu *vcpu)
{
	struct kvm_segment cs, ss;

	vmx_get_segment(vcpu, &cs, VCPU_SREG_CS);
	vmx_get_segment(vcpu, &ss, VCPU_SREG_SS);

	return ((cs.selector & SELECTOR_RPL_MASK) ==
		 (ss.selector & SELECTOR_RPL_MASK));
}

/*
 * Check if guest state is valid. Returns true if valid, false if
 * not.
 * We assume that registers are always usable
 */
static bool guest_state_valid(struct kvm_vcpu *vcpu)
{
	/* real mode guest state checks */
	if (!is_protmode(vcpu)) {
		if (!rmode_segment_valid(vcpu, VCPU_SREG_CS))
			return false;
		if (!rmode_segment_valid(vcpu, VCPU_SREG_SS))
			return false;
		if (!rmode_segment_valid(vcpu, VCPU_SREG_DS))
			return false;
		if (!rmode_segment_valid(vcpu, VCPU_SREG_ES))
			return false;
		if (!rmode_segment_valid(vcpu, VCPU_SREG_FS))
			return false;
		if (!rmode_segment_valid(vcpu, VCPU_SREG_GS))
			return false;
	} else {
	/* protected mode guest state checks */
		if (!cs_ss_rpl_check(vcpu))
			return false;
		if (!code_segment_valid(vcpu))
			return false;
		if (!stack_segment_valid(vcpu))
			return false;
		if (!data_segment_valid(vcpu, VCPU_SREG_DS))
			return false;
		if (!data_segment_valid(vcpu, VCPU_SREG_ES))
			return false;
		if (!data_segment_valid(vcpu, VCPU_SREG_FS))
			return false;
		if (!data_segment_valid(vcpu, VCPU_SREG_GS))
			return false;
		if (!tr_valid(vcpu))
			return false;
		if (!ldtr_valid(vcpu))
			return false;
	}
	/* TODO:
	 * - Add checks on RIP
	 * - Add checks on RFLAGS
	 */

	return true;
}

static int init_rmode_tss(struct kvm *kvm)
{
	gfn_t fn = rmode_tss_base(kvm) >> PAGE_SHIFT;
	u16 data = 0;
	int ret = 0;
	int r;

	r = kvm_clear_guest_page(kvm, fn, 0, PAGE_SIZE);
	if (r < 0)
		goto out;
	data = TSS_BASE_SIZE + TSS_REDIRECTION_SIZE;
	r = kvm_write_guest_page(kvm, fn++, &data,
			TSS_IOPB_BASE_OFFSET, sizeof(u16));
	if (r < 0)
		goto out;
	r = kvm_clear_guest_page(kvm, fn++, 0, PAGE_SIZE);
	if (r < 0)
		goto out;
	r = kvm_clear_guest_page(kvm, fn, 0, PAGE_SIZE);
	if (r < 0)
		goto out;
	data = ~0;
	r = kvm_write_guest_page(kvm, fn, &data,
				 RMODE_TSS_SIZE - 2 * PAGE_SIZE - 1,
				 sizeof(u8));
	if (r < 0)
		goto out;

	ret = 1;
out:
	return ret;
}

static int init_rmode_identity_map(struct kvm *kvm)
{
	int i, r, ret;
	pfn_t identity_map_pfn;
	u32 tmp;

	if (!enable_ept)
		return 1;
	if (unlikely(!kvm->arch.ept_identity_pagetable)) {
		printk(KERN_ERR "EPT: identity-mapping pagetable "
			"haven't been allocated!\n");
		return 0;
	}
	if (likely(kvm->arch.ept_identity_pagetable_done))
		return 1;
	ret = 0;
	identity_map_pfn = kvm->arch.ept_identity_map_addr >> PAGE_SHIFT;
	r = kvm_clear_guest_page(kvm, identity_map_pfn, 0, PAGE_SIZE);
	if (r < 0)
		goto out;
	/* Set up identity-mapping pagetable for EPT in real mode */
	for (i = 0; i < PT32_ENT_PER_PAGE; i++) {
		tmp = (i << 22) + (_PAGE_PRESENT | _PAGE_RW | _PAGE_USER |
			_PAGE_ACCESSED | _PAGE_DIRTY | _PAGE_PSE);
		r = kvm_write_guest_page(kvm, identity_map_pfn,
				&tmp, i * sizeof(tmp), sizeof(tmp));
		if (r < 0)
			goto out;
	}
	kvm->arch.ept_identity_pagetable_done = true;
	ret = 1;
out:
	return ret;
}

static void seg_setup(int seg)
{
	struct kvm_vmx_segment_field *sf = &kvm_vmx_segment_fields[seg];
	unsigned int ar;

	vmcs_write16(sf->selector, 0);
	vmcs_writel(sf->base, 0);
	vmcs_write32(sf->limit, 0xffff);
	if (enable_unrestricted_guest) {
		ar = 0x93;
		if (seg == VCPU_SREG_CS)
			ar |= 0x08; /* code segment */
	} else
		ar = 0xf3;

	vmcs_write32(sf->ar_bytes, ar);
}

static int alloc_apic_access_page(struct kvm *kvm)
{
	struct kvm_userspace_memory_region kvm_userspace_mem;
	int r = 0;

	mutex_lock(&kvm->slots_lock);
	if (kvm->arch.apic_access_page)
		goto out;
	kvm_userspace_mem.slot = APIC_ACCESS_PAGE_PRIVATE_MEMSLOT;
	kvm_userspace_mem.flags = 0;
	kvm_userspace_mem.guest_phys_addr = 0xfee00000ULL;
	kvm_userspace_mem.memory_size = PAGE_SIZE;
	r = __kvm_set_memory_region(kvm, &kvm_userspace_mem, 0);
	if (r)
		goto out;

	kvm->arch.apic_access_page = gfn_to_page(kvm, 0xfee00);
out:
	mutex_unlock(&kvm->slots_lock);
	return r;
}

static int alloc_identity_pagetable(struct kvm *kvm)
{
	struct kvm_userspace_memory_region kvm_userspace_mem;
	int r = 0;

	mutex_lock(&kvm->slots_lock);
	if (kvm->arch.ept_identity_pagetable)
		goto out;
	kvm_userspace_mem.slot = IDENTITY_PAGETABLE_PRIVATE_MEMSLOT;
	kvm_userspace_mem.flags = 0;
	kvm_userspace_mem.guest_phys_addr =
		kvm->arch.ept_identity_map_addr;
	kvm_userspace_mem.memory_size = PAGE_SIZE;
	r = __kvm_set_memory_region(kvm, &kvm_userspace_mem, 0);
	if (r)
		goto out;

	kvm->arch.ept_identity_pagetable = gfn_to_page(kvm,
			kvm->arch.ept_identity_map_addr >> PAGE_SHIFT);
out:
	mutex_unlock(&kvm->slots_lock);
	return r;
}

static void allocate_vpid(struct vcpu_vmx *vmx)
{
	int vpid;

	vmx->vpid = 0;
	if (!enable_vpid)
		return;
	spin_lock(&vmx_vpid_lock);
	vpid = find_first_zero_bit(vmx_vpid_bitmap, VMX_NR_VPIDS);
	if (vpid < VMX_NR_VPIDS) {
		vmx->vpid = vpid;
		__set_bit(vpid, vmx_vpid_bitmap);
	}
	spin_unlock(&vmx_vpid_lock);
}

static void free_vpid(struct vcpu_vmx *vmx)
{
	if (!enable_vpid)
		return;
	spin_lock(&vmx_vpid_lock);
	if (vmx->vpid != 0)
		__clear_bit(vmx->vpid, vmx_vpid_bitmap);
	spin_unlock(&vmx_vpid_lock);
}

static void __vmx_disable_intercept_for_msr(unsigned long *msr_bitmap, u32 msr)
{
	int f = sizeof(unsigned long);

	if (!cpu_has_vmx_msr_bitmap())
		return;

	/*
	 * See Intel PRM Vol. 3, 20.6.9 (MSR-Bitmap Address). Early manuals
	 * have the write-low and read-high bitmap offsets the wrong way round.
	 * We can control MSRs 0x00000000-0x00001fff and 0xc0000000-0xc0001fff.
	 */
	if (msr <= 0x1fff) {
		__clear_bit(msr, msr_bitmap + 0x000 / f); /* read-low */
		__clear_bit(msr, msr_bitmap + 0x800 / f); /* write-low */
	} else if ((msr >= 0xc0000000) && (msr <= 0xc0001fff)) {
		msr &= 0x1fff;
		__clear_bit(msr, msr_bitmap + 0x400 / f); /* read-high */
		__clear_bit(msr, msr_bitmap + 0xc00 / f); /* write-high */
	}
}

static void vmx_disable_intercept_for_msr(u32 msr, bool longmode_only)
{
	if (!longmode_only)
		__vmx_disable_intercept_for_msr(vmx_msr_bitmap_legacy, msr);
	__vmx_disable_intercept_for_msr(vmx_msr_bitmap_longmode, msr);
}

/*
 * Sets up the vmcs for emulated real mode.
 */
static int vmx_vcpu_setup(struct vcpu_vmx *vmx)
{
	u32 host_sysenter_cs, msr_low, msr_high;
	u32 junk;
	u64 host_pat;
	unsigned long a;
	struct desc_ptr dt;
	int i;
	unsigned long kvm_vmx_return;
	u32 exec_control;

	/* I/O */
	vmcs_write64(IO_BITMAP_A, __pa(vmx_io_bitmap_a));
	vmcs_write64(IO_BITMAP_B, __pa(vmx_io_bitmap_b));

	if (cpu_has_vmx_msr_bitmap())
		vmcs_write64(MSR_BITMAP, __pa(vmx_msr_bitmap_legacy));

	vmcs_write64(VMCS_LINK_POINTER, -1ull); /* 22.3.1.5 */

	/* Control */
	vmcs_write32(PIN_BASED_VM_EXEC_CONTROL,
		vmcs_config.pin_based_exec_ctrl);

	exec_control = vmcs_config.cpu_based_exec_ctrl;
	if (!vm_need_tpr_shadow(vmx->vcpu.kvm)) {
		exec_control &= ~CPU_BASED_TPR_SHADOW;
#ifdef CONFIG_X86_64
		exec_control |= CPU_BASED_CR8_STORE_EXITING |
				CPU_BASED_CR8_LOAD_EXITING;
#endif
	}
	if (!enable_ept)
		exec_control |= CPU_BASED_CR3_STORE_EXITING |
				CPU_BASED_CR3_LOAD_EXITING  |
				CPU_BASED_INVLPG_EXITING;
	vmcs_write32(CPU_BASED_VM_EXEC_CONTROL, exec_control);

	if (cpu_has_secondary_exec_ctrls()) {
		exec_control = vmcs_config.cpu_based_2nd_exec_ctrl;
		if (!vm_need_virtualize_apic_accesses(vmx->vcpu.kvm))
			exec_control &=
				~SECONDARY_EXEC_VIRTUALIZE_APIC_ACCESSES;
		if (vmx->vpid == 0)
			exec_control &= ~SECONDARY_EXEC_ENABLE_VPID;
		if (!enable_ept) {
			exec_control &= ~SECONDARY_EXEC_ENABLE_EPT;
			enable_unrestricted_guest = 0;
		}
		if (!enable_unrestricted_guest)
			exec_control &= ~SECONDARY_EXEC_UNRESTRICTED_GUEST;
		if (!ple_gap)
			exec_control &= ~SECONDARY_EXEC_PAUSE_LOOP_EXITING;
		vmcs_write32(SECONDARY_VM_EXEC_CONTROL, exec_control);
	}

	if (ple_gap) {
		vmcs_write32(PLE_GAP, ple_gap);
		vmcs_write32(PLE_WINDOW, ple_window);
	}

	vmcs_write32(PAGE_FAULT_ERROR_CODE_MASK, !!bypass_guest_pf);
	vmcs_write32(PAGE_FAULT_ERROR_CODE_MATCH, !!bypass_guest_pf);
	vmcs_write32(CR3_TARGET_COUNT, 0);           /* 22.2.1 */

	vmcs_writel(HOST_CR0, read_cr0() | X86_CR0_TS);  /* 22.2.3 */
	vmcs_writel(HOST_CR4, read_cr4());  /* 22.2.3, 22.2.5 */
	vmcs_writel(HOST_CR3, read_cr3());  /* 22.2.3  FIXME: shadow tables */

	vmcs_write16(HOST_CS_SELECTOR, __KERNEL_CS);  /* 22.2.4 */
	vmcs_write16(HOST_DS_SELECTOR, __KERNEL_DS);  /* 22.2.4 */
	vmcs_write16(HOST_ES_SELECTOR, __KERNEL_DS);  /* 22.2.4 */
	vmcs_write16(HOST_FS_SELECTOR, 0);            /* 22.2.4 */
	vmcs_write16(HOST_GS_SELECTOR, 0);            /* 22.2.4 */
	vmcs_write16(HOST_SS_SELECTOR, __KERNEL_DS);  /* 22.2.4 */
#ifdef CONFIG_X86_64
	rdmsrl(MSR_FS_BASE, a);
	vmcs_writel(HOST_FS_BASE, a); /* 22.2.4 */
	rdmsrl(MSR_GS_BASE, a);
	vmcs_writel(HOST_GS_BASE, a); /* 22.2.4 */
#else
	vmcs_writel(HOST_FS_BASE, 0); /* 22.2.4 */
	vmcs_writel(HOST_GS_BASE, 0); /* 22.2.4 */
#endif

	vmcs_write16(HOST_TR_SELECTOR, GDT_ENTRY_TSS*8);  /* 22.2.4 */

	native_store_idt(&dt);
	vmcs_writel(HOST_IDTR_BASE, dt.address);   /* 22.2.4 */

	asm("mov $.Lkvm_vmx_return, %0" : "=r"(kvm_vmx_return));
	vmcs_writel(HOST_RIP, kvm_vmx_return); /* 22.2.5 */
	vmcs_write32(VM_EXIT_MSR_STORE_COUNT, 0);
	vmcs_write32(VM_EXIT_MSR_LOAD_COUNT, 0);
	vmcs_write64(VM_EXIT_MSR_LOAD_ADDR, __pa(vmx->msr_autoload.host));
	vmcs_write32(VM_ENTRY_MSR_LOAD_COUNT, 0);
	vmcs_write64(VM_ENTRY_MSR_LOAD_ADDR, __pa(vmx->msr_autoload.guest));

	rdmsr(MSR_IA32_SYSENTER_CS, host_sysenter_cs, junk);
	vmcs_write32(HOST_IA32_SYSENTER_CS, host_sysenter_cs);
	rdmsrl(MSR_IA32_SYSENTER_ESP, a);
	vmcs_writel(HOST_IA32_SYSENTER_ESP, a);   /* 22.2.3 */
	rdmsrl(MSR_IA32_SYSENTER_EIP, a);
	vmcs_writel(HOST_IA32_SYSENTER_EIP, a);   /* 22.2.3 */

	if (vmcs_config.vmexit_ctrl & VM_EXIT_LOAD_IA32_PAT) {
		rdmsr(MSR_IA32_CR_PAT, msr_low, msr_high);
		host_pat = msr_low | ((u64) msr_high << 32);
		vmcs_write64(HOST_IA32_PAT, host_pat);
	}
	if (vmcs_config.vmentry_ctrl & VM_ENTRY_LOAD_IA32_PAT) {
		rdmsr(MSR_IA32_CR_PAT, msr_low, msr_high);
		host_pat = msr_low | ((u64) msr_high << 32);
		/* Write the default value follow host pat */
		vmcs_write64(GUEST_IA32_PAT, host_pat);
		/* Keep arch.pat sync with GUEST_IA32_PAT */
		vmx->vcpu.arch.pat = host_pat;
	}

	for (i = 0; i < NR_VMX_MSR; ++i) {
		u32 index = vmx_msr_index[i];
		u32 data_low, data_high;
		int j = vmx->nmsrs;

		if (rdmsr_safe(index, &data_low, &data_high) < 0)
			continue;
		if (wrmsr_safe(index, data_low, data_high) < 0)
			continue;
		vmx->guest_msrs[j].index = i;
		vmx->guest_msrs[j].data = 0;
		vmx->guest_msrs[j].mask = -1ull;
		++vmx->nmsrs;
	}

	vmcs_write32(VM_EXIT_CONTROLS, vmcs_config.vmexit_ctrl);

	/* 22.2.1, 20.8.1 */
	vmcs_write32(VM_ENTRY_CONTROLS, vmcs_config.vmentry_ctrl);

	vmcs_writel(CR0_GUEST_HOST_MASK, ~0UL);
	vmx->vcpu.arch.cr4_guest_owned_bits = KVM_CR4_GUEST_OWNED_BITS;
	if (enable_ept)
		vmx->vcpu.arch.cr4_guest_owned_bits |= X86_CR4_PGE;
	vmcs_writel(CR4_GUEST_HOST_MASK, ~vmx->vcpu.arch.cr4_guest_owned_bits);

	kvm_write_tsc(&vmx->vcpu, 0);

	return 0;
}

static int init_rmode(struct kvm *kvm)
{
	int idx, ret = 0;

	idx = srcu_read_lock(&kvm->srcu);
	if (!init_rmode_tss(kvm))
		goto exit;
	if (!init_rmode_identity_map(kvm))
		goto exit;

	ret = 1;
exit:
	srcu_read_unlock(&kvm->srcu, idx);
	return ret;
}

static int vmx_vcpu_reset(struct kvm_vcpu *vcpu)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);
	u64 msr;
	int ret;

	vcpu->arch.regs_avail = ~((1 << VCPU_REGS_RIP) | (1 << VCPU_REGS_RSP));
	if (!init_rmode(vmx->vcpu.kvm)) {
		ret = -ENOMEM;
		goto out;
	}

	vmx->rmode.vm86_active = 0;

	vmx->soft_vnmi_blocked = 0;

	vmx->vcpu.arch.regs[VCPU_REGS_RDX] = get_rdx_init_val();
	kvm_set_cr8(&vmx->vcpu, 0);
	msr = 0xfee00000 | MSR_IA32_APICBASE_ENABLE;
	if (kvm_vcpu_is_bsp(&vmx->vcpu))
		msr |= MSR_IA32_APICBASE_BSP;
	kvm_set_apic_base(&vmx->vcpu, msr);

	ret = fx_init(&vmx->vcpu);
	if (ret != 0)
		goto out;

	seg_setup(VCPU_SREG_CS);
	/*
	 * GUEST_CS_BASE should really be 0xffff0000, but VT vm86 mode
	 * insists on having GUEST_CS_BASE == GUEST_CS_SELECTOR << 4.  Sigh.
	 */
	if (kvm_vcpu_is_bsp(&vmx->vcpu)) {
		vmcs_write16(GUEST_CS_SELECTOR, 0xf000);
		vmcs_writel(GUEST_CS_BASE, 0x000f0000);
	} else {
		vmcs_write16(GUEST_CS_SELECTOR, vmx->vcpu.arch.sipi_vector << 8);
		vmcs_writel(GUEST_CS_BASE, vmx->vcpu.arch.sipi_vector << 12);
	}

	seg_setup(VCPU_SREG_DS);
	seg_setup(VCPU_SREG_ES);
	seg_setup(VCPU_SREG_FS);
	seg_setup(VCPU_SREG_GS);
	seg_setup(VCPU_SREG_SS);

	vmcs_write16(GUEST_TR_SELECTOR, 0);
	vmcs_writel(GUEST_TR_BASE, 0);
	vmcs_write32(GUEST_TR_LIMIT, 0xffff);
	vmcs_write32(GUEST_TR_AR_BYTES, 0x008b);

	vmcs_write16(GUEST_LDTR_SELECTOR, 0);
	vmcs_writel(GUEST_LDTR_BASE, 0);
	vmcs_write32(GUEST_LDTR_LIMIT, 0xffff);
	vmcs_write32(GUEST_LDTR_AR_BYTES, 0x00082);

	vmcs_write32(GUEST_SYSENTER_CS, 0);
	vmcs_writel(GUEST_SYSENTER_ESP, 0);
	vmcs_writel(GUEST_SYSENTER_EIP, 0);

	vmcs_writel(GUEST_RFLAGS, 0x02);
	if (kvm_vcpu_is_bsp(&vmx->vcpu))
		kvm_rip_write(vcpu, 0xfff0);
	else
		kvm_rip_write(vcpu, 0);
	kvm_register_write(vcpu, VCPU_REGS_RSP, 0);

	vmcs_writel(GUEST_DR7, 0x400);

	vmcs_writel(GUEST_GDTR_BASE, 0);
	vmcs_write32(GUEST_GDTR_LIMIT, 0xffff);

	vmcs_writel(GUEST_IDTR_BASE, 0);
	vmcs_write32(GUEST_IDTR_LIMIT, 0xffff);

	vmcs_write32(GUEST_ACTIVITY_STATE, GUEST_ACTIVITY_ACTIVE);
	vmcs_write32(GUEST_INTERRUPTIBILITY_INFO, 0);
	vmcs_write32(GUEST_PENDING_DBG_EXCEPTIONS, 0);

	/* Special registers */
	vmcs_write64(GUEST_IA32_DEBUGCTL, 0);

	setup_msrs(vmx);

	vmcs_write32(VM_ENTRY_INTR_INFO_FIELD, 0);  /* 22.2.1 */

	if (cpu_has_vmx_tpr_shadow()) {
		vmcs_write64(VIRTUAL_APIC_PAGE_ADDR, 0);
		if (vm_need_tpr_shadow(vmx->vcpu.kvm))
			vmcs_write64(VIRTUAL_APIC_PAGE_ADDR,
				page_to_phys(vmx->vcpu.arch.apic->regs_page));
		vmcs_write32(TPR_THRESHOLD, 0);
	}

	if (vm_need_virtualize_apic_accesses(vmx->vcpu.kvm))
		vmcs_write64(APIC_ACCESS_ADDR,
			     page_to_phys(vmx->vcpu.kvm->arch.apic_access_page));

	if (vmx->vpid != 0)
		vmcs_write16(VIRTUAL_PROCESSOR_ID, vmx->vpid);

	vmx->vcpu.arch.cr0 = X86_CR0_NW | X86_CR0_CD | X86_CR0_ET;
	vmx_set_cr0(&vmx->vcpu, kvm_read_cr0(vcpu)); /* enter rmode */
	vmx_set_cr4(&vmx->vcpu, 0);
	vmx_set_efer(&vmx->vcpu, 0);
	vmx_fpu_activate(&vmx->vcpu);
	update_exception_bitmap(&vmx->vcpu);

	vpid_sync_context(vmx);

	ret = 0;

	/* HACK: Don't enable emulation on guest boot/reset */
	vmx->emulation_required = 0;

out:
	return ret;
}

/*
 * In nested virtualization, check if L1 asked to exit on external interrupts.
 * For most existing hypervisors, this will always return true.
 */
static bool nested_exit_on_intr(struct kvm_vcpu *vcpu)
{
	return get_vmcs12_fields(vcpu)->pin_based_vm_exec_control &
		PIN_BASED_EXT_INTR_MASK;
}

static void enable_irq_window(struct kvm_vcpu *vcpu)
{
	u32 cpu_based_vm_exec_control;
	if (is_guest_mode(vcpu) && nested_exit_on_intr(vcpu))
		/* We can get here when nested_run_pending caused
		 * vmx_interrupt_allowed() to return false. In this case, do
		 * nothing - the interrupt will be injected later.
		 */
		return;

	cpu_based_vm_exec_control = vmcs_read32(CPU_BASED_VM_EXEC_CONTROL);
	cpu_based_vm_exec_control |= CPU_BASED_VIRTUAL_INTR_PENDING;
	vmcs_write32(CPU_BASED_VM_EXEC_CONTROL, cpu_based_vm_exec_control);
}

static void enable_nmi_window(struct kvm_vcpu *vcpu)
{
	u32 cpu_based_vm_exec_control;

	if (!cpu_has_virtual_nmis()) {
		enable_irq_window(vcpu);
		return;
	}

	if (vmcs_read32(GUEST_INTERRUPTIBILITY_INFO) & GUEST_INTR_STATE_STI) {
		enable_irq_window(vcpu);
		return;
	}
	cpu_based_vm_exec_control = vmcs_read32(CPU_BASED_VM_EXEC_CONTROL);
	cpu_based_vm_exec_control |= CPU_BASED_VIRTUAL_NMI_PENDING;
	vmcs_write32(CPU_BASED_VM_EXEC_CONTROL, cpu_based_vm_exec_control);
}

static void vmx_inject_irq(struct kvm_vcpu *vcpu)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);
	uint32_t intr;
	int irq = vcpu->arch.interrupt.nr;

	trace_kvm_inj_virq(irq);

	++vcpu->stat.irq_injections;
	if (vmx->rmode.vm86_active) {
		if (kvm_inject_realmode_interrupt(vcpu, irq) != EMULATE_DONE)
			kvm_make_request(KVM_REQ_TRIPLE_FAULT, vcpu);
		return;
	}
	intr = irq | INTR_INFO_VALID_MASK;
	if (vcpu->arch.interrupt.soft) {
		intr |= INTR_TYPE_SOFT_INTR;
		vmcs_write32(VM_ENTRY_INSTRUCTION_LEN,
			     vmx->vcpu.arch.event_exit_inst_len);
	} else
		intr |= INTR_TYPE_EXT_INTR;
	vmcs_write32(VM_ENTRY_INTR_INFO_FIELD, intr);
	vmx_clear_hlt(vcpu);
}

static void vmx_inject_nmi(struct kvm_vcpu *vcpu)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);

	if (is_guest_mode(vcpu))
		return;

	if (!cpu_has_virtual_nmis()) {
		/*
		 * Tracking the NMI-blocked state in software is built upon
		 * finding the next open IRQ window. This, in turn, depends on
		 * well-behaving guests: They have to keep IRQs disabled at
		 * least as long as the NMI handler runs. Otherwise we may
		 * cause NMI nesting, maybe breaking the guest. But as this is
		 * highly unlikely, we can live with the residual risk.
		 */
		vmx->soft_vnmi_blocked = 1;
		vmx->vnmi_blocked_time = 0;
	}

	++vcpu->stat.nmi_injections;
	if (vmx->rmode.vm86_active) {
		if (kvm_inject_realmode_interrupt(vcpu, NMI_VECTOR) != EMULATE_DONE)
			kvm_make_request(KVM_REQ_TRIPLE_FAULT, vcpu);
		return;
	}
	vmcs_write32(VM_ENTRY_INTR_INFO_FIELD,
			INTR_TYPE_NMI_INTR | INTR_INFO_VALID_MASK | NMI_VECTOR);
	vmx_clear_hlt(vcpu);
}

static int vmx_nmi_allowed(struct kvm_vcpu *vcpu)
{
	if (!cpu_has_virtual_nmis() && to_vmx(vcpu)->soft_vnmi_blocked)
		return 0;

	return	!(vmcs_read32(GUEST_INTERRUPTIBILITY_INFO) &
		  (GUEST_INTR_STATE_MOV_SS | GUEST_INTR_STATE_STI
		   | GUEST_INTR_STATE_NMI));
}

static bool vmx_get_nmi_mask(struct kvm_vcpu *vcpu)
{
	if (!cpu_has_virtual_nmis())
		return to_vmx(vcpu)->soft_vnmi_blocked;
	return vmcs_read32(GUEST_INTERRUPTIBILITY_INFO)	& GUEST_INTR_STATE_NMI;
}

static void vmx_set_nmi_mask(struct kvm_vcpu *vcpu, bool masked)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);

	if (!cpu_has_virtual_nmis()) {
		if (vmx->soft_vnmi_blocked != masked) {
			vmx->soft_vnmi_blocked = masked;
			vmx->vnmi_blocked_time = 0;
		}
	} else {
		if (masked)
			vmcs_set_bits(GUEST_INTERRUPTIBILITY_INFO,
				      GUEST_INTR_STATE_NMI);
		else
			vmcs_clear_bits(GUEST_INTERRUPTIBILITY_INFO,
					GUEST_INTR_STATE_NMI);
	}
}

static int vmx_interrupt_allowed(struct kvm_vcpu *vcpu)
{
	if (is_guest_mode(vcpu) && nested_exit_on_intr(vcpu)) {
		if (to_vmx(vcpu)->nested.nested_run_pending)
			return 0;
		nested_vmx_vmexit(vcpu, true);
		/* fall through to normal code, but now in L1, not L2 */
	}

	return (vmcs_readl(GUEST_RFLAGS) & X86_EFLAGS_IF) &&
		!(vmcs_read32(GUEST_INTERRUPTIBILITY_INFO) &
			(GUEST_INTR_STATE_STI | GUEST_INTR_STATE_MOV_SS));
}

static int vmx_set_tss_addr(struct kvm *kvm, unsigned int addr)
{
	int ret;
	struct kvm_userspace_memory_region tss_mem = {
		.slot = TSS_PRIVATE_MEMSLOT,
		.guest_phys_addr = addr,
		.memory_size = PAGE_SIZE * 3,
		.flags = 0,
	};

	ret = kvm_set_memory_region(kvm, &tss_mem, 0);
	if (ret)
		return ret;
	kvm->arch.tss_addr = addr;
	return 0;
}

static int handle_rmode_exception(struct kvm_vcpu *vcpu,
				  int vec, u32 err_code)
{
	/*
	 * Instruction with address size override prefix opcode 0x67
	 * Cause the #SS fault with 0 error code in VM86 mode.
	 */
	if (((vec == GP_VECTOR) || (vec == SS_VECTOR)) && err_code == 0)
		if (emulate_instruction(vcpu, 0) == EMULATE_DONE)
			return 1;
	/*
	 * Forward all other exceptions that are valid in real mode.
	 * FIXME: Breaks guest debugging in real mode, needs to be fixed with
	 *        the required debugging infrastructure rework.
	 */
	switch (vec) {
	case DB_VECTOR:
		if (vcpu->guest_debug &
		    (KVM_GUESTDBG_SINGLESTEP | KVM_GUESTDBG_USE_HW_BP))
			return 0;
		kvm_queue_exception(vcpu, vec);
		return 1;
	case BP_VECTOR:
		/*
		 * Update instruction length as we may reinject the exception
		 * from user space while in guest debugging mode.
		 */
		to_vmx(vcpu)->vcpu.arch.event_exit_inst_len =
			vmcs_read32(VM_EXIT_INSTRUCTION_LEN);
		if (vcpu->guest_debug & KVM_GUESTDBG_USE_SW_BP)
			return 0;
		/* fall through */
	case DE_VECTOR:
	case OF_VECTOR:
	case BR_VECTOR:
	case UD_VECTOR:
	case DF_VECTOR:
	case SS_VECTOR:
	case GP_VECTOR:
	case MF_VECTOR:
		kvm_queue_exception(vcpu, vec);
		return 1;
	}
	return 0;
}

/*
 * Trigger machine check on the host. We assume all the MSRs are already set up
 * by the CPU and that we still run on the same CPU as the MCE occurred on.
 * We pass a fake environment to the machine check handler because we want
 * the guest to be always treated like user space, no matter what context
 * it used internally.
 */
static void kvm_machine_check(void)
{
#if defined(CONFIG_X86_MCE) && defined(CONFIG_X86_64)
	struct pt_regs regs = {
		.cs = 3, /* Fake ring 3 no matter what the guest ran on */
		.flags = X86_EFLAGS_IF,
	};

	do_machine_check(&regs, 0);
#endif
}

static int handle_machine_check(struct kvm_vcpu *vcpu)
{
	/* already handled by vcpu_run */
	return 1;
}

static int handle_exception(struct kvm_vcpu *vcpu)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);
	struct kvm_run *kvm_run = vcpu->run;
	u32 intr_info, ex_no, error_code;
	unsigned long cr2, rip, dr6;
	u32 vect_info;
	enum emulation_result er;

	vect_info = vmx->idt_vectoring_info;
	intr_info = vmcs_read32(VM_EXIT_INTR_INFO);

	if (is_machine_check(intr_info))
		return handle_machine_check(vcpu);

	if ((vect_info & VECTORING_INFO_VALID_MASK) &&
	    !is_page_fault(intr_info)) {
		vcpu->run->exit_reason = KVM_EXIT_INTERNAL_ERROR;
		vcpu->run->internal.suberror = KVM_INTERNAL_ERROR_SIMUL_EX;
		vcpu->run->internal.ndata = 2;
		vcpu->run->internal.data[0] = vect_info;
		vcpu->run->internal.data[1] = intr_info;
		return 0;
	}

	if ((intr_info & INTR_INFO_INTR_TYPE_MASK) == INTR_TYPE_NMI_INTR)
		return 1;  /* already handled by vmx_vcpu_run() */

	if (is_no_device(intr_info)) {
		vmx_fpu_activate(vcpu);
		return 1;
	}

	if (is_invalid_opcode(intr_info)) {
		er = emulate_instruction(vcpu, EMULTYPE_TRAP_UD);
		if (er != EMULATE_DONE)
			kvm_queue_exception(vcpu, UD_VECTOR);
		return 1;
	}

	error_code = 0;
	rip = kvm_rip_read(vcpu);
	if (intr_info & INTR_INFO_DELIVER_CODE_MASK)
		error_code = vmcs_read32(VM_EXIT_INTR_ERROR_CODE);
	if (is_page_fault(intr_info)) {
		/* EPT won't cause page fault directly */
		if (enable_ept)
			BUG();
		cr2 = vmcs_readl(EXIT_QUALIFICATION);
		trace_kvm_page_fault(cr2, error_code);

		if (kvm_event_needs_reinjection(vcpu))
			kvm_mmu_unprotect_page_virt(vcpu, cr2);
		return kvm_mmu_page_fault(vcpu, cr2, error_code, NULL, 0);
	}

	if (vmx->rmode.vm86_active &&
	    handle_rmode_exception(vcpu, intr_info & INTR_INFO_VECTOR_MASK,
								error_code)) {
		if (vcpu->arch.halt_request) {
			vcpu->arch.halt_request = 0;
			return kvm_emulate_halt(vcpu);
		}
		return 1;
	}

	ex_no = intr_info & INTR_INFO_VECTOR_MASK;
	switch (ex_no) {
	case DB_VECTOR:
		dr6 = vmcs_readl(EXIT_QUALIFICATION);
		if (!(vcpu->guest_debug &
		      (KVM_GUESTDBG_SINGLESTEP | KVM_GUESTDBG_USE_HW_BP))) {
			vcpu->arch.dr6 = dr6 | DR6_FIXED_1;
			kvm_queue_exception(vcpu, DB_VECTOR);
			return 1;
		}
		kvm_run->debug.arch.dr6 = dr6 | DR6_FIXED_1;
		kvm_run->debug.arch.dr7 = vmcs_readl(GUEST_DR7);
		/* fall through */
	case BP_VECTOR:
		/*
		 * Update instruction length as we may reinject #BP from
		 * user space while in guest debugging mode. Reading it for
		 * #DB as well causes no harm, it is not used in that case.
		 */
		vmx->vcpu.arch.event_exit_inst_len =
			vmcs_read32(VM_EXIT_INSTRUCTION_LEN);
		kvm_run->exit_reason = KVM_EXIT_DEBUG;
		kvm_run->debug.arch.pc = vmcs_readl(GUEST_CS_BASE) + rip;
		kvm_run->debug.arch.exception = ex_no;
		break;
	default:
		kvm_run->exit_reason = KVM_EXIT_EXCEPTION;
		kvm_run->ex.exception = ex_no;
		kvm_run->ex.error_code = error_code;
		break;
	}
	return 0;
}

static int handle_external_interrupt(struct kvm_vcpu *vcpu)
{
	++vcpu->stat.irq_exits;
	return 1;
}

static int handle_triple_fault(struct kvm_vcpu *vcpu)
{
	vcpu->run->exit_reason = KVM_EXIT_SHUTDOWN;
	return 0;
}

static int handle_io(struct kvm_vcpu *vcpu)
{
	unsigned long exit_qualification;
	int size, in, string;
	unsigned port;

	exit_qualification = vmcs_readl(EXIT_QUALIFICATION);
	string = (exit_qualification & 16) != 0;
	in = (exit_qualification & 8) != 0;

	++vcpu->stat.io_exits;

	if (string || in)
		return emulate_instruction(vcpu, 0) == EMULATE_DONE;

	port = exit_qualification >> 16;
	size = (exit_qualification & 7) + 1;
	skip_emulated_instruction(vcpu);

	return kvm_fast_pio_out(vcpu, size, port);
}

static void
vmx_patch_hypercall(struct kvm_vcpu *vcpu, unsigned char *hypercall)
{
	/*
	 * Patch in the VMCALL instruction:
	 */
	hypercall[0] = 0x0f;
	hypercall[1] = 0x01;
	hypercall[2] = 0xc1;
}

/* called to set cr0 as approriate for a mov-to-cr0 exit. */
static int handle_set_cr0(struct kvm_vcpu *vcpu, unsigned long val)
{
	if (is_guest_mode(vcpu)) {
		/*
		 * We get here when L2 changed cr0 in a way that did not change
		 * any of L1's shadowed bits (see nested_vmx_exit_handled_cr),
		 * but did change L0 shadowed bits. This can currently happen
		 * with the TS bit: L0 may want to leave TS on (for lazy fpu
		 * loading) while pretending to allow the guest to change it.
		 */
		vmcs_writel(GUEST_CR0,
		   (val & vcpu->arch.cr0_guest_owned_bits) |
		   (vmcs_readl(GUEST_CR0) & ~vcpu->arch.cr0_guest_owned_bits));
		vmcs_writel(CR0_READ_SHADOW, val);
		vcpu->arch.cr0 = val;
		return 0;
	} else
		return kvm_set_cr0(vcpu, val);
}

static int handle_set_cr4(struct kvm_vcpu *vcpu, unsigned long val)
{
	if (is_guest_mode(vcpu)) {
		vmcs_writel(GUEST_CR4,
		   (val & vcpu->arch.cr4_guest_owned_bits) |
		   (vmcs_readl(GUEST_CR4) & ~vcpu->arch.cr4_guest_owned_bits));
		vmcs_writel(CR4_READ_SHADOW, val);
		vcpu->arch.cr4 = val;
		return 0;
	} else
		return kvm_set_cr4(vcpu, val);
}

/* called to set cr0 as approriate for clts instruction exit. */
static void handle_clts(struct kvm_vcpu *vcpu)
{
	if (is_guest_mode(vcpu)) {
		/* As in handle_set_cr0(), we can't call vmx_set_cr0 here */
		vmcs_writel(GUEST_CR0, vmcs_readl(GUEST_CR0) & ~X86_CR0_TS);
		vmcs_writel(CR0_READ_SHADOW,
			vmcs_readl(CR0_READ_SHADOW) & ~X86_CR0_TS);
		vcpu->arch.cr0 &= ~X86_CR0_TS;
	} else
		vmx_set_cr0(vcpu, kvm_read_cr0_bits(vcpu, ~X86_CR0_TS));
}

static int handle_cr(struct kvm_vcpu *vcpu)
{
	unsigned long exit_qualification, val;
	int cr;
	int reg;
	int err;

	exit_qualification = vmcs_readl(EXIT_QUALIFICATION);
	cr = exit_qualification & 15;
	reg = (exit_qualification >> 8) & 15;
	switch ((exit_qualification >> 4) & 3) {
	case 0: /* mov to cr */
		val = kvm_register_read(vcpu, reg);
		trace_kvm_cr_write(cr, val);
		switch (cr) {
		case 0:
			err = handle_set_cr0(vcpu, val);
			kvm_complete_insn_gp(vcpu, err);
			return 1;
		case 3:
			err = kvm_set_cr3(vcpu, val);
			kvm_complete_insn_gp(vcpu, err);
			return 1;
		case 4:
			err = handle_set_cr4(vcpu, val);
			kvm_complete_insn_gp(vcpu, err);
			return 1;
		case 8: {
				u8 cr8_prev = kvm_get_cr8(vcpu);
				u8 cr8 = kvm_register_read(vcpu, reg);
				err = kvm_set_cr8(vcpu, cr8);
				kvm_complete_insn_gp(vcpu, err);
				if (irqchip_in_kernel(vcpu->kvm))
					return 1;
				if (cr8_prev <= cr8)
					return 1;
				vcpu->run->exit_reason = KVM_EXIT_SET_TPR;
				return 0;
			}
		};
		break;
	case 2: /* clts */
		handle_clts(vcpu);
		trace_kvm_cr_write(0, kvm_read_cr0(vcpu));
		skip_emulated_instruction(vcpu);
		vmx_fpu_activate(vcpu);
		return 1;
	case 1: /*mov from cr*/
		switch (cr) {
		case 3:
			val = kvm_read_cr3(vcpu);
			kvm_register_write(vcpu, reg, val);
			trace_kvm_cr_read(cr, val);
			skip_emulated_instruction(vcpu);
			return 1;
		case 8:
			val = kvm_get_cr8(vcpu);
			kvm_register_write(vcpu, reg, val);
			trace_kvm_cr_read(cr, val);
			skip_emulated_instruction(vcpu);
			return 1;
		}
		break;
	case 3: /* lmsw */
		val = (exit_qualification >> LMSW_SOURCE_DATA_SHIFT) & 0x0f;
		trace_kvm_cr_write(0, (kvm_read_cr0(vcpu) & ~0xful) | val);
		kvm_lmsw(vcpu, val);

		skip_emulated_instruction(vcpu);
		return 1;
	default:
		break;
	}
	vcpu->run->exit_reason = 0;
	pr_unimpl(vcpu, "unhandled control register: op %d cr %d\n",
	       (int)(exit_qualification >> 4) & 3, cr);
	return 0;
}

static int handle_dr(struct kvm_vcpu *vcpu)
{
	unsigned long exit_qualification;
	int dr, reg;

	/* Do not handle if the CPL > 0, will trigger GP on re-entry */
	if (!kvm_require_cpl(vcpu, 0))
		return 1;
	dr = vmcs_readl(GUEST_DR7);
	if (dr & DR7_GD) {
		/*
		 * As the vm-exit takes precedence over the debug trap, we
		 * need to emulate the latter, either for the host or the
		 * guest debugging itself.
		 */
		if (vcpu->guest_debug & KVM_GUESTDBG_USE_HW_BP) {
			vcpu->run->debug.arch.dr6 = vcpu->arch.dr6;
			vcpu->run->debug.arch.dr7 = dr;
			vcpu->run->debug.arch.pc =
				vmcs_readl(GUEST_CS_BASE) +
				vmcs_readl(GUEST_RIP);
			vcpu->run->debug.arch.exception = DB_VECTOR;
			vcpu->run->exit_reason = KVM_EXIT_DEBUG;
			return 0;
		} else {
			vcpu->arch.dr7 &= ~DR7_GD;
			vcpu->arch.dr6 |= DR6_BD;
			vmcs_writel(GUEST_DR7, vcpu->arch.dr7);
			kvm_queue_exception(vcpu, DB_VECTOR);
			return 1;
		}
	}

	exit_qualification = vmcs_readl(EXIT_QUALIFICATION);
	dr = exit_qualification & DEBUG_REG_ACCESS_NUM;
	reg = DEBUG_REG_ACCESS_REG(exit_qualification);
	if (exit_qualification & TYPE_MOV_FROM_DR) {
		unsigned long val;
		if (!kvm_get_dr(vcpu, dr, &val))
			kvm_register_write(vcpu, reg, val);
	} else
		kvm_set_dr(vcpu, dr, vcpu->arch.regs[reg]);
	skip_emulated_instruction(vcpu);
	return 1;
}

static void vmx_set_dr7(struct kvm_vcpu *vcpu, unsigned long val)
{
	vmcs_writel(GUEST_DR7, val);
}

static int handle_cpuid(struct kvm_vcpu *vcpu)
{
	kvm_emulate_cpuid(vcpu);
	return 1;
}

static int handle_rdmsr(struct kvm_vcpu *vcpu)
{
	u32 ecx = vcpu->arch.regs[VCPU_REGS_RCX];
	u64 data;

	if (vmx_get_msr(vcpu, ecx, &data)) {
		trace_kvm_msr_read_ex(ecx);
		kvm_inject_gp(vcpu, 0);
		return 1;
	}

	trace_kvm_msr_read(ecx, data);

	/* FIXME: handling of bits 32:63 of rax, rdx */
	vcpu->arch.regs[VCPU_REGS_RAX] = data & -1u;
	vcpu->arch.regs[VCPU_REGS_RDX] = (data >> 32) & -1u;
	skip_emulated_instruction(vcpu);
	return 1;
}

static int handle_wrmsr(struct kvm_vcpu *vcpu)
{
	u32 ecx = vcpu->arch.regs[VCPU_REGS_RCX];
	u64 data = (vcpu->arch.regs[VCPU_REGS_RAX] & -1u)
		| ((u64)(vcpu->arch.regs[VCPU_REGS_RDX] & -1u) << 32);

	if (vmx_set_msr(vcpu, ecx, data) != 0) {
		trace_kvm_msr_write_ex(ecx, data);
		kvm_inject_gp(vcpu, 0);
		return 1;
	}

	trace_kvm_msr_write(ecx, data);
	skip_emulated_instruction(vcpu);
	return 1;
}

static int handle_tpr_below_threshold(struct kvm_vcpu *vcpu)
{
	kvm_make_request(KVM_REQ_EVENT, vcpu);
	return 1;
}

static int handle_interrupt_window(struct kvm_vcpu *vcpu)
{
	u32 cpu_based_vm_exec_control;

	/* clear pending irq */
	cpu_based_vm_exec_control = vmcs_read32(CPU_BASED_VM_EXEC_CONTROL);
	cpu_based_vm_exec_control &= ~CPU_BASED_VIRTUAL_INTR_PENDING;
	vmcs_write32(CPU_BASED_VM_EXEC_CONTROL, cpu_based_vm_exec_control);

	kvm_make_request(KVM_REQ_EVENT, vcpu);

	++vcpu->stat.irq_window_exits;

	/*
	 * If the user space waits to inject interrupts, exit as soon as
	 * possible
	 */
	if (!irqchip_in_kernel(vcpu->kvm) &&
	    vcpu->run->request_interrupt_window &&
	    !kvm_cpu_has_interrupt(vcpu)) {
		vcpu->run->exit_reason = KVM_EXIT_IRQ_WINDOW_OPEN;
		return 0;
	}
	return 1;
}

static int handle_halt(struct kvm_vcpu *vcpu)
{
	skip_emulated_instruction(vcpu);
	return kvm_emulate_halt(vcpu);
}

static int handle_vmcall(struct kvm_vcpu *vcpu)
{
	skip_emulated_instruction(vcpu);
	kvm_emulate_hypercall(vcpu);
	return 1;
}

static int handle_invd(struct kvm_vcpu *vcpu)
{
	return emulate_instruction(vcpu, 0) == EMULATE_DONE;
}

static int handle_invlpg(struct kvm_vcpu *vcpu)
{
	unsigned long exit_qualification = vmcs_readl(EXIT_QUALIFICATION);

	kvm_mmu_invlpg(vcpu, exit_qualification);
	skip_emulated_instruction(vcpu);
	return 1;
}

static int handle_wbinvd(struct kvm_vcpu *vcpu)
{
	skip_emulated_instruction(vcpu);
	kvm_emulate_wbinvd(vcpu);
	return 1;
}

static int handle_xsetbv(struct kvm_vcpu *vcpu)
{
	u64 new_bv = kvm_read_edx_eax(vcpu);
	u32 index = kvm_register_read(vcpu, VCPU_REGS_RCX);

	if (kvm_set_xcr(vcpu, index, new_bv) == 0)
		skip_emulated_instruction(vcpu);
	return 1;
}

static int handle_apic_access(struct kvm_vcpu *vcpu)
{
	return emulate_instruction(vcpu, 0) == EMULATE_DONE;
}

static int handle_task_switch(struct kvm_vcpu *vcpu)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);
	unsigned long exit_qualification;
	bool has_error_code = false;
	u32 error_code = 0;
	u16 tss_selector;
	int reason, type, idt_v;

	idt_v = (vmx->idt_vectoring_info & VECTORING_INFO_VALID_MASK);
	type = (vmx->idt_vectoring_info & VECTORING_INFO_TYPE_MASK);

	exit_qualification = vmcs_readl(EXIT_QUALIFICATION);

	reason = (u32)exit_qualification >> 30;
	if (reason == TASK_SWITCH_GATE && idt_v) {
		switch (type) {
		case INTR_TYPE_NMI_INTR:
			vcpu->arch.nmi_injected = false;
			if (cpu_has_virtual_nmis())
				vmcs_set_bits(GUEST_INTERRUPTIBILITY_INFO,
					      GUEST_INTR_STATE_NMI);
			break;
		case INTR_TYPE_EXT_INTR:
		case INTR_TYPE_SOFT_INTR:
			kvm_clear_interrupt_queue(vcpu);
			break;
		case INTR_TYPE_HARD_EXCEPTION:
			if (vmx->idt_vectoring_info &
			    VECTORING_INFO_DELIVER_CODE_MASK) {
				has_error_code = true;
				error_code =
					vmcs_read32(IDT_VECTORING_ERROR_CODE);
			}
			/* fall through */
		case INTR_TYPE_SOFT_EXCEPTION:
			kvm_clear_exception_queue(vcpu);
			break;
		default:
			break;
		}
	}
	tss_selector = exit_qualification;

	if (!idt_v || (type != INTR_TYPE_HARD_EXCEPTION &&
		       type != INTR_TYPE_EXT_INTR &&
		       type != INTR_TYPE_NMI_INTR))
		skip_emulated_instruction(vcpu);

	if (kvm_task_switch(vcpu, tss_selector, reason,
				has_error_code, error_code) == EMULATE_FAIL) {
		vcpu->run->exit_reason = KVM_EXIT_INTERNAL_ERROR;
		vcpu->run->internal.suberror = KVM_INTERNAL_ERROR_EMULATION;
		vcpu->run->internal.ndata = 0;
		return 0;
	}

	/* clear all local breakpoint enable flags */
	vmcs_writel(GUEST_DR7, vmcs_readl(GUEST_DR7) & ~55);

	/*
	 * TODO: What about debug traps on tss switch?
	 *       Are we supposed to inject them and update dr6?
	 */

	return 1;
}

static int handle_ept_violation(struct kvm_vcpu *vcpu)
{
	unsigned long exit_qualification;
	gpa_t gpa;
	int gla_validity;

	exit_qualification = vmcs_readl(EXIT_QUALIFICATION);

	if (exit_qualification & (1 << 6)) {
		printk(KERN_ERR "EPT: GPA exceeds GAW!\n");
		return -EINVAL;
	}

	gla_validity = (exit_qualification >> 7) & 0x3;
	if (gla_validity != 0x3 && gla_validity != 0x1 && gla_validity != 0) {
		printk(KERN_ERR "EPT: Handling EPT violation failed!\n");
		printk(KERN_ERR "EPT: GPA: 0x%lx, GVA: 0x%lx\n",
			(long unsigned int)vmcs_read64(GUEST_PHYSICAL_ADDRESS),
			vmcs_readl(GUEST_LINEAR_ADDRESS));
		printk(KERN_ERR "EPT: Exit qualification is 0x%lx\n",
			(long unsigned int)exit_qualification);
		vcpu->run->exit_reason = KVM_EXIT_UNKNOWN;
		vcpu->run->hw.hardware_exit_reason = EXIT_REASON_EPT_VIOLATION;
		return 0;
	}

	gpa = vmcs_read64(GUEST_PHYSICAL_ADDRESS);
	trace_kvm_page_fault(gpa, exit_qualification);
	return kvm_mmu_page_fault(vcpu, gpa, exit_qualification & 0x3, NULL, 0);
}

static u64 ept_rsvd_mask(u64 spte, int level)
{
	int i;
	u64 mask = 0;

	for (i = 51; i > boot_cpu_data.x86_phys_bits; i--)
		mask |= (1ULL << i);

	if (level > 2)
		/* bits 7:3 reserved */
		mask |= 0xf8;
	else if (level == 2) {
		if (spte & (1ULL << 7))
			/* 2MB ref, bits 20:12 reserved */
			mask |= 0x1ff000;
		else
			/* bits 6:3 reserved */
			mask |= 0x78;
	}

	return mask;
}

static void ept_misconfig_inspect_spte(struct kvm_vcpu *vcpu, u64 spte,
				       int level)
{
	printk(KERN_ERR "%s: spte 0x%llx level %d\n", __func__, spte, level);

	/* 010b (write-only) */
	WARN_ON((spte & 0x7) == 0x2);

	/* 110b (write/execute) */
	WARN_ON((spte & 0x7) == 0x6);

	/* 100b (execute-only) and value not supported by logical processor */
	if (!cpu_has_vmx_ept_execute_only())
		WARN_ON((spte & 0x7) == 0x4);

	/* not 000b */
	if ((spte & 0x7)) {
		u64 rsvd_bits = spte & ept_rsvd_mask(spte, level);

		if (rsvd_bits != 0) {
			printk(KERN_ERR "%s: rsvd_bits = 0x%llx\n",
					 __func__, rsvd_bits);
			WARN_ON(1);
		}

		if (level == 1 || (level == 2 && (spte & (1ULL << 7)))) {
			u64 ept_mem_type = (spte & 0x38) >> 3;

			if (ept_mem_type == 2 || ept_mem_type == 3 ||
			    ept_mem_type == 7) {
				printk(KERN_ERR "%s: ept_mem_type=0x%llx\n",
						__func__, ept_mem_type);
				WARN_ON(1);
			}
		}
	}
}

static int handle_ept_misconfig(struct kvm_vcpu *vcpu)
{
	u64 sptes[4];
	int nr_sptes, i;
	gpa_t gpa;

	gpa = vmcs_read64(GUEST_PHYSICAL_ADDRESS);

	printk(KERN_ERR "EPT: Misconfiguration.\n");
	printk(KERN_ERR "EPT: GPA: 0x%llx\n", gpa);

	nr_sptes = kvm_mmu_get_spte_hierarchy(vcpu, gpa, sptes);

	for (i = PT64_ROOT_LEVEL; i > PT64_ROOT_LEVEL - nr_sptes; --i)
		ept_misconfig_inspect_spte(vcpu, sptes[i-1], i);

	vcpu->run->exit_reason = KVM_EXIT_UNKNOWN;
	vcpu->run->hw.hardware_exit_reason = EXIT_REASON_EPT_MISCONFIG;

	return 0;
}

static int handle_nmi_window(struct kvm_vcpu *vcpu)
{
	u32 cpu_based_vm_exec_control;

	/* clear pending NMI */
	cpu_based_vm_exec_control = vmcs_read32(CPU_BASED_VM_EXEC_CONTROL);
	cpu_based_vm_exec_control &= ~CPU_BASED_VIRTUAL_NMI_PENDING;
	vmcs_write32(CPU_BASED_VM_EXEC_CONTROL, cpu_based_vm_exec_control);
	++vcpu->stat.nmi_window_exits;
	kvm_make_request(KVM_REQ_EVENT, vcpu);

	return 1;
}

static int handle_invalid_guest_state(struct kvm_vcpu *vcpu)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);
	enum emulation_result err = EMULATE_DONE;
	int ret = 1;
	u32 cpu_exec_ctrl;
	bool intr_window_requested;

	cpu_exec_ctrl = vmcs_read32(CPU_BASED_VM_EXEC_CONTROL);
	intr_window_requested = cpu_exec_ctrl & CPU_BASED_VIRTUAL_INTR_PENDING;

	while (!guest_state_valid(vcpu)) {
		if (intr_window_requested
		    && (kvm_get_rflags(&vmx->vcpu) & X86_EFLAGS_IF))
			return handle_interrupt_window(&vmx->vcpu);

		err = emulate_instruction(vcpu, 0);

		if (err == EMULATE_DO_MMIO) {
			ret = 0;
			goto out;
		}

		if (err != EMULATE_DONE)
			return 0;

		if (signal_pending(current))
			goto out;
		if (need_resched())
			schedule();
	}

	vmx->emulation_required = 0;
out:
	return ret;
}

/*
 * Indicate a busy-waiting vcpu in spinlock. We do not enable the PAUSE
 * exiting, so only get here on cpu with PAUSE-Loop-Exiting.
 */
static int handle_pause(struct kvm_vcpu *vcpu)
{
	skip_emulated_instruction(vcpu);
	kvm_vcpu_on_spin(vcpu);

	return 1;
}

static int handle_invalid_op(struct kvm_vcpu *vcpu)
{
	kvm_queue_exception(vcpu, UD_VECTOR);
	return 1;
}

/* Find a vmcs02 saved for the current L2's vmcs12 */
static struct saved_vmcs *nested_get_current_vmcs(struct vcpu_vmx *vmx)
{
	struct vmcs_list *item;
	list_for_each_entry(item, &vmx->nested.vmcs02_list, list)
		if (item->vmcs12_addr == vmx->nested.current_vmptr)
			return &item->vmcs02;
	return NULL;
}

/*
 * Allocate an L0 VMCS (vmcs02) for the current L1 VMCS (vmcs12), if one
 * does not already exist. The allocation is done in L0 memory, so to avoid
 * denial-of-service attack by guests, we limit the number of concurrently-
 * allocated vmcss. A well-behaving L1 will VMCLEAR unused vmcs12s and not
 * trigger this limit.
 */
static int nested_create_current_vmcs(struct kvm_vcpu *vcpu)
{
	struct vmcs_list *new_l2_guest;
	struct vmcs *vmcs02;
	struct vcpu_vmx *vmx = to_vmx(vcpu);

	if (nested_get_current_vmcs(vmx))
		return 0; /* nothing to do - we already have a VMCS */

	if (vmx->nested.vmcs02_num >= NESTED_MAX_VMCS)
		return -ENOMEM;

	new_l2_guest = (struct vmcs_list *)
		kmalloc(sizeof(struct vmcs_list), GFP_KERNEL);
	if (!new_l2_guest)
		return -ENOMEM;

	vmcs02 = alloc_vmcs();
	if (!vmcs02) {
		kfree(new_l2_guest);
		return -ENOMEM;
	}

	new_l2_guest->vmcs12_addr = vmx->nested.current_vmptr;
	new_l2_guest->vmcs02.vmcs = vmcs02;
	new_l2_guest->vmcs02.cpu = -1;
	new_l2_guest->vmcs02.launched = 0;
	list_add(&(new_l2_guest->list), &(vmx->nested.vmcs02_list));
	vmx->nested.vmcs02_num++;
	return 0;
}

static void __nested_free_saved_vmcs(void *arg)
{
	struct saved_vmcs *saved_vmcs = arg;
	int cpu = raw_smp_processor_id();

	if (saved_vmcs->cpu == cpu) /* TODO: how can this not be the case? */
		vmcs_clear(saved_vmcs->vmcs);
	if (per_cpu(current_vmcs, cpu) == saved_vmcs->vmcs)
		per_cpu(current_vmcs, cpu) = NULL;
}

/*
 * Free a VMCS, but before that VMCLEAR it on the CPU where it was last loaded
 * (the necessary information is in the saved_vmcs structure).
 * See also vcpu_clear() (with different parameters and side-effects)
 */
static void nested_free_saved_vmcs(struct vcpu_vmx *vmx,
		struct saved_vmcs *saved_vmcs)
{
	if (saved_vmcs->cpu != -1)
		smp_call_function_single(saved_vmcs->cpu,
				__nested_free_saved_vmcs, saved_vmcs, 1);

	free_vmcs(saved_vmcs->vmcs);
}

/*
 * Free a vmcs12's associated vmcs02 (if there is one), and remove it from
 * vmcs02_list.
 */
static void nested_free_vmcs(struct vcpu_vmx *vmx, gpa_t vmptr)
{
	struct vmcs_list *item;
	list_for_each_entry(item, &vmx->nested.vmcs02_list, list)
		if (item->vmcs12_addr == vmptr) {
			nested_free_saved_vmcs(vmx, &item->vmcs02);
			list_del(&item->list);
			kfree(item);
			vmx->nested.vmcs02_num--;
			return;
		}
}

/* Free all vmcs02 saved for this L1 vcpu */
static void nested_free_all_vmcs(struct vcpu_vmx *vmx)
{
	struct vmcs_list *item, *n;
	list_for_each_entry_safe(item, n, &vmx->nested.vmcs02_list, list) {
		nested_free_saved_vmcs(vmx, &item->vmcs02);
		list_del(&item->list);
		kfree(item);
	}
	vmx->nested.vmcs02_num = 0;
}

/*
 * Emulate the VMXON instruction.
 * Currently, we just remember that VMX is active, and do not save or even
 * inspect the argument to VMXON (the so-called "VMXON pointer") because we
 * do not currently need to store anything in that guest-allocated memory
 * region. Consequently, VMCLEAR and VMPTRLD also do not verify that the their
 * argument is different from the VMXON pointer (which the spec says they do).
 */
static int handle_vmon(struct kvm_vcpu *vcpu)
{
	struct kvm_segment cs;
	struct vcpu_vmx *vmx = to_vmx(vcpu);

	/* The Intel VMX Instruction Reference lists a bunch of bits that
	 * are prerequisite to running VMXON, most notably cr4.VMXE must be
	 * set to 1 (see vmx_set_cr4() for when we allow the guest to set this).
	 * Otherwise, we should fail with #UD. We test these now:
	 */
	if (!kvm_read_cr4_bits(vcpu, X86_CR4_VMXE) ||
	    !kvm_read_cr0_bits(vcpu, X86_CR0_PE) ||
	    (vmx_get_rflags(vcpu) & X86_EFLAGS_VM)) {
		kvm_queue_exception(vcpu, UD_VECTOR);
		return 1;
	}

	vmx_get_segment(vcpu, &cs, VCPU_SREG_CS);
	if (is_long_mode(vcpu) && !cs.l) {
		kvm_queue_exception(vcpu, UD_VECTOR);
		return 1;
	}

	if (vmx_get_cpl(vcpu)) {
		kvm_inject_gp(vcpu, 0);
		return 1;
	}

	INIT_LIST_HEAD(&(vmx->nested.vmcs02_list));
	vmx->nested.vmcs02_num = 0;

	vmx->nested.vmcs01_fields = kzalloc(PAGE_SIZE, GFP_KERNEL);
	if (!vmx->nested.vmcs01_fields)
		return -ENOMEM;

	vmx->nested.vmxon = true;

	skip_emulated_instruction(vcpu);
	return 1;
}

/*
 * Intel's VMX Instruction Reference specifies a common set of prerequisites
 * for running VMX instructions (except VMXON, whose prerequisites are
 * slightly different). It also specifies what exception to inject otherwise.
 */
static int nested_vmx_check_permission(struct kvm_vcpu *vcpu)
{
	struct kvm_segment cs;
	struct vcpu_vmx *vmx = to_vmx(vcpu);

	if (!vmx->nested.vmxon) {
		kvm_queue_exception(vcpu, UD_VECTOR);
		return 0;
	}

	vmx_get_segment(vcpu, &cs, VCPU_SREG_CS);
	if ((vmx_get_rflags(vcpu) & X86_EFLAGS_VM) ||
	    (is_long_mode(vcpu) && !cs.l)) {
		kvm_queue_exception(vcpu, UD_VECTOR);
		return 0;
	}

	if (vmx_get_cpl(vcpu)) {
		kvm_inject_gp(vcpu, 0);
		return 0;
	}

	return 1;
}

/*
 * Free whatever needs to be freed from vmx->nested when L1 goes down, or
 * just stops using VMX.
 */
static void free_nested(struct vcpu_vmx *vmx)
{
	if (!vmx->nested.vmxon)
		return;
	vmx->nested.vmxon = false;
	if (vmx->nested.current_vmptr != -1ull) {
		kunmap(vmx->nested.current_vmcs12_page);
		nested_release_page(vmx->nested.current_vmcs12_page);
		vmx->nested.current_vmptr = -1ull;
	}

	nested_free_all_vmcs(vmx);

	kfree(vmx->nested.vmcs01_fields);
	vmx->nested.vmcs01_fields = NULL;
}

/* Emulate the VMXOFF instruction */
static int handle_vmoff(struct kvm_vcpu *vcpu)
{
	if (!nested_vmx_check_permission(vcpu))
		return 1;
	free_nested(to_vmx(vcpu));
	skip_emulated_instruction(vcpu);
	return 1;
}

/*
 * Decode the memory-address operand of a vmx instruction, as recorded on an
 * exit caused by such an instruction (run by a guest hypervisor).
 * On success, returns 0. When the operand is invalid, returns 1 and throws
 * #UD or #GP.
 */
static int get_vmx_mem_address(struct kvm_vcpu *vcpu,
				 unsigned long exit_qualification,
				 u32 vmx_instruction_info, gva_t *ret)
{
	/*
	 * According to Vol. 3B, "Information for VM Exits Due to Instruction
	 * Execution", on an exit, vmx_instruction_info holds most of the
	 * addressing components of the operand. Only the displacement part
	 * is put in exit_qualification (see 3B, "Basic VM-Exit Information").
	 * For how an actual address is calculated from all these components,
	 * refer to Vol. 1, "Operand Addressing".
	 */
	int  scaling = vmx_instruction_info & 3;
	int  addr_size = (vmx_instruction_info >> 7) & 7;
	bool is_reg = vmx_instruction_info & (1u << 10);
	int  seg_reg = (vmx_instruction_info >> 15) & 7;
	int  index_reg = (vmx_instruction_info >> 18) & 0xf;
	bool index_is_valid = !(vmx_instruction_info & (1u << 22));
	int  base_reg       = (vmx_instruction_info >> 23) & 0xf;
	bool base_is_valid  = !(vmx_instruction_info & (1u << 27));

	if (is_reg) {
		kvm_queue_exception(vcpu, UD_VECTOR);
		return 1;
	}

	switch (addr_size) {
	case 1: /* 32 bit. high bits are undefined according to the spec: */
		exit_qualification &= 0xffffffff;
		break;
	case 2: /* 64 bit */
		break;
	default: /* 16 bit */
		return 1;
	}

	/* Addr = segment_base + offset */
	/* offset = base + [index * scale] + displacement */
	*ret = vmx_get_segment_base(vcpu, seg_reg);
	if (base_is_valid)
		*ret += kvm_register_read(vcpu, base_reg);
	if (index_is_valid)
		*ret += kvm_register_read(vcpu, index_reg)<<scaling;
	*ret += exit_qualification; /* holds the displacement */
	/*
	 * TODO: throw #GP (and return 1) in various cases that the VM*
	 * instructions require it - e.g., offset beyond segment limit,
	 * unusable or unreadable/unwritable segment, non-canonical 64-bit
	 * address, and so on. Currently these are not checked.
	 */
	return 0;
}

/*
 * The following 3 functions, nested_vmx_succeed()/failValid()/failInvalid(),
 * set the success or error code of an emulated VMX instruction, as specified
 * by Vol 2B, VMX Instruction Reference, "Conventions".
 */
static void nested_vmx_succeed(struct kvm_vcpu *vcpu)
{
	vmx_set_rflags(vcpu, vmx_get_rflags(vcpu)
			& ~(X86_EFLAGS_CF | X86_EFLAGS_PF | X86_EFLAGS_AF |
			    X86_EFLAGS_ZF | X86_EFLAGS_SF | X86_EFLAGS_OF));
}

static void nested_vmx_failInvalid(struct kvm_vcpu *vcpu)
{
	vmx_set_rflags(vcpu, (vmx_get_rflags(vcpu)
			& ~(X86_EFLAGS_PF | X86_EFLAGS_AF | X86_EFLAGS_ZF |
			    X86_EFLAGS_SF | X86_EFLAGS_OF))
			| X86_EFLAGS_CF);
}

static void nested_vmx_failValid(struct kvm_vcpu *vcpu,
					u32 vm_instruction_error)
{
	vmx_set_rflags(vcpu, (vmx_get_rflags(vcpu)
			& ~(X86_EFLAGS_CF | X86_EFLAGS_PF | X86_EFLAGS_AF |
			    X86_EFLAGS_SF | X86_EFLAGS_OF))
			| X86_EFLAGS_ZF);
	get_vmcs12_fields(vcpu)->vm_instruction_error = vm_instruction_error;
}

/* Emulate the VMCLEAR instruction */
static int handle_vmclear(struct kvm_vcpu *vcpu)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);
	gva_t gva;
	gpa_t vmcs12_addr;
	struct vmcs12 *vmcs12;
	struct page *page;

	if (!nested_vmx_check_permission(vcpu))
		return 1;

	if (get_vmx_mem_address(vcpu, vmcs_readl(EXIT_QUALIFICATION),
			vmcs_read32(VMX_INSTRUCTION_INFO), &gva))
		return 1;

	if (kvm_read_guest_virt(gva, &vmcs12_addr, sizeof(vmcs12_addr),
				vcpu, NULL)) {
		kvm_queue_exception(vcpu, PF_VECTOR);
		return 1;
	}

	if (!IS_ALIGNED(vmcs12_addr, PAGE_SIZE)) {
		nested_vmx_failValid(vcpu, VMXERR_VMCLEAR_INVALID_ADDRESS);
		skip_emulated_instruction(vcpu);
		return 1;
	}

	if (vmcs12_addr == vmx->nested.current_vmptr) {
		kunmap(vmx->nested.current_vmcs12_page);
		nested_release_page(vmx->nested.current_vmcs12_page);
		vmx->nested.current_vmptr = -1ull;
	}

	page = nested_get_page(vcpu, vmcs12_addr);
	if (page == NULL) {
		/*
		 * For accurate processor emulation, VMCLEAR beyond available
		 * physical memory should do nothing at all. However, it is
		 * possible that a nested vmx bug, not a guest hypervisor bug,
		 * resulted in this case, so let's shut down before doing any
		 * more damage:
		 */
		kvm_make_request(KVM_REQ_TRIPLE_FAULT, vcpu);
		nested_release_page(page);
		return 1;
	}
	vmcs12 = kmap(page);
	vmcs12->launch_state = 0;
	kunmap(page);
	nested_release_page(page);

	nested_free_vmcs(vmx, vmcs12_addr);

	skip_emulated_instruction(vcpu);
	nested_vmx_succeed(vcpu);
	return 1;
}

static int nested_vmx_run(struct kvm_vcpu *vcpu);

static int handle_launch_or_resume(struct kvm_vcpu *vcpu, bool launch)
{
	struct vmcs12 *vmcs12;
	if (!nested_vmx_check_permission(vcpu))
		return 1;

	skip_emulated_instruction(vcpu);

	vmcs12 = get_vmcs12(vcpu);
	/* yet another strange pre-requisite listed in the VMX spec */
	if (vmcs12->fields.guest_interruptibility_info &
			GUEST_INTR_STATE_MOV_SS) {
		nested_vmx_failValid(vcpu,
			VMXERR_ENTRY_EVENTS_BLOCKED_BY_MOV_SS);
		return 1;
	}
	/*
	 * enforce that after VMCLEAR, L1 must use VMLAUNCH, but later must use
	 * VMRESUME, as this is part of the spec (even though it was easier for
	 * us to just allow both to work any time).
	 */
	if (vmcs12->launch_state == launch) {
		nested_vmx_failValid(vcpu,
			launch ? VMXERR_VMLAUNCH_NONCLEAR_VMCS :
				 VMXERR_VMRESUME_NONLAUNCHED_VMCS);
		return 1;
	}

	nested_vmx_run(vcpu);

	/*
	 * Note no nested_vmx_succeed or nested_vmx_fail here. At this point
	 * we are no longer running L1, and VMLAUNCH/VMRESUME has not yet
	 * returned as far as L1 is concerned. It will only return (and set
	 * the success flag) when L2 exits (see nested_vmx_vmexit()).
	 */
	return 1;
}

/* Emulate the VMLAUNCH instruction */
static int handle_vmlaunch(struct kvm_vcpu *vcpu)
{
	return handle_launch_or_resume(vcpu, true);
}

/* Emulate the VMRESUME instruction */
static int handle_vmresume(struct kvm_vcpu *vcpu)
{

	return handle_launch_or_resume(vcpu, false);
}

enum vmcs_field_type {
	VMCS_FIELD_TYPE_U16 = 0,
	VMCS_FIELD_TYPE_U64 = 1,
	VMCS_FIELD_TYPE_U32 = 2,
	VMCS_FIELD_TYPE_ULONG = 3
};

static inline int vmcs_field_type(unsigned long field)
{
	if (0x1 & field)	/* one of the *_HIGH fields, all are 32 bit */
		return VMCS_FIELD_TYPE_U32;
	return (field >> 13) & 0x3 ;
}

static inline int vmcs_field_readonly(unsigned long field)
{
	return (((field >> 10) & 0x3) == 1);
}

static inline bool vmcs12_read_any(struct kvm_vcpu *vcpu,
					unsigned long field, u64 *ret)
{
	short offset = vmcs_field_to_offset(field);
	char *p;

	if (offset < 0)
		return 0;

	p = ((char *)(get_vmcs12_fields(vcpu))) + offset;

	switch (vmcs_field_type(field)) {
	case VMCS_FIELD_TYPE_ULONG:
		*ret = *((unsigned long *)p);
		return 1;
	case VMCS_FIELD_TYPE_U16:
		*ret = (u16) *((unsigned long *)p);
		return 1;
	case VMCS_FIELD_TYPE_U32:
		*ret = (u32) *((unsigned long *)p);
		return 1;
	case VMCS_FIELD_TYPE_U64:
		*ret = *((u64 *)p);
		return 1;
	default:
		return 0; /* can never happen. */
	}
}

static int handle_vmread(struct kvm_vcpu *vcpu)
{
	unsigned long field;
	u64 field_value;
	unsigned long exit_qualification = vmcs_readl(EXIT_QUALIFICATION);
	u32 vmx_instruction_info = vmcs_read32(VMX_INSTRUCTION_INFO);
	gva_t gva = 0;

	if (!nested_vmx_check_permission(vcpu))
		return 1;

	/* decode instruction info and find the field to read */
	field = kvm_register_read(vcpu, (((vmx_instruction_info) >> 28) & 0xf));
	if (!vmcs12_read_any(vcpu, field, &field_value)) {
		nested_vmx_failValid(vcpu, VMXERR_UNSUPPORTED_VMCS_COMPONENT);
		skip_emulated_instruction(vcpu);
		return 1;
	}

	/*
	 * and now check if request to put the value in register or memory.
	 * Note that the number of bits actually written is 32 or 64 depending
	 * in the mode, not on the given field's length.
	 */
	if (vmx_instruction_info & (1u << 10)) {
		kvm_register_write(vcpu, (((vmx_instruction_info) >> 3) & 0xf),
			field_value);
	} else {
		if (get_vmx_mem_address(vcpu, exit_qualification,
				vmx_instruction_info, &gva))
			return 1;
		/* ok to use *_system, because handle_vmread verified cpl=0 */
		kvm_write_guest_virt_system(gva, &field_value,
			     (is_long_mode(vcpu) ? 8 : 4), vcpu, NULL);
	}

	nested_vmx_succeed(vcpu);
	skip_emulated_instruction(vcpu);
	return 1;
}


static int handle_vmwrite(struct kvm_vcpu *vcpu)
{
	unsigned long field;
	u64 field_value = 0;
	gva_t gva;
	int field_type;
	unsigned long exit_qualification   = vmcs_readl(EXIT_QUALIFICATION);
	u32 vmx_instruction_info = vmcs_read32(VMX_INSTRUCTION_INFO);
	char *p;
	short offset;

	if (!nested_vmx_check_permission(vcpu))
		return 1;

	if (vmx_instruction_info & (1u << 10))
		field_value = kvm_register_read(vcpu,
			(((vmx_instruction_info) >> 3) & 0xf));
	else {
		if (get_vmx_mem_address(vcpu, exit_qualification,
				vmx_instruction_info, &gva))
			return 1;
		if (kvm_read_guest_virt(gva, &field_value,
				(is_long_mode(vcpu) ? 8 : 4), vcpu, NULL)) {
			kvm_queue_exception(vcpu, PF_VECTOR);
			return 1;
		}
	}


	field = kvm_register_read(vcpu, (((vmx_instruction_info) >> 28) & 0xf));

	if (vmcs_field_readonly(field)) {
		nested_vmx_failValid(vcpu,
			VMXERR_VMWRITE_READ_ONLY_VMCS_COMPONENT);
		skip_emulated_instruction(vcpu);
		return 1;
	}

	field_type = vmcs_field_type(field);

	offset = vmcs_field_to_offset(field);
	if (offset < 0) {
		nested_vmx_failValid(vcpu, VMXERR_UNSUPPORTED_VMCS_COMPONENT);
		skip_emulated_instruction(vcpu);
		return 1;
	}
	p = ((char *) get_vmcs12_fields(vcpu)) + offset;

	switch (field_type) {
	case VMCS_FIELD_TYPE_U16:
		*(u16 *)p = field_value;
		break;
	case VMCS_FIELD_TYPE_U32:
		*(u32 *)p = field_value;
		break;
	case VMCS_FIELD_TYPE_U64:
#ifdef CONFIG_X86_64
		*(unsigned long *)p = field_value;
#else
		*(unsigned long *)p = field_value;
		*(((unsigned long *)p)+1) = field_value >> 32;
#endif
		break;
	case VMCS_FIELD_TYPE_ULONG:
		*(unsigned long *)p = field_value;
		break;
	default:
		nested_vmx_failValid(vcpu, VMXERR_UNSUPPORTED_VMCS_COMPONENT);
		skip_emulated_instruction(vcpu);
		return 1;
	}

	nested_vmx_succeed(vcpu);
	skip_emulated_instruction(vcpu);
	return 1;
}

/* Emulate the VMPTRLD instruction */
static int handle_vmptrld(struct kvm_vcpu *vcpu)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);
	gva_t gva;
	gpa_t vmcs12_addr;

	if (!nested_vmx_check_permission(vcpu))
		return 1;

	if (get_vmx_mem_address(vcpu, vmcs_readl(EXIT_QUALIFICATION),
			vmcs_read32(VMX_INSTRUCTION_INFO), &gva))
		return 1;

	if (kvm_read_guest_virt(gva, &vmcs12_addr, sizeof(vmcs12_addr),
				vcpu, NULL)) {
		kvm_queue_exception(vcpu, PF_VECTOR);
		return 1;
	}

	if (!IS_ALIGNED(vmcs12_addr, PAGE_SIZE)) {
		nested_vmx_failValid(vcpu, VMXERR_VMPTRLD_INVALID_ADDRESS);
		skip_emulated_instruction(vcpu);
		return 1;
	}

	if (vmx->nested.current_vmptr != vmcs12_addr) {
		struct vmcs12 *new_vmcs12;
		struct page *page;
		page = nested_get_page(vcpu, vmcs12_addr);
		if (page == NULL) {
			nested_vmx_failInvalid(vcpu);
			skip_emulated_instruction(vcpu);
			return 1;
		}
		new_vmcs12 = kmap(page);
		if (new_vmcs12->revision_id != VMCS12_REVISION) {
			kunmap(page);
			nested_release_page_clean(page);
			nested_vmx_failValid(vcpu,
				VMXERR_VMPTRLD_INCORRECT_VMCS_REVISION_ID);
			skip_emulated_instruction(vcpu);
			return 1;
		}
		if (vmx->nested.current_vmptr != -1ull) {
			kunmap(vmx->nested.current_vmcs12_page);
			nested_release_page(vmx->nested.current_vmcs12_page);
		}

		vmx->nested.current_vmptr = vmcs12_addr;
		vmx->nested.current_vmcs12 = new_vmcs12;
		vmx->nested.current_vmcs12_page = page;

		if (nested_create_current_vmcs(vcpu))
			return -ENOMEM;
	}

	nested_vmx_succeed(vcpu);
	skip_emulated_instruction(vcpu);
	return 1;
}

/* Emulate the VMPTRST instruction */
static int handle_vmptrst(struct kvm_vcpu *vcpu)
{
	unsigned long exit_qualification = vmcs_readl(EXIT_QUALIFICATION);
	u32 vmx_instruction_info = vmcs_read32(VMX_INSTRUCTION_INFO);
	gva_t vmcs_gva;

	if (!nested_vmx_check_permission(vcpu))
		return 1;

	if (get_vmx_mem_address(vcpu, exit_qualification,
			vmx_instruction_info, &vmcs_gva))
		return 1;
	/* ok to use *_system, because handle_vmread verified cpl=0 */
	if (kvm_write_guest_virt_system(vmcs_gva,
				 (void *)&to_vmx(vcpu)->nested.current_vmptr,
				 sizeof(u64), vcpu, NULL)) {
		kvm_queue_exception(vcpu, PF_VECTOR);
		return 1;
	}
	nested_vmx_succeed(vcpu);
	skip_emulated_instruction(vcpu);
	return 1;
}

/*
 * The exit handlers return 1 if the exit was handled fully and guest execution
 * may resume.  Otherwise they set the kvm_run parameter to indicate what needs
 * to be done to userspace and return 0.
 */
static int (*kvm_vmx_exit_handlers[])(struct kvm_vcpu *vcpu) = {
	[EXIT_REASON_EXCEPTION_NMI]           = handle_exception,
	[EXIT_REASON_EXTERNAL_INTERRUPT]      = handle_external_interrupt,
	[EXIT_REASON_TRIPLE_FAULT]            = handle_triple_fault,
	[EXIT_REASON_NMI_WINDOW]	      = handle_nmi_window,
	[EXIT_REASON_IO_INSTRUCTION]          = handle_io,
	[EXIT_REASON_CR_ACCESS]               = handle_cr,
	[EXIT_REASON_DR_ACCESS]               = handle_dr,
	[EXIT_REASON_CPUID]                   = handle_cpuid,
	[EXIT_REASON_MSR_READ]                = handle_rdmsr,
	[EXIT_REASON_MSR_WRITE]               = handle_wrmsr,
	[EXIT_REASON_PENDING_INTERRUPT]       = handle_interrupt_window,
	[EXIT_REASON_HLT]                     = handle_halt,
	[EXIT_REASON_INVD]		      = handle_invd,
	[EXIT_REASON_INVLPG]		      = handle_invlpg,
	[EXIT_REASON_VMCALL]                  = handle_vmcall,
	[EXIT_REASON_VMCLEAR]	              = handle_vmclear,
	[EXIT_REASON_VMLAUNCH]                = handle_vmlaunch,
	[EXIT_REASON_VMPTRLD]                 = handle_vmptrld,
	[EXIT_REASON_VMPTRST]                 = handle_vmptrst,
	[EXIT_REASON_VMREAD]                  = handle_vmread,
	[EXIT_REASON_VMRESUME]                = handle_vmresume,
	[EXIT_REASON_VMWRITE]                 = handle_vmwrite,
	[EXIT_REASON_VMOFF]                   = handle_vmoff,
	[EXIT_REASON_VMON]                    = handle_vmon,
	[EXIT_REASON_TPR_BELOW_THRESHOLD]     = handle_tpr_below_threshold,
	[EXIT_REASON_APIC_ACCESS]             = handle_apic_access,
	[EXIT_REASON_WBINVD]                  = handle_wbinvd,
	[EXIT_REASON_XSETBV]                  = handle_xsetbv,
	[EXIT_REASON_TASK_SWITCH]             = handle_task_switch,
	[EXIT_REASON_MCE_DURING_VMENTRY]      = handle_machine_check,
	[EXIT_REASON_EPT_VIOLATION]	      = handle_ept_violation,
	[EXIT_REASON_EPT_MISCONFIG]           = handle_ept_misconfig,
	[EXIT_REASON_PAUSE_INSTRUCTION]       = handle_pause,
	[EXIT_REASON_MWAIT_INSTRUCTION]	      = handle_invalid_op,
	[EXIT_REASON_MONITOR_INSTRUCTION]     = handle_invalid_op,
};

static const int kvm_vmx_max_exit_handlers =
	ARRAY_SIZE(kvm_vmx_exit_handlers);

/*
 * Return 1 if we should exit from L2 to L1 to handle an MSR access access,
 * rather than handle it ourselves in L0. I.e., check L1's MSR bitmap whether
 * it expressed interest in the current event (read or write a specific MSR).
 */
static bool nested_vmx_exit_handled_msr(struct kvm_vcpu *vcpu,
	struct vmcs_fields *vmcs12, u32 exit_reason)
{
	u32 msr_index = vcpu->arch.regs[VCPU_REGS_RCX];
	struct page *msr_bitmap_page;
	void *va;
	bool ret;

	if (!cpu_has_vmx_msr_bitmap() || !nested_cpu_has_vmx_msr_bitmap(vcpu))
		return 1;

	msr_bitmap_page = nested_get_page(vcpu, vmcs12->msr_bitmap);
	if (!msr_bitmap_page) {
		printk(KERN_INFO "%s error in nested_get_page\n", __func__);
		return 0;
	}

	va = kmap_atomic(msr_bitmap_page, KM_USER1);
	if (exit_reason == EXIT_REASON_MSR_WRITE)
		va += 0x800;
	if (msr_index >= 0xc0000000) {
		msr_index -= 0xc0000000;
		va += 0x400;
	}
	if (msr_index <= 0x1fff)
		ret = test_bit(msr_index, va);
	else
		ret = 1; /* let L1 handle the wrong parameter */
	kunmap_atomic(va, KM_USER1);
	nested_release_page_clean(msr_bitmap_page);
	return ret;
}

/*
 * Return 1 if we should exit from L2 to L1 to handle a CR access exit,
 * rather than handle it ourselves in L0. I.e., check if L1 wanted to
 * intercept (via guest_host_mask etc.) the current event.
 */
static bool nested_vmx_exit_handled_cr(struct kvm_vcpu *vcpu,
	struct vmcs_fields *vmcs12)
{
	unsigned long exit_qualification = vmcs_readl(EXIT_QUALIFICATION);
	int cr = exit_qualification & 15;
	int reg = (exit_qualification >> 8) & 15;
	unsigned long val = kvm_register_read(vcpu, reg);

	switch ((exit_qualification >> 4) & 3) {
	case 0: /* mov to cr */
		switch (cr) {
		case 0:
			if (vmcs12->cr0_guest_host_mask &
			    (val ^ vmcs12->cr0_read_shadow))
				return 1;
			break;
		case 3:
			if ((vmcs12->cr3_target_count >= 1 &&
					vmcs12->cr3_target_value0 == val) ||
				(vmcs12->cr3_target_count >= 2 &&
					vmcs12->cr3_target_value1 == val) ||
				(vmcs12->cr3_target_count >= 3 &&
					vmcs12->cr3_target_value2 == val) ||
				(vmcs12->cr3_target_count >= 4 &&
					vmcs12->cr3_target_value3 == val))
				return 0;
			if (nested_cpu_has_secondary_exec_ctrls(vcpu) &&
				(vmcs12->cpu_based_vm_exec_control &
				CPU_BASED_CR3_LOAD_EXITING)) {
				return 1;
			}
			break;
		case 4:
			if (vmcs12->cr4_guest_host_mask &
			    (vmcs12->cr4_read_shadow ^ val))
				return 1;
			break;
		case 8:
			if (nested_cpu_has_secondary_exec_ctrls(vcpu) &&
				(vmcs12->cpu_based_vm_exec_control &
				CPU_BASED_CR8_LOAD_EXITING))
				return 1;
			/*
			 * TODO: missing else if control & CPU_BASED_TPR_SHADOW
			 * then set tpr shadow and if below tpr_threshold, exit.
			 */
			break;
		}
		break;
	case 2: /* clts */
		if (vmcs12->cr0_guest_host_mask & X86_CR0_TS)
			return 1;
		break;
	case 1: /* mov from cr */
		switch (cr) {
		case 0:
			return 1;
		case 3:
			if (vmcs12->cpu_based_vm_exec_control &
			    CPU_BASED_CR3_STORE_EXITING)
				return 1;
			break;
		case 4:
			return 1;
			break;
		case 8:
			if (vmcs12->cpu_based_vm_exec_control &
			    CPU_BASED_CR8_STORE_EXITING)
				return 1;
			break;
		}
		break;
	case 3: /* lmsw */
		/*
		 * lmsw can change bits 1..3 of cr0, and only set bit 0 of
		 * cr0. Other attempted changes are ignored, with no exit.
		 */
		if (vmcs12->cr0_guest_host_mask & 0xe &
		    (val ^ vmcs12->cr0_read_shadow))
			return 1;
		if ((vmcs12->cr0_guest_host_mask & 0x1) &&
		    !(vmcs12->cr0_read_shadow & 0x1) &&
		    (val & 0x1))
			return 1;
		break;
	}
	return 0;
}

/*
 * Return 1 if we should exit from L2 to L1 to handle an exit, or 0 if we
 * should handle it ourselves in L0 (and then continue L2). Only call this
 * when in is_guest_mode (L2).
 */
static bool nested_vmx_exit_handled(struct kvm_vcpu *vcpu)
{
	u32 exit_reason = vmcs_read32(VM_EXIT_REASON);
	u32 intr_info = vmcs_read32(VM_EXIT_INTR_INFO);
	struct vcpu_vmx *vmx = to_vmx(vcpu);
	struct vmcs_fields *vmcs12 = get_vmcs12_fields(vcpu);

	if (vmx->nested.nested_run_pending)
		return 0;

	if (unlikely(vmx->fail)) {
		printk(KERN_INFO "%s failed vm entry %x\n",
		       __func__, vmcs_read32(VM_INSTRUCTION_ERROR));
		return 1;
	}

	switch (exit_reason) {
	case EXIT_REASON_EXTERNAL_INTERRUPT:
		return 0;
	case EXIT_REASON_EXCEPTION_NMI:
		if (!is_exception(intr_info))
			return 0;
		else if (is_page_fault(intr_info))
			return enable_ept;
		return vmcs12->exception_bitmap &
				(1u << (intr_info & INTR_INFO_VECTOR_MASK));
	case EXIT_REASON_EPT_VIOLATION:
		return 0;
	case EXIT_REASON_INVLPG:
		return vmcs12->cpu_based_vm_exec_control &
				CPU_BASED_INVLPG_EXITING;
	case EXIT_REASON_MSR_READ:
	case EXIT_REASON_MSR_WRITE:
		return nested_vmx_exit_handled_msr(vcpu, vmcs12, exit_reason);
	case EXIT_REASON_CR_ACCESS:
		return nested_vmx_exit_handled_cr(vcpu, vmcs12);
	case EXIT_REASON_DR_ACCESS:
		return vmcs12->cpu_based_vm_exec_control &
				CPU_BASED_MOV_DR_EXITING;
	default:
		/*
		 * One particularly interesting case that is covered here is an
		 * exit caused by L2 running a VMX instruction. L2 is guest
		 * mode in L1's world, and according to the VMX spec running a
		 * VMX instruction in guest mode should cause an exit to root
		 * mode, i.e., to L1. This is why we need to return r=1 for
		 * those exit reasons too. This enables further nesting: Like
		 * L0 emulates VMX for L1, we now allow L1 to emulate VMX for
		 * L2, who will then be able to run L3.
		 */
		return 1;
	}
}

static void vmx_get_exit_info(struct kvm_vcpu *vcpu, u64 *info1, u64 *info2)
{
	*info1 = vmcs_readl(EXIT_QUALIFICATION);
	*info2 = vmcs_read32(VM_EXIT_INTR_INFO);
}

/*
 * The guest has exited.  See if we can fix it or if we need userspace
 * assistance.
 */
static int vmx_handle_exit(struct kvm_vcpu *vcpu)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);
	u32 exit_reason = vmx->exit_reason;
	u32 vectoring_info = vmx->idt_vectoring_info;

	trace_kvm_exit(exit_reason, vcpu, KVM_ISA_VMX);

	/* If guest state is invalid, start emulating */
	if (vmx->emulation_required && emulate_invalid_guest_state)
		return handle_invalid_guest_state(vcpu);

	/*
	 * the KVM_REQ_EVENT optimization bit is only on for one entry, and if
	 * we did not inject a still-pending event to L1 now because of
	 * nested_run_pending, we need to re-enable this bit.
	 */
	if (vmx->nested.nested_run_pending)
		kvm_make_request(KVM_REQ_EVENT, vcpu);

	if (exit_reason == EXIT_REASON_VMLAUNCH ||
	    exit_reason == EXIT_REASON_VMRESUME)
		vmx->nested.nested_run_pending = 1;
	else
		vmx->nested.nested_run_pending = 0;

	if (is_guest_mode(vcpu) && nested_vmx_exit_handled(vcpu)) {
		nested_vmx_vmexit(vcpu, false);
		return 1;
	}

	if (exit_reason & VMX_EXIT_REASONS_FAILED_VMENTRY) {
		vcpu->run->exit_reason = KVM_EXIT_FAIL_ENTRY;
		vcpu->run->fail_entry.hardware_entry_failure_reason
			= exit_reason;
		return 0;
	}

	if (unlikely(vmx->fail)) {
		vcpu->run->exit_reason = KVM_EXIT_FAIL_ENTRY;
		vcpu->run->fail_entry.hardware_entry_failure_reason
			= vmcs_read32(VM_INSTRUCTION_ERROR);
		return 0;
	}

	if ((vectoring_info & VECTORING_INFO_VALID_MASK) &&
			(exit_reason != EXIT_REASON_EXCEPTION_NMI &&
			exit_reason != EXIT_REASON_EPT_VIOLATION &&
			exit_reason != EXIT_REASON_TASK_SWITCH))
		printk(KERN_WARNING "%s: unexpected, valid vectoring info "
		       "(0x%x) and exit reason is 0x%x\n",
		       __func__, vectoring_info, exit_reason);

	if (!is_guest_mode(vcpu) &&
	    unlikely(!cpu_has_virtual_nmis() && vmx->soft_vnmi_blocked)) {
		if (vmx_interrupt_allowed(vcpu)) {
			vmx->soft_vnmi_blocked = 0;
		} else if (vmx->vnmi_blocked_time > 1000000000LL &&
			   vcpu->arch.nmi_pending) {
			/*
			 * This CPU don't support us in finding the end of an
			 * NMI-blocked window if the guest runs with IRQs
			 * disabled. So we pull the trigger after 1 s of
			 * futile waiting, but inform the user about this.
			 */
			printk(KERN_WARNING "%s: Breaking out of NMI-blocked "
			       "state on VCPU %d after 1 s timeout\n",
			       __func__, vcpu->vcpu_id);
			vmx->soft_vnmi_blocked = 0;
		}
	}

	if (exit_reason < kvm_vmx_max_exit_handlers
	    && kvm_vmx_exit_handlers[exit_reason])
		return kvm_vmx_exit_handlers[exit_reason](vcpu);
	else {
		vcpu->run->exit_reason = KVM_EXIT_UNKNOWN;
		vcpu->run->hw.hardware_exit_reason = exit_reason;
	}
	return 0;
}

static void update_cr8_intercept(struct kvm_vcpu *vcpu, int tpr, int irr)
{
	if (irr == -1 || tpr < irr) {
		vmcs_write32(TPR_THRESHOLD, 0);
		return;
	}

	vmcs_write32(TPR_THRESHOLD, irr);
}

static void vmx_complete_atomic_exit(struct vcpu_vmx *vmx)
{
	u32 exit_intr_info = vmx->exit_intr_info;

	/* Handle machine checks before interrupts are enabled */
	if ((vmx->exit_reason == EXIT_REASON_MCE_DURING_VMENTRY)
	    || (vmx->exit_reason == EXIT_REASON_EXCEPTION_NMI
		&& is_machine_check(exit_intr_info)))
		kvm_machine_check();

	/* We need to handle NMIs before interrupts are enabled */
	if ((exit_intr_info & INTR_INFO_INTR_TYPE_MASK) == INTR_TYPE_NMI_INTR &&
	    (exit_intr_info & INTR_INFO_VALID_MASK)) {
		kvm_before_handle_nmi(&vmx->vcpu);
		asm("int $2");
		kvm_after_handle_nmi(&vmx->vcpu);
	}
}

static void vmx_recover_nmi_blocking(struct vcpu_vmx *vmx)
{
	u32 exit_intr_info = vmx->exit_intr_info;
	bool unblock_nmi;
	u8 vector;
	bool idtv_info_valid;

	idtv_info_valid = vmx->idt_vectoring_info & VECTORING_INFO_VALID_MASK;

	if (cpu_has_virtual_nmis()) {
		unblock_nmi = (exit_intr_info & INTR_INFO_UNBLOCK_NMI) != 0;
		vector = exit_intr_info & INTR_INFO_VECTOR_MASK;
		/*
		 * SDM 3: 27.7.1.2 (September 2008)
		 * Re-set bit "block by NMI" before VM entry if vmexit caused by
		 * a guest IRET fault.
		 * SDM 3: 23.2.2 (September 2008)
		 * Bit 12 is undefined in any of the following cases:
		 *  If the VM exit sets the valid bit in the IDT-vectoring
		 *   information field.
		 *  If the VM exit is due to a double fault.
		 */
		if ((exit_intr_info & INTR_INFO_VALID_MASK) && unblock_nmi &&
		    vector != DF_VECTOR && !idtv_info_valid)
			vmcs_set_bits(GUEST_INTERRUPTIBILITY_INFO,
				      GUEST_INTR_STATE_NMI);
	} else if (unlikely(vmx->soft_vnmi_blocked))
		vmx->vnmi_blocked_time +=
			ktime_to_ns(ktime_sub(ktime_get(), vmx->entry_time));
}

static void __vmx_complete_interrupts(struct vcpu_vmx *vmx,
				      u32 idt_vectoring_info,
				      int instr_len_field,
				      int error_code_field)
{
	u8 vector;
	int type;
	bool idtv_info_valid;

	idtv_info_valid = idt_vectoring_info & VECTORING_INFO_VALID_MASK;

	vmx->vcpu.arch.nmi_injected = false;
	kvm_clear_exception_queue(&vmx->vcpu);
	kvm_clear_interrupt_queue(&vmx->vcpu);

	if (!idtv_info_valid)
		return;

	kvm_make_request(KVM_REQ_EVENT, &vmx->vcpu);

	vector = idt_vectoring_info & VECTORING_INFO_VECTOR_MASK;
	type = idt_vectoring_info & VECTORING_INFO_TYPE_MASK;

	switch (type) {
	case INTR_TYPE_NMI_INTR:
		vmx->vcpu.arch.nmi_injected = true;
		/*
		 * SDM 3: 27.7.1.2 (September 2008)
		 * Clear bit "block by NMI" before VM entry if a NMI
		 * delivery faulted.
		 */
		vmcs_clear_bits(GUEST_INTERRUPTIBILITY_INFO,
				GUEST_INTR_STATE_NMI);
		break;
	case INTR_TYPE_SOFT_EXCEPTION:
		vmx->vcpu.arch.event_exit_inst_len =
			vmcs_read32(instr_len_field);
		/* fall through */
	case INTR_TYPE_HARD_EXCEPTION:
		if (idt_vectoring_info & VECTORING_INFO_DELIVER_CODE_MASK) {
			u32 err = vmcs_read32(error_code_field);
			kvm_queue_exception_e(&vmx->vcpu, vector, err);
		} else
			kvm_queue_exception(&vmx->vcpu, vector);
		break;
	case INTR_TYPE_SOFT_INTR:
		vmx->vcpu.arch.event_exit_inst_len =
			vmcs_read32(instr_len_field);
		/* fall through */
	case INTR_TYPE_EXT_INTR:
		kvm_queue_interrupt(&vmx->vcpu, vector,
			type == INTR_TYPE_SOFT_INTR);
		break;
	default:
		break;
	}
}

static void vmx_complete_interrupts(struct vcpu_vmx *vmx)
{
	if (is_guest_mode(&vmx->vcpu))
		return;
	__vmx_complete_interrupts(vmx, vmx->idt_vectoring_info,
				  VM_EXIT_INSTRUCTION_LEN,
				  IDT_VECTORING_ERROR_CODE);
}

static void vmx_cancel_injection(struct kvm_vcpu *vcpu)
{
	if (is_guest_mode(vcpu))
		return;
	__vmx_complete_interrupts(to_vmx(vcpu),
				  vmcs_read32(VM_ENTRY_INTR_INFO_FIELD),
				  VM_ENTRY_INSTRUCTION_LEN,
				  VM_ENTRY_EXCEPTION_ERROR_CODE);

	vmcs_write32(VM_ENTRY_INTR_INFO_FIELD, 0);
}

static void nested_handle_valid_idt_vectoring_info(struct vcpu_vmx *vmx)
{
	int irq  = vmx->idt_vectoring_info & VECTORING_INFO_VECTOR_MASK;
	int type = vmx->idt_vectoring_info & VECTORING_INFO_TYPE_MASK;
	int errCodeValid = vmx->idt_vectoring_info &
		VECTORING_INFO_DELIVER_CODE_MASK;
	vmcs_write32(VM_ENTRY_INTR_INFO_FIELD,
		irq | type | INTR_INFO_VALID_MASK | errCodeValid);

	vmcs_write32(VM_ENTRY_INSTRUCTION_LEN,
		vmx->nested.vm_exit_instruction_len);
	if (errCodeValid)
		vmcs_write32(VM_ENTRY_EXCEPTION_ERROR_CODE,
			vmx->nested.idt_vectoring_error_code);
}

static inline void sync_cached_regs_to_vmcs(struct kvm_vcpu *vcpu)
{
	if (test_bit(VCPU_REGS_RSP, (unsigned long *)&vcpu->arch.regs_dirty))
		vmcs_writel(GUEST_RSP, vcpu->arch.regs[VCPU_REGS_RSP]);
	if (test_bit(VCPU_REGS_RIP, (unsigned long *)&vcpu->arch.regs_dirty))
		vmcs_writel(GUEST_RIP, vcpu->arch.regs[VCPU_REGS_RIP]);
	vcpu->arch.regs_dirty = 0;
}

#ifdef CONFIG_X86_64
#define R "r"
#define Q "q"
#else
#define R "e"
#define Q "l"
#endif

static void vmx_vcpu_run(struct kvm_vcpu *vcpu)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);

	if (is_guest_mode(vcpu) && vmx->nested.valid_idt_vectoring_info)
		nested_handle_valid_idt_vectoring_info(vmx);

	/* Record the guest's net vcpu time for enforced NMI injections. */
	if (unlikely(!cpu_has_virtual_nmis() && vmx->soft_vnmi_blocked))
		vmx->entry_time = ktime_get();

	/* Don't enter VMX if guest state is invalid, let the exit handler
	   start emulation until we arrive back to a valid state */
	if (vmx->emulation_required && emulate_invalid_guest_state)
		return;

	sync_cached_regs_to_vmcs(vcpu);

	/* When single-stepping over STI and MOV SS, we must clear the
	 * corresponding interruptibility bits in the guest state. Otherwise
	 * vmentry fails as it then expects bit 14 (BS) in pending debug
	 * exceptions being set, but that's not correct for the guest debugging
	 * case. */
	if (vcpu->guest_debug & KVM_GUESTDBG_SINGLESTEP)
		vmx_set_interrupt_shadow(vcpu, 0);

	asm(
		/* Store host registers */
		"push %%"R"dx; push %%"R"bp;"
		"push %%"R"cx \n\t" /* placeholder for guest rcx */
		"push %%"R"cx \n\t"
		"cmp %%"R"sp, %c[host_rsp](%0) \n\t"
		"je 1f \n\t"
		"mov %%"R"sp, %c[host_rsp](%0) \n\t"
		__ex(ASM_VMX_VMWRITE_RSP_RDX) "\n\t"
		"1: \n\t"
		/* Reload cr2 if changed */
		"mov %c[cr2](%0), %%"R"ax \n\t"
		"mov %%cr2, %%"R"dx \n\t"
		"cmp %%"R"ax, %%"R"dx \n\t"
		"je 2f \n\t"
		"mov %%"R"ax, %%cr2 \n\t"
		"2: \n\t"
		/* Check if vmlaunch of vmresume is needed */
		"cmpl $0, %c[launched](%0) \n\t"
		/* Load guest registers.  Don't clobber flags. */
		"mov %c[rax](%0), %%"R"ax \n\t"
		"mov %c[rbx](%0), %%"R"bx \n\t"
		"mov %c[rdx](%0), %%"R"dx \n\t"
		"mov %c[rsi](%0), %%"R"si \n\t"
		"mov %c[rdi](%0), %%"R"di \n\t"
		"mov %c[rbp](%0), %%"R"bp \n\t"
#ifdef CONFIG_X86_64
		"mov %c[r8](%0),  %%r8  \n\t"
		"mov %c[r9](%0),  %%r9  \n\t"
		"mov %c[r10](%0), %%r10 \n\t"
		"mov %c[r11](%0), %%r11 \n\t"
		"mov %c[r12](%0), %%r12 \n\t"
		"mov %c[r13](%0), %%r13 \n\t"
		"mov %c[r14](%0), %%r14 \n\t"
		"mov %c[r15](%0), %%r15 \n\t"
#endif
		"mov %c[rcx](%0), %%"R"cx \n\t" /* kills %0 (ecx) */

		/* Enter guest mode */
		"jne .Llaunched \n\t"
		__ex(ASM_VMX_VMLAUNCH) "\n\t"
		"jmp .Lkvm_vmx_return \n\t"
		".Llaunched: " __ex(ASM_VMX_VMRESUME) "\n\t"
		".Lkvm_vmx_return: "
		/* Save guest registers, load host registers, keep flags */
		"mov %0, %c[wordsize](%%"R"sp) \n\t"
		"pop %0 \n\t"
		"mov %%"R"ax, %c[rax](%0) \n\t"
		"mov %%"R"bx, %c[rbx](%0) \n\t"
		"pop"Q" %c[rcx](%0) \n\t"
		"mov %%"R"dx, %c[rdx](%0) \n\t"
		"mov %%"R"si, %c[rsi](%0) \n\t"
		"mov %%"R"di, %c[rdi](%0) \n\t"
		"mov %%"R"bp, %c[rbp](%0) \n\t"
#ifdef CONFIG_X86_64
		"mov %%r8,  %c[r8](%0) \n\t"
		"mov %%r9,  %c[r9](%0) \n\t"
		"mov %%r10, %c[r10](%0) \n\t"
		"mov %%r11, %c[r11](%0) \n\t"
		"mov %%r12, %c[r12](%0) \n\t"
		"mov %%r13, %c[r13](%0) \n\t"
		"mov %%r14, %c[r14](%0) \n\t"
		"mov %%r15, %c[r15](%0) \n\t"
#endif
		"mov %%cr2, %%"R"ax   \n\t"
		"mov %%"R"ax, %c[cr2](%0) \n\t"

		"pop  %%"R"bp; pop  %%"R"dx \n\t"
		"setbe %c[fail](%0) \n\t"
	      : : "c"(vmx), "d"((unsigned long)HOST_RSP),
		[launched]"i"(offsetof(struct vcpu_vmx, launched)),
		[fail]"i"(offsetof(struct vcpu_vmx, fail)),
		[host_rsp]"i"(offsetof(struct vcpu_vmx, host_rsp)),
		[rax]"i"(offsetof(struct vcpu_vmx, vcpu.arch.regs[VCPU_REGS_RAX])),
		[rbx]"i"(offsetof(struct vcpu_vmx, vcpu.arch.regs[VCPU_REGS_RBX])),
		[rcx]"i"(offsetof(struct vcpu_vmx, vcpu.arch.regs[VCPU_REGS_RCX])),
		[rdx]"i"(offsetof(struct vcpu_vmx, vcpu.arch.regs[VCPU_REGS_RDX])),
		[rsi]"i"(offsetof(struct vcpu_vmx, vcpu.arch.regs[VCPU_REGS_RSI])),
		[rdi]"i"(offsetof(struct vcpu_vmx, vcpu.arch.regs[VCPU_REGS_RDI])),
		[rbp]"i"(offsetof(struct vcpu_vmx, vcpu.arch.regs[VCPU_REGS_RBP])),
#ifdef CONFIG_X86_64
		[r8]"i"(offsetof(struct vcpu_vmx, vcpu.arch.regs[VCPU_REGS_R8])),
		[r9]"i"(offsetof(struct vcpu_vmx, vcpu.arch.regs[VCPU_REGS_R9])),
		[r10]"i"(offsetof(struct vcpu_vmx, vcpu.arch.regs[VCPU_REGS_R10])),
		[r11]"i"(offsetof(struct vcpu_vmx, vcpu.arch.regs[VCPU_REGS_R11])),
		[r12]"i"(offsetof(struct vcpu_vmx, vcpu.arch.regs[VCPU_REGS_R12])),
		[r13]"i"(offsetof(struct vcpu_vmx, vcpu.arch.regs[VCPU_REGS_R13])),
		[r14]"i"(offsetof(struct vcpu_vmx, vcpu.arch.regs[VCPU_REGS_R14])),
		[r15]"i"(offsetof(struct vcpu_vmx, vcpu.arch.regs[VCPU_REGS_R15])),
#endif
		[cr2]"i"(offsetof(struct vcpu_vmx, vcpu.arch.cr2)),
		[wordsize]"i"(sizeof(ulong))
	      : "cc", "memory"
		, R"ax", R"bx", R"di", R"si"
#ifdef CONFIG_X86_64
		, "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"
#endif
	      );

	vcpu->arch.regs_avail = ~((1 << VCPU_REGS_RIP) | (1 << VCPU_REGS_RSP)
				  | (1 << VCPU_EXREG_PDPTR)
				  | (1 << VCPU_EXREG_CR3));

	vmx->idt_vectoring_info = vmcs_read32(IDT_VECTORING_INFO_FIELD);

	vmx->nested.valid_idt_vectoring_info = is_guest_mode(vcpu) &&
		(vmx->idt_vectoring_info & VECTORING_INFO_VALID_MASK);
	if (vmx->nested.valid_idt_vectoring_info) {
		vmx->nested.vm_exit_instruction_len =
			vmcs_read32(VM_EXIT_INSTRUCTION_LEN);
		vmx->nested.idt_vectoring_error_code =
			vmcs_read32(IDT_VECTORING_ERROR_CODE);
	}

	asm("mov %0, %%ds; mov %0, %%es" : : "r"(__USER_DS));
	vmx->launched = 1;

	vmx->exit_reason = vmcs_read32(VM_EXIT_REASON);
	vmx->exit_intr_info = vmcs_read32(VM_EXIT_INTR_INFO);

	vmx_complete_atomic_exit(vmx);
	vmx_recover_nmi_blocking(vmx);
	vmx_complete_interrupts(vmx);
}

#undef R
#undef Q

static void vmx_free_vmcs(struct kvm_vcpu *vcpu)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);

	if (vmx->vmcs) {
		vcpu_clear(vmx);
		free_vmcs(vmx->vmcs);
		vmx->vmcs = NULL;
	}
}

static void vmx_free_vcpu(struct kvm_vcpu *vcpu)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);

	free_vpid(vmx);
	free_nested(vmx);
	vmx_free_vmcs(vcpu);
	kfree(vmx->guest_msrs);
	kvm_vcpu_uninit(vcpu);
	kmem_cache_free(kvm_vcpu_cache, vmx);
}

static inline void vmcs_init(struct vmcs *vmcs)
{
	u64 phys_addr = __pa(per_cpu(vmxarea, raw_smp_processor_id()));

	if (!vmm_exclusive)
		kvm_cpu_vmxon(phys_addr);

	vmcs_clear(vmcs);

	if (!vmm_exclusive)
		kvm_cpu_vmxoff();
}

static struct kvm_vcpu *vmx_create_vcpu(struct kvm *kvm, unsigned int id)
{
	int err;
	struct vcpu_vmx *vmx = kmem_cache_zalloc(kvm_vcpu_cache, GFP_KERNEL);
	int cpu;

	if (!vmx)
		return ERR_PTR(-ENOMEM);

	allocate_vpid(vmx);

	err = kvm_vcpu_init(&vmx->vcpu, kvm, id);
	if (err)
		goto free_vcpu;

	vmx->guest_msrs = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (!vmx->guest_msrs) {
		err = -ENOMEM;
		goto uninit_vcpu;
	}

	vmx->vmcs = alloc_vmcs();
	if (!vmx->vmcs)
		goto free_msrs;

	vmcs_init(vmx->vmcs);

	cpu = get_cpu();
	vmx_vcpu_load(&vmx->vcpu, cpu);
	vmx->vcpu.cpu = cpu;
	err = vmx_vcpu_setup(vmx);
	vmx_vcpu_put(&vmx->vcpu);
	put_cpu();
	if (err)
		goto free_vmcs;
	if (vm_need_virtualize_apic_accesses(kvm))
		if (alloc_apic_access_page(kvm) != 0)
			goto free_vmcs;

	if (enable_ept) {
		if (!kvm->arch.ept_identity_map_addr)
			kvm->arch.ept_identity_map_addr =
				VMX_EPT_IDENTITY_PAGETABLE_ADDR;
		if (alloc_identity_pagetable(kvm) != 0)
			goto free_vmcs;
	}

	vmx->nested.current_vmptr = -1ull;
	vmx->nested.current_vmcs12 = NULL;

	return &vmx->vcpu;

free_vmcs:
	free_vmcs(vmx->vmcs);
free_msrs:
	kfree(vmx->guest_msrs);
uninit_vcpu:
	kvm_vcpu_uninit(&vmx->vcpu);
free_vcpu:
	free_vpid(vmx);
	kmem_cache_free(kvm_vcpu_cache, vmx);
	return ERR_PTR(err);
}

static void __init vmx_check_processor_compat(void *rtn)
{
	struct vmcs_config vmcs_conf;

	*(int *)rtn = 0;
	if (setup_vmcs_config(&vmcs_conf) < 0)
		*(int *)rtn = -EIO;
	if (memcmp(&vmcs_config, &vmcs_conf, sizeof(struct vmcs_config)) != 0) {
		printk(KERN_ERR "kvm: CPU %d feature inconsistency!\n",
				smp_processor_id());
		*(int *)rtn = -EIO;
	}
}

static int get_ept_level(void)
{
	return VMX_EPT_DEFAULT_GAW + 1;
}

static u64 vmx_get_mt_mask(struct kvm_vcpu *vcpu, gfn_t gfn, bool is_mmio)
{
	u64 ret;

	/* For VT-d and EPT combination
	 * 1. MMIO: always map as UC
	 * 2. EPT with VT-d:
	 *   a. VT-d without snooping control feature: can't guarantee the
	 *	result, try to trust guest.
	 *   b. VT-d with snooping control feature: snooping control feature of
	 *	VT-d engine can guarantee the cache correctness. Just set it
	 *	to WB to keep consistent with host. So the same as item 3.
	 * 3. EPT without VT-d: always map as WB and set IPAT=1 to keep
	 *    consistent with host MTRR
	 */
	if (is_mmio)
		ret = MTRR_TYPE_UNCACHABLE << VMX_EPT_MT_EPTE_SHIFT;
	else if (vcpu->kvm->arch.iommu_domain &&
		!(vcpu->kvm->arch.iommu_flags & KVM_IOMMU_CACHE_COHERENCY))
		ret = kvm_get_guest_memory_type(vcpu, gfn) <<
		      VMX_EPT_MT_EPTE_SHIFT;
	else
		ret = (MTRR_TYPE_WRBACK << VMX_EPT_MT_EPTE_SHIFT)
			| VMX_EPT_IPAT_BIT;

	return ret;
}

#define _ER(x) { EXIT_REASON_##x, #x }

static const struct trace_print_flags vmx_exit_reasons_str[] = {
	_ER(EXCEPTION_NMI),
	_ER(EXTERNAL_INTERRUPT),
	_ER(TRIPLE_FAULT),
	_ER(PENDING_INTERRUPT),
	_ER(NMI_WINDOW),
	_ER(TASK_SWITCH),
	_ER(CPUID),
	_ER(HLT),
	_ER(INVLPG),
	_ER(RDPMC),
	_ER(RDTSC),
	_ER(VMCALL),
	_ER(VMCLEAR),
	_ER(VMLAUNCH),
	_ER(VMPTRLD),
	_ER(VMPTRST),
	_ER(VMREAD),
	_ER(VMRESUME),
	_ER(VMWRITE),
	_ER(VMOFF),
	_ER(VMON),
	_ER(CR_ACCESS),
	_ER(DR_ACCESS),
	_ER(IO_INSTRUCTION),
	_ER(MSR_READ),
	_ER(MSR_WRITE),
	_ER(MWAIT_INSTRUCTION),
	_ER(MONITOR_INSTRUCTION),
	_ER(PAUSE_INSTRUCTION),
	_ER(MCE_DURING_VMENTRY),
	_ER(TPR_BELOW_THRESHOLD),
	_ER(APIC_ACCESS),
	_ER(EPT_VIOLATION),
	_ER(EPT_MISCONFIG),
	_ER(WBINVD),
	{ -1, NULL }
};

#undef _ER

static int vmx_get_lpage_level(void)
{
	if (enable_ept && !cpu_has_vmx_ept_1g_page())
		return PT_DIRECTORY_LEVEL;
	else
		/* For shadow and EPT supported 1GB page */
		return PT_PDPE_LEVEL;
}

static void vmx_cpuid_update(struct kvm_vcpu *vcpu)
{
	struct kvm_cpuid_entry2 *best;
	struct vcpu_vmx *vmx = to_vmx(vcpu);
	u32 exec_control;

	vmx->rdtscp_enabled = false;
	if (vmx_rdtscp_supported()) {
		exec_control = vmcs_read32(SECONDARY_VM_EXEC_CONTROL);
		if (exec_control & SECONDARY_EXEC_RDTSCP) {
			best = kvm_find_cpuid_entry(vcpu, 0x80000001, 0);
			if (best && (best->edx & bit(X86_FEATURE_RDTSCP)))
				vmx->rdtscp_enabled = true;
			else {
				exec_control &= ~SECONDARY_EXEC_RDTSCP;
				vmcs_write32(SECONDARY_VM_EXEC_CONTROL,
						exec_control);
			}
		}
	}
}

static void vmx_set_supported_cpuid(u32 func, struct kvm_cpuid_entry2 *entry)
{
	if (func == 1 && nested)
		entry->ecx |= bit(X86_FEATURE_VMX);
}

/*
 * Make a copy of the current VMCS to ordinary memory. This is needed because
 * in VMX you cannot read and write to two VMCS at the same time, so when we
 * want to do this (in prepare_vmcs02, which needs to read from vmcs01 while
 * preparing vmcs02), we need to first save a copy of one VMCS's fields in
 * memory, and then use that copy.
 */
void save_vmcs(struct vmcs_fields *dst)
{
	dst->guest_es_selector = vmcs_read16(GUEST_ES_SELECTOR);
	dst->guest_cs_selector = vmcs_read16(GUEST_CS_SELECTOR);
	dst->guest_ss_selector = vmcs_read16(GUEST_SS_SELECTOR);
	dst->guest_ds_selector = vmcs_read16(GUEST_DS_SELECTOR);
	dst->guest_fs_selector = vmcs_read16(GUEST_FS_SELECTOR);
	dst->guest_gs_selector = vmcs_read16(GUEST_GS_SELECTOR);
	dst->guest_ldtr_selector = vmcs_read16(GUEST_LDTR_SELECTOR);
	dst->guest_tr_selector = vmcs_read16(GUEST_TR_SELECTOR);
	dst->host_es_selector = vmcs_read16(HOST_ES_SELECTOR);
	dst->host_cs_selector = vmcs_read16(HOST_CS_SELECTOR);
	dst->host_ss_selector = vmcs_read16(HOST_SS_SELECTOR);
	dst->host_ds_selector = vmcs_read16(HOST_DS_SELECTOR);
	dst->host_fs_selector = vmcs_read16(HOST_FS_SELECTOR);
	dst->host_gs_selector = vmcs_read16(HOST_GS_SELECTOR);
	dst->host_tr_selector = vmcs_read16(HOST_TR_SELECTOR);
	dst->tsc_offset = vmcs_read64(TSC_OFFSET);
	dst->virtual_apic_page_addr = vmcs_read64(VIRTUAL_APIC_PAGE_ADDR);
	dst->apic_access_addr = vmcs_read64(APIC_ACCESS_ADDR);
	dst->guest_physical_address = vmcs_read64(GUEST_PHYSICAL_ADDRESS);
	dst->vmcs_link_pointer = vmcs_read64(VMCS_LINK_POINTER);
	dst->guest_ia32_debugctl = vmcs_read64(GUEST_IA32_DEBUGCTL);
	if (vmcs_config.vmentry_ctrl & VM_ENTRY_LOAD_IA32_PAT)
		dst->guest_ia32_pat = vmcs_read64(GUEST_IA32_PAT);
	if (enable_ept) {
		/* shadow pages tables on EPT */
		dst->ept_pointer = vmcs_read64(EPT_POINTER);
		dst->guest_pdptr0 = vmcs_read64(GUEST_PDPTR0);
		dst->guest_pdptr1 = vmcs_read64(GUEST_PDPTR1);
		dst->guest_pdptr2 = vmcs_read64(GUEST_PDPTR2);
		dst->guest_pdptr3 = vmcs_read64(GUEST_PDPTR3);
	}
	dst->pin_based_vm_exec_control = vmcs_read32(PIN_BASED_VM_EXEC_CONTROL);
	dst->cpu_based_vm_exec_control = vmcs_read32(CPU_BASED_VM_EXEC_CONTROL);
	dst->exception_bitmap = vmcs_read32(EXCEPTION_BITMAP);
	dst->page_fault_error_code_mask =
		vmcs_read32(PAGE_FAULT_ERROR_CODE_MASK);
	dst->page_fault_error_code_match =
		vmcs_read32(PAGE_FAULT_ERROR_CODE_MATCH);
	dst->cr3_target_count = vmcs_read32(CR3_TARGET_COUNT);
	dst->vm_exit_controls = vmcs_read32(VM_EXIT_CONTROLS);
	dst->vm_entry_controls = vmcs_read32(VM_ENTRY_CONTROLS);
	dst->vm_entry_intr_info_field = vmcs_read32(VM_ENTRY_INTR_INFO_FIELD);
	dst->vm_entry_exception_error_code =
		vmcs_read32(VM_ENTRY_EXCEPTION_ERROR_CODE);
	dst->vm_entry_instruction_len = vmcs_read32(VM_ENTRY_INSTRUCTION_LEN);
	dst->tpr_threshold = vmcs_read32(TPR_THRESHOLD);
	dst->secondary_vm_exec_control = vmcs_read32(SECONDARY_VM_EXEC_CONTROL);
	if (enable_vpid && dst->secondary_vm_exec_control &
	    SECONDARY_EXEC_ENABLE_VPID)
		dst->virtual_processor_id = vmcs_read16(VIRTUAL_PROCESSOR_ID);
	dst->vm_instruction_error = vmcs_read32(VM_INSTRUCTION_ERROR);
	dst->vm_exit_reason  = vmcs_read32(VM_EXIT_REASON);
	dst->vm_exit_intr_info = vmcs_read32(VM_EXIT_INTR_INFO);
	dst->vm_exit_intr_error_code = vmcs_read32(VM_EXIT_INTR_ERROR_CODE);
	dst->idt_vectoring_info_field = vmcs_read32(IDT_VECTORING_INFO_FIELD);
	dst->idt_vectoring_error_code = vmcs_read32(IDT_VECTORING_ERROR_CODE);
	dst->vm_exit_instruction_len = vmcs_read32(VM_EXIT_INSTRUCTION_LEN);
	dst->vmx_instruction_info = vmcs_read32(VMX_INSTRUCTION_INFO);
	dst->guest_es_limit = vmcs_read32(GUEST_ES_LIMIT);
	dst->guest_cs_limit = vmcs_read32(GUEST_CS_LIMIT);
	dst->guest_ss_limit = vmcs_read32(GUEST_SS_LIMIT);
	dst->guest_ds_limit = vmcs_read32(GUEST_DS_LIMIT);
	dst->guest_fs_limit = vmcs_read32(GUEST_FS_LIMIT);
	dst->guest_gs_limit = vmcs_read32(GUEST_GS_LIMIT);
	dst->guest_ldtr_limit = vmcs_read32(GUEST_LDTR_LIMIT);
	dst->guest_tr_limit = vmcs_read32(GUEST_TR_LIMIT);
	dst->guest_gdtr_limit = vmcs_read32(GUEST_GDTR_LIMIT);
	dst->guest_idtr_limit = vmcs_read32(GUEST_IDTR_LIMIT);
	dst->guest_es_ar_bytes = vmcs_read32(GUEST_ES_AR_BYTES);
	dst->guest_cs_ar_bytes = vmcs_read32(GUEST_CS_AR_BYTES);
	dst->guest_ss_ar_bytes = vmcs_read32(GUEST_SS_AR_BYTES);
	dst->guest_ds_ar_bytes = vmcs_read32(GUEST_DS_AR_BYTES);
	dst->guest_fs_ar_bytes = vmcs_read32(GUEST_FS_AR_BYTES);
	dst->guest_gs_ar_bytes = vmcs_read32(GUEST_GS_AR_BYTES);
	dst->guest_ldtr_ar_bytes = vmcs_read32(GUEST_LDTR_AR_BYTES);
	dst->guest_tr_ar_bytes = vmcs_read32(GUEST_TR_AR_BYTES);
	dst->guest_interruptibility_info =
		vmcs_read32(GUEST_INTERRUPTIBILITY_INFO);
	dst->guest_activity_state = vmcs_read32(GUEST_ACTIVITY_STATE);
	dst->guest_sysenter_cs = vmcs_read32(GUEST_SYSENTER_CS);
	dst->host_ia32_sysenter_cs = vmcs_read32(HOST_IA32_SYSENTER_CS);
	dst->cr0_guest_host_mask = vmcs_readl(CR0_GUEST_HOST_MASK);
	dst->cr4_guest_host_mask = vmcs_readl(CR4_GUEST_HOST_MASK);
	dst->cr0_read_shadow = vmcs_readl(CR0_READ_SHADOW);
	dst->cr4_read_shadow = vmcs_readl(CR4_READ_SHADOW);
	dst->cr3_target_value0 = vmcs_readl(CR3_TARGET_VALUE0);
	dst->cr3_target_value1 = vmcs_readl(CR3_TARGET_VALUE1);
	dst->cr3_target_value2 = vmcs_readl(CR3_TARGET_VALUE2);
	dst->cr3_target_value3 = vmcs_readl(CR3_TARGET_VALUE3);
	dst->exit_qualification = vmcs_readl(EXIT_QUALIFICATION);
	dst->guest_linear_address = vmcs_readl(GUEST_LINEAR_ADDRESS);
	dst->guest_cr0 = vmcs_readl(GUEST_CR0);
	dst->guest_cr3 = vmcs_readl(GUEST_CR3);
	dst->guest_cr4 = vmcs_readl(GUEST_CR4);
	dst->guest_es_base = vmcs_readl(GUEST_ES_BASE);
	dst->guest_cs_base = vmcs_readl(GUEST_CS_BASE);
	dst->guest_ss_base = vmcs_readl(GUEST_SS_BASE);
	dst->guest_ds_base = vmcs_readl(GUEST_DS_BASE);
	dst->guest_fs_base = vmcs_readl(GUEST_FS_BASE);
	dst->guest_gs_base = vmcs_readl(GUEST_GS_BASE);
	dst->guest_ldtr_base = vmcs_readl(GUEST_LDTR_BASE);
	dst->guest_tr_base = vmcs_readl(GUEST_TR_BASE);
	dst->guest_gdtr_base = vmcs_readl(GUEST_GDTR_BASE);
	dst->guest_idtr_base = vmcs_readl(GUEST_IDTR_BASE);
	dst->guest_dr7 = vmcs_readl(GUEST_DR7);
	dst->guest_rsp = vmcs_readl(GUEST_RSP);
	dst->guest_rip = vmcs_readl(GUEST_RIP);
	dst->guest_rflags = vmcs_readl(GUEST_RFLAGS);
	dst->guest_pending_dbg_exceptions =
		vmcs_readl(GUEST_PENDING_DBG_EXCEPTIONS);
	dst->guest_sysenter_esp = vmcs_readl(GUEST_SYSENTER_ESP);
	dst->guest_sysenter_eip = vmcs_readl(GUEST_SYSENTER_EIP);
	dst->host_cr0 = vmcs_readl(HOST_CR0);
	dst->host_cr3 = vmcs_readl(HOST_CR3);
	dst->host_cr4 = vmcs_readl(HOST_CR4);
	dst->host_fs_base = vmcs_readl(HOST_FS_BASE);
	dst->host_gs_base = vmcs_readl(HOST_GS_BASE);
	dst->host_tr_base = vmcs_readl(HOST_TR_BASE);
	dst->host_gdtr_base = vmcs_readl(HOST_GDTR_BASE);
	dst->host_idtr_base = vmcs_readl(HOST_IDTR_BASE);
	dst->host_ia32_sysenter_esp = vmcs_readl(HOST_IA32_SYSENTER_ESP);
	dst->host_ia32_sysenter_eip = vmcs_readl(HOST_IA32_SYSENTER_EIP);
	dst->host_rsp = vmcs_readl(HOST_RSP);
	dst->host_rip = vmcs_readl(HOST_RIP);
	if (vmcs_config.vmexit_ctrl & VM_EXIT_LOAD_IA32_PAT)
		dst->host_ia32_pat = vmcs_read64(HOST_IA32_PAT);
}

/*
 * prepare_vmcs02 is called in when the L1 guest hypervisor runs its nested
 * L2 guest. L1 has a vmcs for L2 (vmcs12), and this function "merges" it
 * with L0's wishes for its guest (vmsc01), so we can run the L2 guest in a
 * way that will both be appropriate to L1's requests, and our needs.
 */
int prepare_vmcs02(struct kvm_vcpu *vcpu,
	struct vmcs_fields *vmcs12, struct vmcs_fields *vmcs01)
{
	u32 exec_control;

	vmcs_write16(GUEST_ES_SELECTOR, vmcs12->guest_es_selector);
	vmcs_write16(GUEST_CS_SELECTOR, vmcs12->guest_cs_selector);
	vmcs_write16(GUEST_SS_SELECTOR, vmcs12->guest_ss_selector);
	vmcs_write16(GUEST_DS_SELECTOR, vmcs12->guest_ds_selector);
	vmcs_write16(GUEST_FS_SELECTOR, vmcs12->guest_fs_selector);
	vmcs_write16(GUEST_GS_SELECTOR, vmcs12->guest_gs_selector);
	vmcs_write16(GUEST_LDTR_SELECTOR, vmcs12->guest_ldtr_selector);
	vmcs_write16(GUEST_TR_SELECTOR, vmcs12->guest_tr_selector);

	vmcs_write64(GUEST_IA32_DEBUGCTL, vmcs12->guest_ia32_debugctl);

	if (vmcs_config.vmentry_ctrl & VM_ENTRY_LOAD_IA32_PAT)
		vmcs_write64(GUEST_IA32_PAT, vmcs12->guest_ia32_pat);

	vmcs_write32(VM_ENTRY_INTR_INFO_FIELD,
		     vmcs12->vm_entry_intr_info_field);
	vmcs_write32(VM_ENTRY_EXCEPTION_ERROR_CODE,
		     vmcs12->vm_entry_exception_error_code);
	vmcs_write32(VM_ENTRY_INSTRUCTION_LEN,
		     vmcs12->vm_entry_instruction_len);

	vmcs_write32(GUEST_ES_LIMIT, vmcs12->guest_es_limit);
	vmcs_write32(GUEST_CS_LIMIT, vmcs12->guest_cs_limit);
	vmcs_write32(GUEST_SS_LIMIT, vmcs12->guest_ss_limit);
	vmcs_write32(GUEST_DS_LIMIT, vmcs12->guest_ds_limit);
	vmcs_write32(GUEST_FS_LIMIT, vmcs12->guest_fs_limit);
	vmcs_write32(GUEST_GS_LIMIT, vmcs12->guest_gs_limit);
	vmcs_write32(GUEST_LDTR_LIMIT, vmcs12->guest_ldtr_limit);
	vmcs_write32(GUEST_TR_LIMIT, vmcs12->guest_tr_limit);
	vmcs_write32(GUEST_GDTR_LIMIT, vmcs12->guest_gdtr_limit);
	vmcs_write32(GUEST_IDTR_LIMIT, vmcs12->guest_idtr_limit);
	vmcs_write32(GUEST_ES_AR_BYTES, vmcs12->guest_es_ar_bytes);
	vmcs_write32(GUEST_CS_AR_BYTES, vmcs12->guest_cs_ar_bytes);
	vmcs_write32(GUEST_SS_AR_BYTES, vmcs12->guest_ss_ar_bytes);
	vmcs_write32(GUEST_DS_AR_BYTES, vmcs12->guest_ds_ar_bytes);
	vmcs_write32(GUEST_FS_AR_BYTES, vmcs12->guest_fs_ar_bytes);
	vmcs_write32(GUEST_GS_AR_BYTES, vmcs12->guest_gs_ar_bytes);
	vmcs_write32(GUEST_LDTR_AR_BYTES, vmcs12->guest_ldtr_ar_bytes);
	vmcs_write32(GUEST_TR_AR_BYTES, vmcs12->guest_tr_ar_bytes);
	vmcs_write32(GUEST_INTERRUPTIBILITY_INFO,
		     vmcs12->guest_interruptibility_info);
	vmcs_write32(GUEST_ACTIVITY_STATE, vmcs12->guest_activity_state);
	vmcs_write32(GUEST_SYSENTER_CS, vmcs12->guest_sysenter_cs);

	vmcs_writel(GUEST_ES_BASE, vmcs12->guest_es_base);
	vmcs_writel(GUEST_CS_BASE, vmcs12->guest_cs_base);
	vmcs_writel(GUEST_SS_BASE, vmcs12->guest_ss_base);
	vmcs_writel(GUEST_DS_BASE, vmcs12->guest_ds_base);
	vmcs_writel(GUEST_FS_BASE, vmcs12->guest_fs_base);
	vmcs_writel(GUEST_GS_BASE, vmcs12->guest_gs_base);
	vmcs_writel(GUEST_LDTR_BASE, vmcs12->guest_ldtr_base);
	vmcs_writel(GUEST_TR_BASE, vmcs12->guest_tr_base);
	vmcs_writel(GUEST_GDTR_BASE, vmcs12->guest_gdtr_base);
	vmcs_writel(GUEST_IDTR_BASE, vmcs12->guest_idtr_base);
	vmcs_writel(GUEST_DR7, vmcs12->guest_dr7);
	vmcs_writel(GUEST_RSP, vmcs12->guest_rsp);
	vmcs_writel(GUEST_RIP, vmcs12->guest_rip);
	vmcs_writel(GUEST_RFLAGS, vmcs12->guest_rflags);
	vmcs_writel(GUEST_PENDING_DBG_EXCEPTIONS,
		    vmcs12->guest_pending_dbg_exceptions);
	vmcs_writel(GUEST_SYSENTER_ESP, vmcs12->guest_sysenter_esp);
	vmcs_writel(GUEST_SYSENTER_EIP, vmcs12->guest_sysenter_eip);

	vmcs_write64(VMCS_LINK_POINTER, vmcs12->vmcs_link_pointer);

	if (vmcs12->vm_entry_msr_load_count > 0 ||
			vmcs12->vm_exit_msr_load_count > 0 ||
			vmcs12->vm_exit_msr_store_count > 0) {
		printk(KERN_WARNING
			"%s: VMCS MSR_{LOAD,STORE} unsupported\n", __func__);
	}

	if (nested_cpu_has_vmx_tpr_shadow(vcpu)) {
		struct page *page =
			nested_get_page(vcpu, vmcs12->virtual_apic_page_addr);
		if (!page)
			return 1;
		vmcs_write64(VIRTUAL_APIC_PAGE_ADDR, page_to_phys(page));
		kvm_release_page_clean(page);
	}

	if (nested_vm_need_virtualize_apic_accesses(vcpu)) {
		struct page *page =
			nested_get_page(vcpu, vmcs12->apic_access_addr);
		if (!page)
			return 1;
		vmcs_write64(APIC_ACCESS_ADDR, page_to_phys(page));
		kvm_release_page_clean(page);
	}

	vmcs_write32(PIN_BASED_VM_EXEC_CONTROL,
		     (vmcs01->pin_based_vm_exec_control |
		      vmcs12->pin_based_vm_exec_control));

	/*
	 * Whether page-faults are trapped is determined by a combination of
	 * 3 settings: PFEC_MASK, PFEC_MATCH and EXCEPTION_BITMAP.PF.
	 * If enable_ept, L0 doesn't care about page faults and we should
	 * set all of these to L1's desires. However, if !enable_ept, L0 does
	 * care about (at least some) page faults, and because it is not easy
	 * (if at all possible?) to merge L0 and L1's desires, we simply ask
	 * to exit on each and every L2 page fault. This is done by setting
	 * MASK=MATCH=0 and (see below) EB.PF=1.
	 * Note that below we don't need special code to set EB.PF beyond the
	 * "or"ing of the EB of vmcs01 and vmcs12, because when enable_ept,
	 * vmcs01's EB.PF is 0 so the "or" will take vmcs12's value, and when
	 * !enable_ept, EB.PF is 1, so the "or" will always be 1.
	 *
	 * A problem with this approach (when !enable_ept) is that L1 may be
	 * injected with more page faults than it asked for. This could have
	 * caused problems, but in practice existing hypervisors don't care.
	 * To fix this, we will need to emulate the PFEC checking (on the L1
	 * page tables), using walk_addr(), when injecting PFs to L1.
	 */
	vmcs_write32(PAGE_FAULT_ERROR_CODE_MASK,
		enable_ept ? vmcs12->page_fault_error_code_mask : 0);
	vmcs_write32(PAGE_FAULT_ERROR_CODE_MATCH,
		enable_ept ? vmcs12->page_fault_error_code_match : 0);

	if (cpu_has_secondary_exec_ctrls()) {
		u32 exec_control = vmcs01->secondary_vm_exec_control;
		if (nested_cpu_has_secondary_exec_ctrls(vcpu)) {
			exec_control |= vmcs12->secondary_vm_exec_control;
			if (!vm_need_virtualize_apic_accesses(vcpu->kvm) ||
			    !nested_vm_need_virtualize_apic_accesses(vcpu))
				exec_control &=
				~SECONDARY_EXEC_VIRTUALIZE_APIC_ACCESSES;
		}
		vmcs_write32(SECONDARY_VM_EXEC_CONTROL, exec_control);
	}

	/*
	 * Copy host-state from vcms01. Notes that some fields are different
	 * per CPU, and are not copied here but rather in vmx_vcpu_load().
	 * Eventually, we shouldn't copy host fields from vcms01 at all, but
	 * rather just call the KVM code which sets them up.
	 */
	vmcs_write16(HOST_ES_SELECTOR, vmcs01->host_es_selector);
	vmcs_write16(HOST_CS_SELECTOR, vmcs01->host_cs_selector);
	vmcs_write16(HOST_SS_SELECTOR, vmcs01->host_ss_selector);
	vmcs_write16(HOST_DS_SELECTOR, vmcs01->host_ds_selector);
	vmcs_write16(HOST_FS_SELECTOR, vmcs01->host_fs_selector);
	vmcs_write16(HOST_GS_SELECTOR, vmcs01->host_gs_selector);
	vmcs_write16(HOST_TR_SELECTOR, vmcs01->host_tr_selector);
	if (vmcs_config.vmexit_ctrl & VM_EXIT_LOAD_IA32_PAT)
		vmcs_write64(HOST_IA32_PAT, vmcs01->host_ia32_pat);
	vmcs_write32(HOST_IA32_SYSENTER_CS, vmcs01->host_ia32_sysenter_cs);
	vmcs_writel(HOST_CR0, vmcs01->host_cr0);
	vmcs_writel(HOST_CR3, vmcs01->host_cr3);
	vmcs_writel(HOST_CR4, vmcs01->host_cr4);
	vmcs_writel(HOST_FS_BASE, vmcs01->host_fs_base);
	vmcs_writel(HOST_GS_BASE, vmcs01->host_gs_base);
	vmcs_writel(HOST_IDTR_BASE, vmcs01->host_idtr_base);
	vmcs_writel(HOST_RSP, vmcs01->host_rsp);
	vmcs_writel(HOST_RIP, vmcs01->host_rip);
	vmcs_writel(HOST_IA32_SYSENTER_EIP, vmcs01->host_ia32_sysenter_eip);

	if (vm_need_tpr_shadow(vcpu->kvm) &&
	    nested_cpu_has_vmx_tpr_shadow(vcpu))
		vmcs_write32(TPR_THRESHOLD, vmcs12->tpr_threshold);

	exec_control = vmcs01->cpu_based_vm_exec_control;
	exec_control &= ~CPU_BASED_VIRTUAL_INTR_PENDING;
	exec_control &= ~CPU_BASED_VIRTUAL_NMI_PENDING;
	exec_control &= ~CPU_BASED_TPR_SHADOW;
	exec_control |= vmcs12->cpu_based_vm_exec_control;
	if (!vm_need_tpr_shadow(vcpu->kvm) ||
	    vmcs12->virtual_apic_page_addr == 0) {
		exec_control &= ~CPU_BASED_TPR_SHADOW;
#ifdef CONFIG_X86_64
		exec_control |= CPU_BASED_CR8_STORE_EXITING |
			CPU_BASED_CR8_LOAD_EXITING;
#endif
	} else if (exec_control & CPU_BASED_TPR_SHADOW) {
#ifdef CONFIG_X86_64
		exec_control &= ~CPU_BASED_CR8_STORE_EXITING;
		exec_control &= ~CPU_BASED_CR8_LOAD_EXITING;
#endif
	}
	/*
	 * Merging of IO and MSR bitmaps not currently supported.
	 * Rather, exit every time.
	 */
	exec_control &= ~CPU_BASED_USE_MSR_BITMAPS;
	exec_control &= ~CPU_BASED_USE_IO_BITMAPS;
	exec_control |= CPU_BASED_UNCOND_IO_EXITING;

	vmcs_write32(CPU_BASED_VM_EXEC_CONTROL, exec_control);

	/* EXCEPTION_BITMAP and CR0_GUEST_HOST_MASK should basically be the
	 * bitwise-or of what L1 wants to trap for L2, and what we want to
	 * trap. However, vmx_fpu_activate/deactivate may have happened after
	 * we saved vmcs01, so we shouldn't trust its TS and NM_VECTOR bits
	 * and need to base them again on fpu_active. Note that CR0.TS also
	 * needs updating - we do this after this function returns (in
	 * nested_vmx_run).
	 */
	vmcs_write32(EXCEPTION_BITMAP,
		     ((vmcs01->exception_bitmap&~(1u<<NM_VECTOR)) |
		      (vcpu->fpu_active ? 0 : (1u<<NM_VECTOR)) |
		      vmcs12->exception_bitmap));
	vmcs_writel(CR0_GUEST_HOST_MASK, vmcs12->cr0_guest_host_mask |
			(vcpu->fpu_active ? 0 : X86_CR0_TS));
	vcpu->arch.cr0_guest_owned_bits = ~(vmcs12->cr0_guest_host_mask |
			(vcpu->fpu_active ? 0 : X86_CR0_TS));

	vmcs_write32(VM_EXIT_CONTROLS,
		     (vmcs01->vm_exit_controls &
			(~(VM_EXIT_LOAD_IA32_PAT | VM_EXIT_SAVE_IA32_PAT)))
		       | vmcs12->vm_exit_controls);

	vmcs_write32(VM_ENTRY_CONTROLS,
		     (vmcs01->vm_entry_controls &
			(~(VM_ENTRY_LOAD_IA32_PAT | VM_ENTRY_IA32E_MODE)))
		      | vmcs12->vm_entry_controls);

	vmcs_writel(CR4_GUEST_HOST_MASK,
		    (vmcs01->cr4_guest_host_mask |
		     vmcs12->cr4_guest_host_mask));
	vcpu->arch.cr4_guest_owned_bits = ~(vmcs01->cr4_guest_host_mask |
		vmcs12->cr4_guest_host_mask);

	vmcs_write64(TSC_OFFSET, vmcs01->tsc_offset + vmcs12->tsc_offset);

	if (enable_ept) {
		/* shadow page tables on EPT */
		vmcs_write64(EPT_POINTER, vmcs01->ept_pointer);
	}
	if (enable_vpid) {
		/*
		 * Trivially support vpid by letting L2s share their parent
		 * L1's vpid. TODO: move to a more elaborate solution, giving
		 * each L2 its own vpid and exposing the vpid feature to L1.
		 */
		vmcs_write16(VIRTUAL_PROCESSOR_ID, to_vmx(vcpu)->vpid);
		vmx_flush_tlb(vcpu);
	}
	return 0;
}

/*
 * Return the cr0 value that a guest would read. This is a combination of
 * the real cr0 used to run the guest (guest_cr0), and the bits shadowed by
 * the hypervisor (cr0_read_shadow).
 */
static inline unsigned long guest_readable_cr0(struct vmcs_fields *fields)
{
	return (fields->guest_cr0 & ~fields->cr0_guest_host_mask) |
		(fields->cr0_read_shadow & fields->cr0_guest_host_mask);
}
static inline unsigned long guest_readable_cr4(struct vmcs_fields *fields)
{
	return (fields->guest_cr4 & ~fields->cr4_guest_host_mask) |
		(fields->cr4_read_shadow & fields->cr4_guest_host_mask);
}
static inline void set_cr3_and_pdptrs(struct kvm_vcpu *vcpu, unsigned long cr3)
{
	vcpu->arch.cr3 = cr3;
	vmcs_writel(GUEST_CR3, cr3);
	__set_bit(VCPU_EXREG_CR3, (ulong *)&vcpu->arch.regs_avail);
	load_pdptrs(vcpu, vcpu->arch.walk_mmu, cr3);
	vmcs_write64(GUEST_PDPTR0, vcpu->arch.mmu.pdptrs[0]);
	vmcs_write64(GUEST_PDPTR1, vcpu->arch.mmu.pdptrs[1]);
	vmcs_write64(GUEST_PDPTR2, vcpu->arch.mmu.pdptrs[2]);
	vmcs_write64(GUEST_PDPTR3, vcpu->arch.mmu.pdptrs[3]);
}

static int nested_vmx_run(struct kvm_vcpu *vcpu)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);
	int cpu;
	struct saved_vmcs *saved_vmcs02;

	enter_guest_mode(vcpu);
	sync_cached_regs_to_vmcs(vcpu);
	save_vmcs(vmx->nested.vmcs01_fields);

	/*
	 * Switch from L1's VMCS, to L2's VMCS. Remember the L1 VMCS, on which
	 * CPU it was last loaded, and whether it was launched (we need all
	 * these values next time we will use L1). Then recall these values as
	 * they were for L2's VMCS (unless L2 has never been launched).
	 */
	vmx->nested.saved_vmcs01.vmcs = vmx->vmcs;
	vmx->nested.saved_vmcs01.cpu = vcpu->cpu;
	vmx->nested.saved_vmcs01.launched = vmx->launched;

	saved_vmcs02 = nested_get_current_vmcs(vmx);
	if (!saved_vmcs02) {
		/* In the current code, this cannot happen */
		kvm_make_request(KVM_REQ_TRIPLE_FAULT, vcpu);
		return 1;
	}
	vmx->vmcs = saved_vmcs02->vmcs;
	vcpu->cpu = saved_vmcs02->cpu;
	vmx->launched = saved_vmcs02->launched;

	vmx_vcpu_put(vcpu);
	cpu = get_cpu();
	vmx_vcpu_load(vcpu, cpu);
	vcpu->cpu = cpu;
	put_cpu();

	vmx->nested.current_vmcs12->launch_state = 1;

	prepare_vmcs02(vcpu,
		get_vmcs12_fields(vcpu), vmx->nested.vmcs01_fields);

	if (get_vmcs12_fields(vcpu)->vm_entry_controls &
	    VM_ENTRY_IA32E_MODE)
		vcpu->arch.efer |= (EFER_LMA | EFER_LME);
	else
		vcpu->arch.efer &= ~(EFER_LMA | EFER_LME);

	vmx->rmode.vm86_active =
		!(get_vmcs12_fields(vcpu)->cr0_read_shadow & X86_CR0_PE);

	/* vmx_set_cr0() sets the cr0 that L2 will read, to be the one that L1
	 * dictated, and takes appropriate actions for special cr0 bits (like
	 * real mode, etc.).
	 */
	vmx_set_cr0(vcpu, guest_readable_cr0(get_vmcs12_fields(vcpu)));

	/* However, vmx_set_cr0 incorrectly enforces KVM's relationship between
	 * GUEST_CR0 and CR0_READ_SHADOW, e.g., that the former is the same as
	 * the latter with with TS added if !fpu_active. We need to take the
	 * actual GUEST_CR0 that L1 wanted, just with added TS if !fpu_active
	 * like KVM wants (for the "lazy fpu" feature, to avoid the costly
	 * restoration of fpu registers until the FPU is really used).
	 */
	vmcs_writel(GUEST_CR0, get_vmcs12_fields(vcpu)->guest_cr0 |
		(vcpu->fpu_active ? 0 : X86_CR0_TS));

	/* we have to set the X86_CR0_PG bit of the cached cr0, because
	 * kvm_mmu_reset_context enables paging only if X86_CR0_PG is set in
	 * CR0 (we need the paging so that KVM treat this guest as a paging
	 * guest so we can easly forward page faults to L1.)
	 */
	vcpu->arch.cr0 |= X86_CR0_PG;

	if (enable_ept) {
		/* shadow page tables on EPT */
		vcpu->arch.cr4 = guest_readable_cr4(get_vmcs12_fields(vcpu));
		vmcs_writel(CR4_READ_SHADOW, vcpu->arch.cr4);
		vmcs_writel(GUEST_CR4, get_vmcs12_fields(vcpu)->guest_cr4);
		set_cr3_and_pdptrs(vcpu, get_vmcs12_fields(vcpu)->guest_cr3);
	} else {
		/* shadow page tables on shadow page tables */
		vmx_set_cr4(vcpu, get_vmcs12_fields(vcpu)->guest_cr4);
		vmcs_writel(CR4_READ_SHADOW,
			    get_vmcs12_fields(vcpu)->cr4_read_shadow);
		kvm_set_cr3(vcpu, get_vmcs12_fields(vcpu)->guest_cr3);
		kvm_mmu_reset_context(vcpu);

		if (unlikely(kvm_mmu_load(vcpu))) {
			/* switch back to L1 */
			nested_vmx_vmexit(vcpu, false);
			/*
			 * TODO: there is no reasonable error number to use.
			 * perhaps a more reasonable thing to do is to
			 * emulate a guest shutdown, not a launch error?
			 */
			nested_vmx_failValid(vcpu, 87);
			return 1;
		}
	}

	kvm_register_write(vcpu, VCPU_REGS_RSP,
			   get_vmcs12_fields(vcpu)->guest_rsp);
	kvm_register_write(vcpu, VCPU_REGS_RIP,
			   get_vmcs12_fields(vcpu)->guest_rip);

	return 1;
}

/*
 * On a nested exit from L2 to L1, vmcs12.guest_cr0 might not be up-to-date
 * because L2 may have changed some cr0 bits directly (see CRO_GUEST_HOST_MASK)
 * without L0 trapping the change and updating vmcs12.
 * This function returns the value we should put in vmcs12.guest_cr0. It's not
 * enough to just return the current (vmcs02) GUEST_CR0. This may not be the
 * guest cr0 that L1 thought it was giving its L2 guest - it is possible that
 * L1 wished to allow its guest to set a cr0 bit directly, but we (L0) asked
 * to trap this change and instead set just the read shadow. If this is the
 * case, we need to copy these read-shadow bits back to vmcs12.guest_cr0, where
 * L1 believes they already are.
 */
static inline unsigned long
vmcs12_guest_cr0(struct kvm_vcpu *vcpu, struct vmcs_fields *vmcs12)
{
	unsigned long guest_cr0_bits =
		vcpu->arch.cr0_guest_owned_bits | vmcs12->cr0_guest_host_mask;
	return (vmcs_readl(GUEST_CR0) & guest_cr0_bits) |
		(vmcs_readl(CR0_READ_SHADOW) & ~guest_cr0_bits);
}

static inline unsigned long
vmcs12_guest_cr4(struct kvm_vcpu *vcpu, struct vmcs_fields *vmcs12)
{
	unsigned long guest_cr4_bits =
		vcpu->arch.cr4_guest_owned_bits | vmcs12->cr4_guest_host_mask;
	return (vmcs_readl(GUEST_CR4) & guest_cr4_bits) |
		(vmcs_readl(CR4_READ_SHADOW) & ~guest_cr4_bits);
}

/*
 * prepare_vmcs12 is called when the nested L2 guest exits and we want to
 * prepare to run its L1 parent. L1 keeps a vmcs for L2 (vmcs12), and this
 * function updates it to reflect the changes to the guest state while L2 was
 * running (and perhaps made some exits which were handled directly by L0
 * without going back to L1), and to reflect the exit reason.
 * Note that we do not have to copy here all VMCS fields, just those that
 * could have changed by the L2 guest or the exit - i.e., the guest-state and
 * exit-information fields only. Other fields are modified by L1 with VMWRITE,
 * which already writes to vmcs12 directly.
 */
void prepare_vmcs12(struct kvm_vcpu *vcpu)
{
	struct vmcs_fields *vmcs12 = get_vmcs12_fields(vcpu);

	/* update guest state fields: */
	vmcs12->guest_cr0 = vmcs12_guest_cr0(vcpu, vmcs12);
	vmcs12->guest_cr4 = vmcs12_guest_cr4(vcpu, vmcs12);

	vmcs12->guest_dr7 = vmcs_readl(GUEST_DR7);
	vmcs12->guest_rsp = vmcs_readl(GUEST_RSP);
	vmcs12->guest_rip = vmcs_readl(GUEST_RIP);
	vmcs12->guest_rflags = vmcs_readl(GUEST_RFLAGS);

	vmcs12->guest_es_selector = vmcs_read16(GUEST_ES_SELECTOR);
	vmcs12->guest_cs_selector = vmcs_read16(GUEST_CS_SELECTOR);
	vmcs12->guest_ss_selector = vmcs_read16(GUEST_SS_SELECTOR);
	vmcs12->guest_ds_selector = vmcs_read16(GUEST_DS_SELECTOR);
	vmcs12->guest_fs_selector = vmcs_read16(GUEST_FS_SELECTOR);
	vmcs12->guest_gs_selector = vmcs_read16(GUEST_GS_SELECTOR);
	vmcs12->guest_ldtr_selector = vmcs_read16(GUEST_LDTR_SELECTOR);
	vmcs12->guest_tr_selector = vmcs_read16(GUEST_TR_SELECTOR);
	vmcs12->guest_es_limit = vmcs_read32(GUEST_ES_LIMIT);
	vmcs12->guest_cs_limit = vmcs_read32(GUEST_CS_LIMIT);
	vmcs12->guest_ss_limit = vmcs_read32(GUEST_SS_LIMIT);
	vmcs12->guest_ds_limit = vmcs_read32(GUEST_DS_LIMIT);
	vmcs12->guest_fs_limit = vmcs_read32(GUEST_FS_LIMIT);
	vmcs12->guest_gs_limit = vmcs_read32(GUEST_GS_LIMIT);
	vmcs12->guest_ldtr_limit = vmcs_read32(GUEST_LDTR_LIMIT);
	vmcs12->guest_tr_limit = vmcs_read32(GUEST_TR_LIMIT);
	vmcs12->guest_gdtr_limit = vmcs_read32(GUEST_GDTR_LIMIT);
	vmcs12->guest_idtr_limit = vmcs_read32(GUEST_IDTR_LIMIT);
	vmcs12->guest_es_ar_bytes = vmcs_read32(GUEST_ES_AR_BYTES);
	vmcs12->guest_cs_ar_bytes = vmcs_read32(GUEST_CS_AR_BYTES);
	vmcs12->guest_ss_ar_bytes = vmcs_read32(GUEST_SS_AR_BYTES);
	vmcs12->guest_ds_ar_bytes = vmcs_read32(GUEST_DS_AR_BYTES);
	vmcs12->guest_fs_ar_bytes = vmcs_read32(GUEST_FS_AR_BYTES);
	vmcs12->guest_gs_ar_bytes = vmcs_read32(GUEST_GS_AR_BYTES);
	vmcs12->guest_ldtr_ar_bytes = vmcs_read32(GUEST_LDTR_AR_BYTES);
	vmcs12->guest_tr_ar_bytes = vmcs_read32(GUEST_TR_AR_BYTES);
	vmcs12->guest_es_base = vmcs_readl(GUEST_ES_BASE);
	vmcs12->guest_cs_base = vmcs_readl(GUEST_CS_BASE);
	vmcs12->guest_ss_base = vmcs_readl(GUEST_SS_BASE);
	vmcs12->guest_ds_base = vmcs_readl(GUEST_DS_BASE);
	vmcs12->guest_fs_base = vmcs_readl(GUEST_FS_BASE);
	vmcs12->guest_gs_base = vmcs_readl(GUEST_GS_BASE);
	vmcs12->guest_ldtr_base = vmcs_readl(GUEST_LDTR_BASE);
	vmcs12->guest_tr_base = vmcs_readl(GUEST_TR_BASE);
	vmcs12->guest_gdtr_base = vmcs_readl(GUEST_GDTR_BASE);
	vmcs12->guest_idtr_base = vmcs_readl(GUEST_IDTR_BASE);

	vmcs12->guest_activity_state = vmcs_read32(GUEST_ACTIVITY_STATE);
	vmcs12->guest_interruptibility_info =
		vmcs_read32(GUEST_INTERRUPTIBILITY_INFO);
	vmcs12->guest_pending_dbg_exceptions =
		vmcs_readl(GUEST_PENDING_DBG_EXCEPTIONS);
	vmcs12->vmcs_link_pointer = vmcs_read64(VMCS_LINK_POINTER);

	/* TODO: These cannot have changed unless we have MSR bitmaps and
	 * the relevant bit asks not to trap the change */
	vmcs12->guest_ia32_debugctl = vmcs_read64(GUEST_IA32_DEBUGCTL);
	if (vmcs_config.vmentry_ctrl & VM_EXIT_SAVE_IA32_PAT)
		vmcs12->guest_ia32_pat = vmcs_read64(GUEST_IA32_PAT);
	vmcs12->guest_sysenter_cs = vmcs_read32(GUEST_SYSENTER_CS);
	vmcs12->guest_sysenter_esp = vmcs_readl(GUEST_SYSENTER_ESP);
	vmcs12->guest_sysenter_eip = vmcs_readl(GUEST_SYSENTER_EIP);

	/* update exit information fields: */

	vmcs12->vm_exit_reason  = vmcs_read32(VM_EXIT_REASON);
	vmcs12->exit_qualification = vmcs_readl(EXIT_QUALIFICATION);

	vmcs12->vm_exit_intr_info = vmcs_read32(VM_EXIT_INTR_INFO);
	vmcs12->vm_exit_intr_error_code = vmcs_read32(VM_EXIT_INTR_ERROR_CODE);
	vmcs12->idt_vectoring_info_field =
		vmcs_read32(IDT_VECTORING_INFO_FIELD);
	vmcs12->idt_vectoring_error_code =
		vmcs_read32(IDT_VECTORING_ERROR_CODE);
	vmcs12->vm_exit_instruction_len = vmcs_read32(VM_EXIT_INSTRUCTION_LEN);
	vmcs12->vmx_instruction_info = vmcs_read32(VMX_INSTRUCTION_INFO);

	/* clear vm-entry fields which are to be cleared on exit */
	if (!(vmcs12->vm_exit_reason & VMX_EXIT_REASONS_FAILED_VMENTRY))
		vmcs12->vm_entry_intr_info_field &= ~INTR_INFO_VALID_MASK;
}

/*
 * Emulate an exit from nested guest (L2) to L1, i.e., prepare to run L1
 * and modify vmcs12 to make it see what it would expect to see there if
 * L2 was its real guest. Must only be called when in L2 (is_guest_mode())
 */
static void nested_vmx_vmexit(struct kvm_vcpu *vcpu, bool is_interrupt)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);
	struct vmcs_fields *vmcs01 = vmx->nested.vmcs01_fields;
	int cpu;
	struct saved_vmcs *saved_vmcs02;

	leave_guest_mode(vcpu);

	sync_cached_regs_to_vmcs(vcpu);

	prepare_vmcs12(vcpu);

	if (is_interrupt)
		get_vmcs12_fields(vcpu)->vm_exit_reason =
			EXIT_REASON_EXTERNAL_INTERRUPT;

	/*
	 * Switch from L2's VMCS, to L1's VMCS. Remember on which CPU the L2
	 * VMCS was last loaded, and whether it was launched (we need to know
	 * this next time we use L2), and recall these values as they were for
	 * L1's VMCS.
	 */
	saved_vmcs02 = nested_get_current_vmcs(vmx);
	if (saved_vmcs02) {
		saved_vmcs02->cpu = vcpu->cpu;
		saved_vmcs02->launched = vmx->launched;
	}
	vmx->vmcs = vmx->nested.saved_vmcs01.vmcs;
	vcpu->cpu = vmx->nested.saved_vmcs01.cpu;
	vmx->launched = vmx->nested.saved_vmcs01.launched;

	vmx_vcpu_put(vcpu);
	cpu = get_cpu();
	vmx_vcpu_load(vcpu, cpu);
	vcpu->cpu = cpu;
	put_cpu();

	if (get_vmcs12_fields(vcpu)->vm_exit_controls &
	    VM_EXIT_HOST_ADDR_SPACE_SIZE)
		vcpu->arch.efer |= (EFER_LMA | EFER_LME);
	else
		vcpu->arch.efer &= ~(EFER_LMA | EFER_LME);
	vmx_set_efer(vcpu, vcpu->arch.efer);

	/*
	 * L2 perhaps switched to real mode and set vmx->rmode, but we're back
	 * in L1 and as it is running VMX, it can't be in real mode.
	 */
	vmx->rmode.vm86_active = 0;

	/*
	 * If L1 set the HOST_* fields in the VMCS, when exiting from L2 to L1
	 * we need to return those, not L1's old values.
	 */
	vmcs_writel(GUEST_RIP, get_vmcs12_fields(vcpu)->host_rip);
	vmcs_writel(GUEST_RSP, get_vmcs12_fields(vcpu)->host_rsp);
	vmcs01->cr0_read_shadow = get_vmcs12_fields(vcpu)->host_cr0;

	/*
	 * We're running a regular L1 guest again, so we do the regular KVM
	 * thing: run vmx_set_cr0 with the cr0 bits the guest thinks it has.
	 * vmx_set_cr0 might use slightly different bits on the new guest_cr0
	 * it sets, e.g., add TS when !fpu_active.
	 * Note that vmx_set_cr0 refers to rmode and efer set above.
	 */
	vmx_set_cr0(vcpu, guest_readable_cr0(vmcs01));
	/*
	 * If we did fpu_activate()/fpu_deactive() during l2's run, we need to
	 * apply the same changes to l1's vmcs. We just set cr0 correctly, but
	 * now we need to also update cr0_guest_host_mask and exception_bitmap.
	 */
	vmcs_write32(EXCEPTION_BITMAP,
		(vmcs01->exception_bitmap & ~(1u<<NM_VECTOR)) |
			(vcpu->fpu_active ? 0 : (1u<<NM_VECTOR)));
	vcpu->arch.cr0_guest_owned_bits = (vcpu->fpu_active ? X86_CR0_TS : 0);
	vmcs_writel(CR0_GUEST_HOST_MASK, ~vcpu->arch.cr0_guest_owned_bits);

	vmx_set_cr4(vcpu, guest_readable_cr4(vmcs01));
	vcpu->arch.cr4_guest_owned_bits = ~vmcs01->cr4_guest_host_mask;

	if (enable_ept) {
		/* shadow page tables on EPT: */
		set_cr3_and_pdptrs(vcpu, get_vmcs12_fields(vcpu)->host_cr3);
	} else {
		/* shadow page tables on shadow page tables: */
		kvm_set_cr3(vcpu, get_vmcs12_fields(vcpu)->host_cr3);
		kvm_mmu_reset_context(vcpu);
		kvm_mmu_load(vcpu);
	}
	if (enable_vpid) {
		/*
		 * Trivially support vpid by letting L2s share their parent
		 * L1's vpid. TODO: move to a more elaborate solution, giving
		 * each L2 its own vpid and exposing the vpid feature to L1.
		 */
		vmx_flush_tlb(vcpu);
	}

	kvm_register_write(vcpu, VCPU_REGS_RSP, vmcs01->guest_rsp);
	kvm_register_write(vcpu, VCPU_REGS_RIP, vmcs01->guest_rip);

	if (unlikely(vmx->fail)) {
		/*
		 * When L1 launches L2 and then we (L0) fail to launch L2,
		 * we nested_vmx_vmexit back to L1, but now should let it know
		 * that the VMLAUNCH failed - with the same error that we
		 * got when launching L2.
		 */
		vmx->fail = 0;
		nested_vmx_failValid(vcpu, vmcs_read32(VM_INSTRUCTION_ERROR));
	} else
		nested_vmx_succeed(vcpu);
}

static struct kvm_x86_ops vmx_x86_ops = {
	.cpu_has_kvm_support = cpu_has_kvm_support,
	.disabled_by_bios = vmx_disabled_by_bios,
	.hardware_setup = hardware_setup,
	.hardware_unsetup = hardware_unsetup,
	.check_processor_compatibility = vmx_check_processor_compat,
	.hardware_enable = hardware_enable,
	.hardware_disable = hardware_disable,
	.cpu_has_accelerated_tpr = report_flexpriority,

	.vcpu_create = vmx_create_vcpu,
	.vcpu_free = vmx_free_vcpu,
	.vcpu_reset = vmx_vcpu_reset,

	.prepare_guest_switch = vmx_save_host_state,
	.vcpu_load = vmx_vcpu_load,
	.vcpu_put = vmx_vcpu_put,

	.set_guest_debug = set_guest_debug,
	.get_msr = vmx_get_msr,
	.set_msr = vmx_set_msr,
	.get_segment_base = vmx_get_segment_base,
	.get_segment = vmx_get_segment,
	.set_segment = vmx_set_segment,
	.get_cpl = vmx_get_cpl,
	.get_cs_db_l_bits = vmx_get_cs_db_l_bits,
	.decache_cr0_guest_bits = vmx_decache_cr0_guest_bits,
	.decache_cr3 = vmx_decache_cr3,
	.decache_cr4_guest_bits = vmx_decache_cr4_guest_bits,
	.set_cr0 = vmx_set_cr0,
	.set_cr3 = vmx_set_cr3,
	.set_cr4 = vmx_set_cr4,
	.set_efer = vmx_set_efer,
	.get_idt = vmx_get_idt,
	.set_idt = vmx_set_idt,
	.get_gdt = vmx_get_gdt,
	.set_gdt = vmx_set_gdt,
	.set_dr7 = vmx_set_dr7,
	.cache_reg = vmx_cache_reg,
	.get_rflags = vmx_get_rflags,
	.set_rflags = vmx_set_rflags,
	.fpu_activate = vmx_fpu_activate,
	.fpu_deactivate = vmx_fpu_deactivate,

	.tlb_flush = vmx_flush_tlb,

	.run = vmx_vcpu_run,
	.handle_exit = vmx_handle_exit,
	.skip_emulated_instruction = skip_emulated_instruction,
	.set_interrupt_shadow = vmx_set_interrupt_shadow,
	.get_interrupt_shadow = vmx_get_interrupt_shadow,
	.patch_hypercall = vmx_patch_hypercall,
	.set_irq = vmx_inject_irq,
	.set_nmi = vmx_inject_nmi,
	.queue_exception = vmx_queue_exception,
	.cancel_injection = vmx_cancel_injection,
	.interrupt_allowed = vmx_interrupt_allowed,
	.nmi_allowed = vmx_nmi_allowed,
	.get_nmi_mask = vmx_get_nmi_mask,
	.set_nmi_mask = vmx_set_nmi_mask,
	.enable_nmi_window = enable_nmi_window,
	.enable_irq_window = enable_irq_window,
	.update_cr8_intercept = update_cr8_intercept,

	.set_tss_addr = vmx_set_tss_addr,
	.get_tdp_level = get_ept_level,
	.get_mt_mask = vmx_get_mt_mask,

	.get_exit_info = vmx_get_exit_info,
	.exit_reasons_str = vmx_exit_reasons_str,

	.get_lpage_level = vmx_get_lpage_level,

	.cpuid_update = vmx_cpuid_update,

	.rdtscp_supported = vmx_rdtscp_supported,

	.set_supported_cpuid = vmx_set_supported_cpuid,

	.has_wbinvd_exit = cpu_has_vmx_wbinvd_exit,

	.write_tsc_offset = vmx_write_tsc_offset,
	.adjust_tsc_offset = vmx_adjust_tsc_offset,

	.set_tdp_cr3 = vmx_set_cr3,
};

static int __init vmx_init(void)
{
	int r, i;

	rdmsrl_safe(MSR_EFER, &host_efer);

	for (i = 0; i < NR_VMX_MSR; ++i)
		kvm_define_shared_msr(i, vmx_msr_index[i]);

	vmx_io_bitmap_a = (unsigned long *)__get_free_page(GFP_KERNEL);
	if (!vmx_io_bitmap_a)
		return -ENOMEM;

	vmx_io_bitmap_b = (unsigned long *)__get_free_page(GFP_KERNEL);
	if (!vmx_io_bitmap_b) {
		r = -ENOMEM;
		goto out;
	}

	vmx_msr_bitmap_legacy = (unsigned long *)__get_free_page(GFP_KERNEL);
	if (!vmx_msr_bitmap_legacy) {
		r = -ENOMEM;
		goto out1;
	}

	vmx_msr_bitmap_longmode = (unsigned long *)__get_free_page(GFP_KERNEL);
	if (!vmx_msr_bitmap_longmode) {
		r = -ENOMEM;
		goto out2;
	}

	/*
	 * Allow direct access to the PC debug port (it is often used for I/O
	 * delays, but the vmexits simply slow things down).
	 */
	memset(vmx_io_bitmap_a, 0xff, PAGE_SIZE);
	clear_bit(0x80, vmx_io_bitmap_a);

	memset(vmx_io_bitmap_b, 0xff, PAGE_SIZE);

	memset(vmx_msr_bitmap_legacy, 0xff, PAGE_SIZE);
	memset(vmx_msr_bitmap_longmode, 0xff, PAGE_SIZE);

	set_bit(0, vmx_vpid_bitmap); /* 0 is reserved for host */

	r = kvm_init(&vmx_x86_ops, sizeof(struct vcpu_vmx),
		     __alignof__(struct vcpu_vmx), THIS_MODULE);
	if (r)
		goto out3;

	vmx_disable_intercept_for_msr(MSR_FS_BASE, false);
	vmx_disable_intercept_for_msr(MSR_GS_BASE, false);
	vmx_disable_intercept_for_msr(MSR_KERNEL_GS_BASE, true);
	vmx_disable_intercept_for_msr(MSR_IA32_SYSENTER_CS, false);
	vmx_disable_intercept_for_msr(MSR_IA32_SYSENTER_ESP, false);
	vmx_disable_intercept_for_msr(MSR_IA32_SYSENTER_EIP, false);

	if (enable_ept) {
		bypass_guest_pf = 0;
		kvm_mmu_set_mask_ptes(0ull, 0ull, 0ull, 0ull,
				VMX_EPT_EXECUTABLE_MASK);
		kvm_enable_tdp();
	} else
		kvm_disable_tdp();

	if (bypass_guest_pf)
		kvm_mmu_set_nonpresent_ptes(~0xffeull, 0ull);

	return 0;

out3:
	free_page((unsigned long)vmx_msr_bitmap_longmode);
out2:
	free_page((unsigned long)vmx_msr_bitmap_legacy);
out1:
	free_page((unsigned long)vmx_io_bitmap_b);
out:
	free_page((unsigned long)vmx_io_bitmap_a);
	return r;
}

static void __exit vmx_exit(void)
{
	free_page((unsigned long)vmx_msr_bitmap_legacy);
	free_page((unsigned long)vmx_msr_bitmap_longmode);
	free_page((unsigned long)vmx_io_bitmap_b);
	free_page((unsigned long)vmx_io_bitmap_a);

	kvm_exit();
}

module_init(vmx_init)
module_exit(vmx_exit)
