// tools/hvf-runner/src/vm.rs
//
// VM + vCPU lifecycle, run loop, and exception dispatch.
//
// Manages the full lifecycle: create VM → allocate RAM → create vGIC →
// create vCPU → load kernel → generate FDT → run loop. The run loop
// handles HVC (PSCI), stage-2 data aborts (MMIO), vtimer, and WFI.

use std::ffi::c_void;
use std::ptr;

use crate::decoder;
use crate::fdt;
use crate::hvf::*;
use crate::pl011;
use crate::virtio;

// ── Guest physical memory layout ─────────────────────────────────────────────
// Mirrors QEMU `virt` machine defaults so the same kernel binary boots
// under both QEMU+TCG and this runner.

const RAM_BASE: u64 = 0x4000_0000;
const PL011_BASE: u64 = 0x0900_0000;
const PL011_SIZE: u64 = 0x1000;
const GICD_BASE: u64 = 0x0800_0000;
const GICR_BASE: u64 = 0x080a_0000;
const VIRTIO_MMIO_BASE: u64 = 0x0a00_0000;
const VIRTIO_MMIO_SIZE: u64 = 0x200;
const VIRTIO_MMIO_SPI: u32 = 3; // INTID = SPI + 32 = 35

/// Where we park the generated DTB in guest RAM (4 MB into RAM).
const DTB_OFFSET: u64 = 0x0040_0000;

// PSCI function IDs (SMC64 convention).
const PSCI_SYSTEM_OFF: u64 = 0x8400_0008;
const PSCI_SYSTEM_RESET: u64 = 0x8400_0009;
const PSCI_CPU_ON: u64 = 0xC400_0003;
const PSCI_NOT_SUPPORTED: u64 = (-1i64) as u64;

// Virtual timer PPI (INTID 27).
const VTIMER_INTID: u32 = 27;

pub struct Vm {
    ram_host: *mut u8,
    ram_size: usize,
    vcpu: hv_vcpu_t,
    exit_ptr: *mut HvVcpuExit,
}

impl Vm {
    /// Create a VM with a default MAC address.
    #[allow(dead_code)]
    pub fn new(kernel_path: &str, ram_mib: usize) -> Result<Self, String> {
        Self::new_with_mac(kernel_path, ram_mib, [0x52, 0x54, 0x00, 0x12, 0x34, 0x56])
    }

    /// Create a VM, allocate RAM, set up vGIC, create vCPU, load kernel,
    /// generate FDT, configure initial register state.
    pub fn new_with_mac(kernel_path: &str, ram_mib: usize, mac: [u8; 6]) -> Result<Self, String> {
        let ram_size_fdt = ram_mib * 1024 * 1024;
        // Map twice the FDT-declared size. The kernel's boot.S maps the
        // first 4 GB as 1 GB L1 blocks, so guest accesses past the FDT
        // boundary are valid page-table-wise. The kernel's heap and
        // frame bitmap can touch addresses right at ram_base + ram_size
        // (e.g., memset zeroing the bitmap's last word extends one
        // 8-byte store past the declared boundary). QEMU doesn't have
        // this problem because it maps a full 1 GB at 0x40000000.
        // We map 2× to be safe. The extra RAM is unused but mapped.
        // Map a full 1 GB (the L1 page-table block size) regardless of
        // the FDT-declared RAM size. boot.S maps L1[1] as a 1 GB Normal
        // block covering 0x40000000–0x7FFFFFFF, and the kernel's heap
        // init zeroes memory past the declared boundary (memset of the
        // frame bitmap can overshoot). QEMU doesn't hit this because it
        // maps the entire virt machine's RAM space. 1 GB is the minimum
        // that guarantees no stage-2 fault from any normal-cached access.
        let ram_mapped = 1024 * 1024 * 1024; // 1 GB

        // 1. Create the VM with a large enough IPA space.
        // The kernel's PCI ECAM fallback is at 0x4010000000 (274 GB),
        // which requires at least 39-bit IPA. Use a VM config to
        // request sufficient IPA size.
        let vm_cfg = unsafe { hv_vm_config_create() };
        if !vm_cfg.is_null() {
            // Query and set max IPA size.
            let mut max_ipa: u32 = 0;
            let mut default_ipa: u32 = 0;
            unsafe {
                hv_vm_config_get_max_ipa_size(&mut max_ipa);
                hv_vm_config_get_default_ipa_size(&mut default_ipa);
            }
            if max_ipa > default_ipa {
                let _ = unsafe { hv_vm_config_set_ipa_size(vm_cfg, max_ipa) };
            }
        }
        check(unsafe { hv_vm_create(vm_cfg) })
            .map_err(|e| format!("hv_vm_create: {e}"))?;

        // 2. Allocate guest RAM.
        let mut ram_ptr: *mut c_void = ptr::null_mut();
        check(unsafe { hv_vm_allocate(&mut ram_ptr, ram_mapped, 0) })
            .map_err(|e| format!("hv_vm_allocate: {e}"))?;
        let ram_host = ram_ptr as *mut u8;
        unsafe { ptr::write_bytes(ram_host, 0, ram_mapped); }

        // 3. Map RAM into guest IPA space (the full allocation including slack).
        check(unsafe {
            hv_vm_map(
                ram_host as *mut c_void,
                RAM_BASE,
                ram_mapped,
                HV_MEMORY_READ | HV_MEMORY_WRITE | HV_MEMORY_EXEC,
            )
        })
        .map_err(|e| format!("hv_vm_map: {e}"))?;

        // 3b. Map a 1 MB region at the default PCIe ECAM address so the
        // kernel's PCI bus scan (which falls back to ECAM_BASE_DEFAULT =
        // 0x4010000000 when no PCI node is in the FDT) reads all zeros
        // instead of faulting on unmapped IPA. The scan finds no devices
        // and completes harmlessly. This is cheaper than adding a full
        // PCI node to the FDT.
        let ecam_size: usize = 1024 * 1024; // 1 MB
        let mut ecam_ptr: *mut c_void = ptr::null_mut();
        let rc = unsafe { hv_vm_allocate(&mut ecam_ptr, ecam_size, 0) };
        if rc == HV_SUCCESS && !ecam_ptr.is_null() {
            unsafe { ptr::write_bytes(ecam_ptr as *mut u8, 0xff, ecam_size); }
            let _ = unsafe {
                hv_vm_map(ecam_ptr, 0x40_1000_0000, ecam_size,
                          HV_MEMORY_READ | HV_MEMORY_WRITE)
            };
        }

        // 4. Create native vGIC (must be before vCPU creation).
        let gic_cfg = unsafe { hv_gic_config_create() };
        if gic_cfg.is_null() {
            return Err("hv_gic_config_create returned null".into());
        }
        check(unsafe { hv_gic_config_set_distributor_base(gic_cfg, GICD_BASE) })
            .map_err(|e| format!("gic dist base: {e}"))?;
        check(unsafe { hv_gic_config_set_redistributor_base(gic_cfg, GICR_BASE) })
            .map_err(|e| format!("gic redist base: {e}"))?;
        check(unsafe { hv_gic_create(gic_cfg) })
            .map_err(|e| format!("hv_gic_create: {e}"))?;

        // 5. Create vCPU.
        let mut vcpu: hv_vcpu_t = 0;
        let mut exit_ptr: *mut HvVcpuExit = ptr::null_mut();
        check(unsafe { hv_vcpu_create(&mut vcpu, &mut exit_ptr, ptr::null_mut()) })
            .map_err(|e| format!("hv_vcpu_create: {e}"))?;

        // 6. Set MPIDR_EL1 (RES1 bit 31 + affinity 0 = CPU 0).
        check(unsafe { hv_vcpu_set_sys_reg(vcpu, HvSysReg::MpidrEl1, 0x8000_0000) })
            .map_err(|e| format!("set MPIDR: {e}"))?;

        // 7. Query the redistributor base HVF assigned (for the FDT).
        let mut gicr_actual: u64 = GICR_BASE;
        let _ = unsafe { hv_gic_get_redistributor_base(vcpu, &mut gicr_actual) };

        // 8. Load kernel image into guest RAM at offset 0 (entry = RAM_BASE).
        let kernel = std::fs::read(kernel_path)
            .map_err(|e| format!("read kernel {kernel_path}: {e}"))?;
        if kernel.len() > ram_size_fdt - DTB_OFFSET as usize {
            return Err(format!(
                "kernel too large: {} bytes (max {})",
                kernel.len(),
                ram_size_fdt - DTB_OFFSET as usize
            ));
        }
        unsafe {
            ptr::copy_nonoverlapping(kernel.as_ptr(), ram_host, kernel.len());
        }

        // 9. Generate FDT and write it into guest RAM at DTB_OFFSET.
        // Tell the kernel only about the nominal RAM size (not the slack).
        let dtb = fdt::generate(
            RAM_BASE,
            ram_size_fdt as u64,
            GICD_BASE,
            gicr_actual,
            PL011_BASE,
            &[fdt::VirtioMmioDesc {
                base: VIRTIO_MMIO_BASE,
                size: VIRTIO_MMIO_SIZE,
                spi: VIRTIO_MMIO_SPI,
            }],
        );
        let dtb_guest_addr = RAM_BASE + DTB_OFFSET;
        unsafe {
            ptr::copy_nonoverlapping(
                dtb.as_ptr(),
                ram_host.add(DTB_OFFSET as usize),
                dtb.len(),
            );
        }

        // 10. Set initial register state.
        //   PC    = RAM_BASE (kernel entry point)
        //   X0    = DTB physical address
        //   CPSR  = EL1h with all DAIF masked (0x3c5)
        let reg_writes: &[(HvReg, u64)] = &[
            (HvReg::Pc, RAM_BASE),
            (HvReg::X0, dtb_guest_addr),
            (HvReg::Cpsr, 0x3c5),
        ];
        for &(reg, val) in reg_writes {
            check(unsafe { hv_vcpu_set_reg(vcpu, reg, val) })
                .map_err(|e| format!("set {reg:?}: {e}"))?;
        }

        // 11. Initialize the virtio-mmio net device.
        *virtio::DEVICE.lock().unwrap() = Some(
            virtio::VirtioNet::new(mac, ram_host, RAM_BASE)
        );

        Ok(Vm { ram_host, ram_size: ram_mapped, vcpu, exit_ptr })
    }

    /// Run the vCPU until the guest executes PSCI SYSTEM_OFF or an
    /// unrecoverable error occurs.
    pub fn run(&mut self) -> Result<(), String> {
        // Publish vCPU ID so the RX thread can kick us via hv_vcpus_exit.
        crate::vmnet_net::VCPU_ID.store(
            self.vcpu,
            std::sync::atomic::Ordering::Release,
        );

        let mut _exit_count: u64 = 0;
        loop {
            check(unsafe { hv_vcpu_run(self.vcpu) })
                .map_err(|e| format!("hv_vcpu_run: {e}"))?;

            // Check for pending RX frames on every exit. This is the
            // only safe point to inject frames because it runs in the
            // vCPU thread context (guaranteeing cache coherency with
            // the guest's view of RAM).
            crate::vmnet_net::check_rx();

            let exit = unsafe { &*self.exit_ptr };
            _exit_count += 1;

            match exit.reason {
                HV_EXIT_REASON_EXCEPTION => {
                    let ec = esr_ec(exit.exception.syndrome);
                    match ec {
                        EC_HVC => {
                            if self.handle_hvc(exit)? {
                                return Ok(());
                            }
                        }
                        EC_DATA_ABORT_LOWER | EC_DATA_ABORT_SAME => {
                            self.handle_mmio(exit)?;
                        }
                        _ => {
                            return Err(format!(
                                "unhandled exception EC=0x{ec:x} syndrome=0x{:x} \
                                 PC=0x{:x} VA=0x{:x} PA=0x{:x}",
                                exit.exception.syndrome,
                                self.get_reg(HvReg::Pc),
                                exit.exception.virtual_address,
                                exit.exception.physical_address,
                            ));
                        }
                    }
                }
                HV_EXIT_REASON_VTIMER_ACTIVATED => {
                    // The virtual timer fired. HVF auto-masks it.
                    // Make the VTimer PPI (INTID 27) pending in the vGIC
                    // so the guest's timer ISR runs on the next entry.
                    let _ = unsafe { hv_gic_set_spi(VTIMER_INTID, true) };
                    // Note: INTID 27 is a PPI, not an SPI. hv_gic_set_spi
                    // might not work for PPIs. If the guest's timer ISR
                    // doesn't fire, we'll need hv_vcpu_set_pending_interrupt
                    // instead. TODO: verify empirically.
                }
                HV_EXIT_REASON_CANCELED => {
                    // RX notify thread kicked us. check_rx() already
                    // ran at the top of the loop. Just resume.
                }
                _ => {
                    return Err(format!("unknown exit reason: {}", exit.reason));
                }
            }
        }
    }

    /// Handle an HVC instruction. Returns true if the guest requested shutdown.
    fn handle_hvc(&self, exit: &HvVcpuExit) -> Result<bool, String> {
        // The HVC immediate is in ESR_EL2 bits 15:0. But for PSCI,
        // the function ID is in x0, not the immediate.
        let x0 = self.get_reg(HvReg::X0);

        match x0 {
            PSCI_SYSTEM_OFF | PSCI_SYSTEM_RESET => {
                return Ok(true); // guest wants to shut down
            }
            PSCI_CPU_ON => {
                // SMP not implemented yet — return PSCI_NOT_SUPPORTED.
                self.set_reg(HvReg::X0, PSCI_NOT_SUPPORTED);
            }
            _ => {
                // Unknown PSCI call — return not supported.
                eprintln!(
                    "hvf: unknown HVC x0=0x{x0:x} imm=0x{:x}",
                    esr_hvc_imm(exit.exception.syndrome)
                );
                self.set_reg(HvReg::X0, PSCI_NOT_SUPPORTED);
            }
        }

        // Advance PC past the HVC instruction (4 bytes).
        let pc = self.get_reg(HvReg::Pc);
        self.set_reg(HvReg::Pc, pc + 4);
        Ok(false)
    }

    /// Handle a stage-2 data abort by decoding the faulting instruction
    /// and dispatching to the appropriate device emulator.
    fn handle_mmio(&self, exit: &HvVcpuExit) -> Result<(), String> {
        let fault_ipa = exit.exception.physical_address;
        let pc = self.get_reg(HvReg::Pc);

        // Fetch the faulting instruction from host-side guest RAM.
        let pc_offset = pc.checked_sub(RAM_BASE)
            .ok_or_else(|| format!("PC 0x{pc:x} outside guest RAM"))?;
        if pc_offset as usize + 4 > self.ram_size {
            return Err(format!("PC 0x{pc:x} past end of guest RAM"));
        }
        let instr = unsafe {
            ptr::read_unaligned(self.ram_host.add(pc_offset as usize) as *const u32)
        };

        // Decode.
        let access = decoder::decode(instr).ok_or_else(|| {
            format!(
                "unhandled MMIO instruction at PC=0x{pc:x}: 0x{instr:08x} \
                 (fault IPA=0x{fault_ipa:x}) — add a decoder case"
            )
        })?;

        // Route by IPA to the correct device.
        if fault_ipa >= PL011_BASE && fault_ipa < PL011_BASE + PL011_SIZE {
            let offset = fault_ipa - PL011_BASE;
            if access.is_write {
                let val = if access.rt == 31 { 0 } else { self.get_reg(HvReg::gpr(access.rt as u32)) };
                pl011::mmio_write(offset, access.size, val);
            } else {
                let val = pl011::mmio_read(offset, access.size);
                if access.rt < 31 {
                    self.set_reg(HvReg::gpr(access.rt as u32), val);
                }
            }
        } else if fault_ipa >= GICD_BASE && fault_ipa < GICD_BASE + 0x1_0000 {
            // GIC distributor MMIO. The native vGIC handles most registers
            // internally, but some accesses (like IROUTER writes) still
            // trap out to us. Forward writes to hv_gic_set_distributor_reg
            // and reads to hv_gic_get_distributor_reg.
            let offset = (fault_ipa - GICD_BASE) as u32;
            if access.is_write {
                let val = if access.rt == 31 { 0 } else {
                    self.get_reg(HvReg::gpr(access.rt as u32))
                };
                unsafe { hv_gic_set_distributor_reg(offset, val) };
            } else {
                let mut val: u64 = 0;
                unsafe { hv_gic_get_distributor_reg(offset, &mut val) };
                if access.rt < 31 {
                    self.set_reg(HvReg::gpr(access.rt as u32), val);
                }
            }
        } else if fault_ipa >= GICR_BASE && fault_ipa < GICR_BASE + 0x4_0000 {
            // GIC redistributor MMIO. Same pattern as distributor.
            let offset = (fault_ipa - GICR_BASE) as u32;
            if access.is_write {
                let val = if access.rt == 31 { 0 } else {
                    self.get_reg(HvReg::gpr(access.rt as u32))
                };
                unsafe { hv_gic_set_redistributor_reg(self.vcpu, offset, val) };
            } else {
                let mut val: u64 = 0;
                unsafe { hv_gic_get_redistributor_reg(self.vcpu, offset, &mut val) };
                if access.rt < 31 {
                    self.set_reg(HvReg::gpr(access.rt as u32), val);
                }
            }
        } else if fault_ipa >= VIRTIO_MMIO_BASE
            && fault_ipa < VIRTIO_MMIO_BASE + VIRTIO_MMIO_SIZE
        {
            let offset = fault_ipa - VIRTIO_MMIO_BASE;

            let mut notify_queue: Option<u32> = None;
            {
                let mut dev_lock = virtio::DEVICE.lock().unwrap();
                let dev = dev_lock.as_mut().unwrap();
                if access.is_write {
                    let val = if access.rt == 31 { 0 } else {
                        self.get_reg(HvReg::gpr(access.rt as u32)) as u32
                    };
                    if dev.write(offset, val) {
                        notify_queue = Some(val);
                    }
                } else {
                    let val = dev.read(offset);
                    if access.rt < 31 {
                        self.set_reg(HvReg::gpr(access.rt as u32), val as u64);
                    }
                }
            } // dev_lock released
            if let Some(queue) = notify_queue {
                if queue == 1 {
                    crate::vmnet_net::process_tx();
                }
            }
        } else {
            // Unknown device address. Return 0 on reads, ignore writes.
            // Don't log every access — the kernel probes many addresses
            // during init (virtio-console at IPA 0, etc.) and logging
            // each one would flood stderr.
            if !access.is_write && access.rt < 31 {
                self.set_reg(HvReg::gpr(access.rt as u32), 0);
            }
        }

        // Advance PC past the faulting instruction.
        self.set_reg(HvReg::Pc, pc + 4);
        Ok(())
    }

    // ── Register helpers ─────────────────────────────────────────────────────

    fn get_reg(&self, reg: HvReg) -> u64 {
        let mut v: u64 = 0;
        unsafe { hv_vcpu_get_reg(self.vcpu, reg, &mut v) };
        v
    }

    fn set_reg(&self, reg: HvReg, value: u64) {
        unsafe { hv_vcpu_set_reg(self.vcpu, reg, value) };
    }
}

impl Drop for Vm {
    fn drop(&mut self) {
        unsafe {
            let _ = hv_vcpu_destroy(self.vcpu);
            let _ = hv_vm_deallocate(self.ram_host as *mut c_void, self.ram_size);
            let _ = hv_vm_destroy();
        }
    }
}
