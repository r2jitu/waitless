// tools/hvf-runner/src/vm.rs
//
// VM + vCPU lifecycle, run loop, and exception dispatch.
//
// Manages the full lifecycle: create VM → allocate RAM → create vGIC →
// create N vCPUs → load kernel → generate FDT → run loop. The run loop
// handles HVC (PSCI), stage-2 data aborts (MMIO), vtimer, and WFI.
//
// Multi-core: vCPU 0 runs on the caller's thread. Secondary vCPUs are
// started on demand via PSCI CPU_ON, each on its own OS thread.

use std::ffi::c_void;
use std::ptr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

use crate::decoder;
use crate::fdt;
use crate::hvf::*;
use crate::pl011;
use crate::virtio;

// ── Global vCPU handles for IO thread wakeup ────────────────────────────────
// Stored as AtomicU64 so the IO thread can read without locking.
// Set once when each vCPU is created; never modified after.
static VCPU_HANDLES: [AtomicU64; MAX_VCPUS] = {
    const INIT: AtomicU64 = AtomicU64::new(0);
    [INIT; MAX_VCPUS]
};

/// Kick a specific vCPU out of `hv_vcpu_run`. Used by the userspace
/// net accept thread to doorbell a vCPU when it hands it a new conn —
/// pairs with the wake pipe in `userspace_net::wake_vcpu`. The
/// resulting CANCELED exit is harmless; the run loop calls
/// `vcpu_poll(0)` before re-entering the guest, which picks up the
/// new conn from `WORKERS[id].conns`.
pub fn wake_vcpu(core_id: usize) {
    if core_id >= MAX_VCPUS { return; }
    let handle = VCPU_HANDLES[core_id].load(Ordering::Acquire);
    if handle != 0 {
        unsafe { hv_vcpus_exit(&handle as *const u64 as *const _, 1); }
    }
}

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
const PSCI_SUCCESS: u64 = 0;
const PSCI_ALREADY_ON: u64 = (-4i64) as u64;
#[allow(dead_code)]
const PSCI_NOT_SUPPORTED: u64 = (-1i64) as u64;

// Virtual timer PPI (INTID 27).
#[allow(dead_code)]
const VTIMER_INTID: u32 = 27;

/// Maximum number of vCPUs we support.
const MAX_VCPUS: usize = 8;

// ── Cooperative yield — guest MMIO write parks the vCPU thread ─────────────
// Address chosen right after PL011 (0x09000000). Not mapped in stage-2,
// so a guest access causes a data abort that we intercept in the run loop.
const YIELD_MMIO_BASE: u64 = 0x0900_1000;
const YIELD_MMIO_SIZE: u64 = 0x1000;

// ── Thread-safe raw pointer wrapper ─────────────────────────────────────────

/// Wrapper for a raw pointer that is safe to send across threads.
/// SAFETY: The guest RAM mapping is stable for the VM's entire lifetime
/// and all accesses are to disjoint regions or protected by Mutex.
#[derive(Copy, Clone)]
struct SendPtr(*mut u8);
unsafe impl Send for SendPtr {}
unsafe impl Sync for SendPtr {}

// ── Per-vCPU state ──────────────────────────────────────────────────────────

/// State for a single vCPU. Shared between the VM owner and the vCPU's
/// run thread (for PSCI CPU_ON startup).
struct VcpuInfo {
    vcpu: hv_vcpu_t,
    exit_ptr: *mut HvVcpuExit,
    /// Set to true once the vCPU thread is running. Used for PSCI
    /// ALREADY_ON detection.
    running: AtomicBool,
}

// SAFETY: hv_vcpu_t is an opaque handle (u64). The exit_ptr is a stable
// allocation from HVF. We never dereference exit_ptr from a thread other
// than the vCPU's own run thread, and the VcpuInfo is only mutated
// (registers set) while the vCPU is not yet running.
unsafe impl Send for VcpuInfo {}
unsafe impl Sync for VcpuInfo {}

pub struct Vm {
    ram_host: *mut u8,
    ram_size: usize,
    vcpus: Vec<Arc<VcpuInfo>>,
    /// Global shutdown flag — set by any vCPU on PSCI SYSTEM_OFF.
    shutdown: Arc<AtomicBool>,
}

impl Vm {
    /// Create a VM, allocate RAM, set up vGIC, create `cpu_count` vCPUs,
    /// load kernel, generate FDT, configure initial register state for vCPU 0.
    ///
    /// `cpu_count` is clamped to [1, MAX_VCPUS]. 1 vCPU is the default and
    /// tends to be optimal for this workload; cooperative MMIO yield keeps
    /// idle vCPUs at zero CPU, so multi-core is also safe to use.
    pub fn new_with_config(
        kernel_path: &str,
        ram_mib: usize,
        cpu_count: usize,
        mac: [u8; 6],
    ) -> Result<Self, String> {
        let ram_size_fdt = ram_mib * 1024 * 1024;
        // Map a full 1 GB (the L1 page-table block size) regardless of
        // the FDT-declared RAM size. boot.S maps L1[1] as a 1 GB Normal
        // block covering 0x40000000–0x7FFFFFFF, and the kernel's heap
        // init zeroes memory past the declared boundary.
        let ram_mapped = 1024 * 1024 * 1024; // 1 GB

        let cpu_count = cpu_count.clamp(1, MAX_VCPUS);
        eprintln!("  vCPU count: {cpu_count}");

        // 1. Create the VM with a large enough IPA space.
        let vm_cfg = unsafe { hv_vm_config_create() };
        if !vm_cfg.is_null() {
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

        // 3. Map RAM into guest IPA space.
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
        // kernel's PCI bus scan reads all-ones instead of faulting.
        let ecam_size: usize = 1024 * 1024;
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

        // 5. Create vCPU 0 only. Secondary vCPUs are created on their
        // own threads during PSCI CPU_ON — HVF requires hv_vcpu_create
        // to be called from the thread that will run the vCPU.
        let mut vcpus: Vec<Arc<VcpuInfo>> = Vec::with_capacity(cpu_count);
        {
            let mut vcpu: hv_vcpu_t = 0;
            let mut exit_ptr: *mut HvVcpuExit = ptr::null_mut();
            check(unsafe { hv_vcpu_create(&mut vcpu, &mut exit_ptr, ptr::null_mut()) })
                .map_err(|e| format!("hv_vcpu_create(cpu 0): {e}"))?;
            check(unsafe { hv_vcpu_set_sys_reg(vcpu, HvSysReg::MpidrEl1, 0x8000_0000) })
                .map_err(|e| format!("set MPIDR(cpu 0): {e}"))?;
            // Publish handle for IO thread wakeup.
            VCPU_HANDLES[0].store(vcpu, Ordering::Release);
            vcpus.push(Arc::new(VcpuInfo {
                vcpu,
                exit_ptr,
                running: AtomicBool::new(false),
            }));
        }
        // Pre-allocate slots for secondary vCPUs (filled in PSCI CPU_ON).
        for _ in 1..cpu_count {
            vcpus.push(Arc::new(VcpuInfo {
                vcpu: 0,
                exit_ptr: ptr::null_mut(),
                running: AtomicBool::new(false),
            }));
        }

        // 5b. Route virtio SPI (INTID 35) to core 0 only so the interrupt
        // doesn't broadcast to all cores (which causes WFI wake storms).
        // GICD_IROUTER for INTID N is at offset 0x6000 + N*8.
        // Value 0x0 = Aff0=0 (core 0). Default 0x80000000 = any PE.
        if cpu_count > 1 {
            let intid = 32 + VIRTIO_MMIO_SPI; // SPI 3 → INTID 35
            let irouter_off = (0x6000 + intid * 8) as u32;
            unsafe { hv_gic_set_distributor_reg(irouter_off, 0x0); }
        }

        // 6. Query the redistributor base HVF assigned (for the FDT).
        let mut gicr_actual: u64 = GICR_BASE;
        let _ = unsafe { hv_gic_get_redistributor_base(vcpus[0].vcpu, &mut gicr_actual) };

        // 7. Load kernel image into guest RAM at offset 0 (entry = RAM_BASE).
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

        // 8. Generate FDT and write it into guest RAM at DTB_OFFSET.
        let dtb = fdt::generate(
            RAM_BASE,
            ram_size_fdt as u64,
            GICD_BASE,
            gicr_actual,
            PL011_BASE,
            cpu_count,
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

        // 9. Set initial register state for vCPU 0 only.
        //   PC    = RAM_BASE (kernel entry point)
        //   X0    = DTB physical address
        //   CPSR  = EL1h with all DAIF masked (0x3c5)
        let vcpu0 = vcpus[0].vcpu;
        let reg_writes: &[(HvReg, u64)] = &[
            (HvReg::Pc, RAM_BASE),
            (HvReg::X0, dtb_guest_addr),
            (HvReg::Cpsr, 0x3c5),
        ];
        for &(reg, val) in reg_writes {
            check(unsafe { hv_vcpu_set_reg(vcpu0, reg, val) })
                .map_err(|e| format!("set {reg:?}: {e}"))?;
        }
        // Mark vCPU 0 as running.
        vcpus[0].running.store(true, Ordering::Release);

        // 10. Initialize the virtio-mmio net device.
        *virtio::DEVICE.lock().unwrap() = Some(
            virtio::VirtioNet::new(mac, ram_host, RAM_BASE, cpu_count)
        );

        let shutdown = Arc::new(AtomicBool::new(false));
        Ok(Vm { ram_host, ram_size: ram_mapped, vcpus, shutdown })
    }

    /// Run vCPU 0 until the guest executes PSCI SYSTEM_OFF or an
    /// unrecoverable error occurs. Secondary vCPUs are started via
    /// PSCI CPU_ON from within the run loop.
    pub fn run(&mut self) -> Result<(), String> {
        let vcpu_info = self.vcpus[0].clone();
        let all_vcpus = self.vcpus.clone();
        let shutdown = self.shutdown.clone();
        let ram = SendPtr(self.ram_host);
        let ram_size = self.ram_size;

        run_vcpu(0, vcpu_info, all_vcpus, shutdown, ram, ram_size)
    }
}

/// Run a single vCPU in a loop. This is the common run loop used by
/// vCPU 0 (on the caller's thread) and secondary vCPUs (on spawned threads).
fn run_vcpu(
    vcpu_id: usize,
    info: Arc<VcpuInfo>,
    all_vcpus: Vec<Arc<VcpuInfo>>,
    shutdown: Arc<AtomicBool>,
    ram: SendPtr,
    ram_size: usize,
) -> Result<(), String> {
    let vcpu = info.vcpu;
    let exit_ptr = info.exit_ptr;
    let ram_host = ram.0;

    let mut vtimer_masked = false;
    let mut vtimer_pending = false;

    loop {
        // Check global shutdown flag (set by any vCPU on PSCI SYSTEM_OFF).
        if shutdown.load(Ordering::Acquire) {
            return Ok(());
        }

        // Inline-poll: drain host fds non-blockingly before re-entering
        // the guest. Replaces the spawned-worker-thread design — the
        // vCPU thread itself owns the host fds for its queue pair.
        crate::userspace_net::vcpu_poll(vcpu_id, 0);

        // Inject pending vtimer IRQ before entering the guest.
        if vtimer_pending {
            unsafe { hv_vcpu_set_pending_interrupt(vcpu, 0, true); }
        }

        check(unsafe { hv_vcpu_run(vcpu) })
            .map_err(|e| format!("hv_vcpu_run(cpu {vcpu_id}): {e}"))?;

        let exit = unsafe { &*exit_ptr };

        match exit.reason {
            HV_EXIT_REASON_EXCEPTION => {
                let ec = esr_ec(exit.exception.syndrome);
                match ec {
                    EC_HVC => {
                        let result = handle_hvc(
                            vcpu_id, vcpu, exit,
                            &all_vcpus, &shutdown,
                            ram, ram_size,
                        )?;
                        if result {
                            return Ok(());
                        }
                    }
                    EC_DATA_ABORT_LOWER | EC_DATA_ABORT_SAME => {
                        let fault_ipa = exit.exception.physical_address;
                        if fault_ipa >= YIELD_MMIO_BASE
                            && fault_ipa < YIELD_MMIO_BASE + YIELD_MMIO_SIZE
                        {
                            // Cooperative yield — block in the inline
                            // poll until host I/O arrives. The vCPU
                            // thread itself does the polling now, so
                            // there's no separate worker to wait on.
                            // Cap each poll at 10ms so we re-check the
                            // global shutdown flag promptly.
                            while !shutdown.load(Ordering::Acquire) {
                                if crate::userspace_net::vcpu_poll(vcpu_id, 10) {
                                    break;
                                }
                            }
                            let pc = get_reg(vcpu, HvReg::Pc);
                            set_reg(vcpu, HvReg::Pc, pc + 4);
                        } else {
                            handle_mmio(vcpu, exit, ram_host, ram_size)?;
                        }
                    }
                    _ => {
                        return Err(format!(
                            "cpu {vcpu_id}: unhandled exception EC=0x{ec:x} \
                             syndrome=0x{:x} PC=0x{:x} VA=0x{:x} PA=0x{:x}",
                            exit.exception.syndrome,
                            get_reg(vcpu, HvReg::Pc),
                            exit.exception.virtual_address,
                            exit.exception.physical_address,
                        ));
                    }
                }

                // After every exception exit: check if the guest
                // cleared the vtimer.
                if vtimer_masked {
                    let cntv_ctl = get_sys_reg(vcpu, HvSysReg::CntvCtlEl0);
                    let enabled = cntv_ctl & 1;
                    let istatus = (cntv_ctl >> 1) & 1;
                    let imask = (cntv_ctl >> 2) & 1;
                    if enabled == 0 || imask != 0 || istatus == 0 {
                        unsafe { hv_vcpu_set_vtimer_mask(vcpu, false); }
                        vtimer_masked = false;
                        vtimer_pending = false;
                    }
                }
            }
            HV_EXIT_REASON_VTIMER_ACTIVATED => {
                vtimer_masked = true;
                vtimer_pending = true;
            }
            HV_EXIT_REASON_CANCELED => {
                // IO thread kicked us via hv_vcpus_exit, or shutdown.
            }
            _ => {
                return Err(format!(
                    "cpu {vcpu_id}: unknown exit reason: {}", exit.reason
                ));
            }
        }
    }
}

/// Handle an HVC instruction. Returns true if the guest requested shutdown.
fn handle_hvc(
    vcpu_id: usize,
    vcpu: hv_vcpu_t,
    exit: &HvVcpuExit,
    all_vcpus: &[Arc<VcpuInfo>],
    shutdown: &Arc<AtomicBool>,
    ram: SendPtr,
    ram_size: usize,
) -> Result<bool, String> {
    let x0 = get_reg(vcpu, HvReg::X0);

    match x0 {
        PSCI_SYSTEM_OFF | PSCI_SYSTEM_RESET => {
            // Signal all vCPUs to stop. The inline-poll idle loop
            // checks `shutdown` between 10ms `poll(2)` waits, so any
            // vCPU sitting in the cooperative-yield path observes it
            // promptly. vCPUs inside `hv_vcpu_run` get kicked out via
            // `hv_vcpus_exit`; the resulting CANCELED exit is harmless.
            shutdown.store(true, Ordering::Release);
            for vi in all_vcpus.iter() {
                if vi.running.load(Ordering::Acquire) {
                    let _ = unsafe {
                        hv_vcpus_exit(&vi.vcpu as *const _, 1)
                    };
                }
            }
            return Ok(true);
        }
        PSCI_CPU_ON => {
            let target_mpidr = get_reg(vcpu, HvReg::X1);
            let entry_point = get_reg(vcpu, HvReg::X2);
            let context_id = get_reg(vcpu, HvReg::X3);

            // Extract cpu index from MPIDR affinity bits.
            // MPIDR format: Aff3[39:32] | Aff2[23:16] | Aff1[15:8] | Aff0[7:0]
            // Our MPIDRs are simple: 0x80000000 | cpu_id, so Aff0 = cpu_id.
            let target_id = (target_mpidr & 0xff) as usize;

            if target_id >= all_vcpus.len() {
                // Invalid CPU — return PSCI_INVALID_PARAMETERS (-2).
                set_reg(vcpu, HvReg::X0, (-2i64) as u64);
            } else if all_vcpus[target_id].running.load(Ordering::Acquire) {
                set_reg(vcpu, HvReg::X0, PSCI_ALREADY_ON);
            } else {
                // Mark as running before spawning the thread.
                all_vcpus[target_id].running.store(true, Ordering::Release);

                // Clone Arcs for the new thread.
                let vcpus_clone = all_vcpus.to_vec();
                let shutdown_clone = shutdown.clone();

                // HVF requires hv_vcpu_create on the thread that runs it.
                // Pass entry_point and context_id to the thread which
                // creates the vCPU, sets registers, and enters the run loop.
                std::thread::Builder::new()
                    .name(format!("vcpu-{target_id}"))
                    .spawn(move || {
                        // Create vCPU on this thread.
                        let mut new_vcpu: hv_vcpu_t = 0;
                        let mut new_exit: *mut HvVcpuExit = ptr::null_mut();
                        let rc = unsafe {
                            hv_vcpu_create(&mut new_vcpu, &mut new_exit, ptr::null_mut())
                        };
                        if rc != HV_SUCCESS {
                            eprintln!("vcpu-{target_id}: hv_vcpu_create failed: 0x{rc:x}");
                            return;
                        }
                        // Publish handle for IO thread wakeup.
                        VCPU_HANDLES[target_id].store(new_vcpu, Ordering::Release);
                        // Set MPIDR.
                        let mpidr = 0x8000_0000u64 | (target_id as u64);
                        unsafe { hv_vcpu_set_sys_reg(new_vcpu, HvSysReg::MpidrEl1, mpidr); }
                        // Set initial registers.
                        unsafe {
                            hv_vcpu_set_reg(new_vcpu, HvReg::Pc, entry_point);
                            hv_vcpu_set_reg(new_vcpu, HvReg::X0, context_id);
                            hv_vcpu_set_reg(new_vcpu, HvReg::Cpsr, 0x3c5);
                        }
                        // Update the VcpuInfo slot (ugly but the Arc is shared).
                        // SAFETY: no other thread accesses these fields before
                        // running is set to true (which already happened).
                        let info = &vcpus_clone[target_id];
                        let info_ptr = Arc::as_ptr(info) as *mut VcpuInfo;
                        unsafe {
                            (*info_ptr).vcpu = new_vcpu;
                            (*info_ptr).exit_ptr = new_exit;
                        }
                        if let Err(e) = run_vcpu(
                            target_id,
                            info.clone(),
                            vcpus_clone,
                            shutdown_clone,
                            ram,
                            ram_size,
                        ) {
                            eprintln!("vcpu-{target_id}: {e}");
                        }
                    })
                    .map_err(|e| format!("spawn vcpu-{target_id}: {e}"))?;

                eprintln!(
                    "  cpu {vcpu_id}: PSCI CPU_ON target={target_id} \
                     entry=0x{entry_point:x} ctx=0x{context_id:x}"
                );
                set_reg(vcpu, HvReg::X0, PSCI_SUCCESS);
            }
        }
        _ => {
            eprintln!(
                "cpu {vcpu_id}: unknown HVC x0=0x{x0:x} imm=0x{:x}",
                esr_hvc_imm(exit.exception.syndrome)
            );
            set_reg(vcpu, HvReg::X0, PSCI_NOT_SUPPORTED);
        }
    }

    // Advance PC past the HVC instruction (4 bytes).
    let pc = get_reg(vcpu, HvReg::Pc);
    set_reg(vcpu, HvReg::Pc, pc + 4);
    Ok(false)
}

/// Handle a stage-2 data abort by decoding the faulting instruction
/// and dispatching to the appropriate device emulator.
fn handle_mmio(
    vcpu: hv_vcpu_t,
    exit: &HvVcpuExit,
    ram_host: *mut u8,
    ram_size: usize,
) -> Result<(), String> {
    let fault_ipa = exit.exception.physical_address;
    let pc = get_reg(vcpu, HvReg::Pc);

    // Fetch the faulting instruction from host-side guest RAM.
    let pc_offset = pc.checked_sub(RAM_BASE)
        .ok_or_else(|| format!("PC 0x{pc:x} outside guest RAM"))?;
    if pc_offset as usize + 4 > ram_size {
        return Err(format!("PC 0x{pc:x} past end of guest RAM"));
    }
    let instr = unsafe {
        ptr::read_unaligned(ram_host.add(pc_offset as usize) as *const u32)
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
            let val = if access.rt == 31 { 0 } else { get_reg(vcpu, HvReg::gpr(access.rt as u32)) };
            pl011::mmio_write(offset, access.size, val);
        } else {
            let val = pl011::mmio_read(offset, access.size);
            if access.rt < 31 {
                set_reg(vcpu, HvReg::gpr(access.rt as u32), val);
            }
        }
    } else if fault_ipa >= GICD_BASE && fault_ipa < GICD_BASE + 0x1_0000 {
        // GIC distributor MMIO.
        let offset = (fault_ipa - GICD_BASE) as u32;
        if access.is_write {
            let val = if access.rt == 31 { 0 } else {
                get_reg(vcpu, HvReg::gpr(access.rt as u32))
            };
            unsafe { hv_gic_set_distributor_reg(offset, val) };
        } else {
            let mut val: u64 = 0;
            unsafe { hv_gic_get_distributor_reg(offset, &mut val) };
            if access.rt < 31 {
                set_reg(vcpu, HvReg::gpr(access.rt as u32), val);
            }
        }
    } else if fault_ipa >= GICR_BASE && fault_ipa < GICR_BASE + MAX_VCPUS as u64 * 0x2_0000 {
        // GIC redistributor MMIO. Route to the correct vCPU based on
        // the offset within the redistributor region (each CPU has a
        // 0x20000-byte frame: 0x10000 RD_base + 0x10000 SGI_base).
        let offset = (fault_ipa - GICR_BASE) as u32;
        if access.is_write {
            let val = if access.rt == 31 { 0 } else {
                get_reg(vcpu, HvReg::gpr(access.rt as u32))
            };
            unsafe { hv_gic_set_redistributor_reg(vcpu, offset, val) };
        } else {
            let mut val: u64 = 0;
            unsafe { hv_gic_get_redistributor_reg(vcpu, offset, &mut val) };
            if access.rt < 31 {
                set_reg(vcpu, HvReg::gpr(access.rt as u32), val);
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
                    get_reg(vcpu, HvReg::gpr(access.rt as u32)) as u32
                };
                if dev.write(offset, val) {
                    notify_queue = Some(val);
                }
            } else {
                let val = dev.read(offset);
                if access.rt < 31 {
                    set_reg(vcpu, HvReg::gpr(access.rt as u32), val as u64);
                }
            }
        } // dev_lock released
        if let Some(queue) = notify_queue {
            let ctrl_qi = virtio::ctrl_queue_index() as u32;
            if queue & 1 == 1 {
                // Odd queue index = TX queue
                crate::userspace_net::process_tx_queue(queue);
            } else if queue == ctrl_qi {
                virtio::handle_ctrl_queue();
            }
        }
    } else {
        // Unknown device address. Return 0 on reads, ignore writes.
        if !access.is_write && access.rt < 31 {
            set_reg(vcpu, HvReg::gpr(access.rt as u32), 0);
        }
    }

    // Advance PC past the faulting instruction.
    set_reg(vcpu, HvReg::Pc, pc + 4);
    Ok(())
}

// ── Register helpers (free functions, take vcpu handle) ─────────────────────

fn get_reg(vcpu: hv_vcpu_t, reg: HvReg) -> u64 {
    let mut v: u64 = 0;
    unsafe { hv_vcpu_get_reg(vcpu, reg, &mut v) };
    v
}

fn set_reg(vcpu: hv_vcpu_t, reg: HvReg, value: u64) {
    unsafe { hv_vcpu_set_reg(vcpu, reg, value) };
}

fn get_sys_reg(vcpu: hv_vcpu_t, reg: HvSysReg) -> u64 {
    let mut v: u64 = 0;
    unsafe { hv_vcpu_get_sys_reg(vcpu, reg, &mut v) };
    v
}

impl Drop for Vm {
    fn drop(&mut self) {
        unsafe {
            for vi in &self.vcpus {
                let _ = hv_vcpu_destroy(vi.vcpu);
            }
            let _ = hv_vm_deallocate(self.ram_host as *mut c_void, self.ram_size);
            let _ = hv_vm_destroy();
        }
    }
}
