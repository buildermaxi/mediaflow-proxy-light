//! Process resource readings for the dashboard. Each returns `None` where the
//! platform isn't supported.

use std::time::Duration;

/// Resident set size of this process, in bytes.
#[cfg(any(target_os = "linux", target_os = "android"))]
pub fn resident_memory_bytes() -> Option<u64> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    let kib = status
        .lines()
        .find_map(|line| line.strip_prefix("VmRSS:"))?
        .trim()
        .strip_suffix("kB")?
        .trim()
        .parse::<u64>()
        .ok()?;
    Some(kib * 1024)
}

/// Resident set size of this process, in bytes.
#[cfg(target_vendor = "apple")]
pub fn resident_memory_bytes() -> Option<u64> {
    let mut info = std::mem::MaybeUninit::<libc::proc_taskinfo>::uninit();
    let size = std::mem::size_of::<libc::proc_taskinfo>() as libc::c_int;
    // SAFETY: `info` is a writable buffer of exactly `size` bytes, which is
    // what PROC_PIDTASKINFO fills; it is only read after a full-size write.
    let written = unsafe {
        libc::proc_pidinfo(
            std::process::id() as libc::c_int,
            libc::PROC_PIDTASKINFO,
            0,
            info.as_mut_ptr().cast(),
            size,
        )
    };
    (written == size).then(|| unsafe { info.assume_init() }.pti_resident_size)
}

#[cfg(not(any(target_os = "linux", target_os = "android", target_vendor = "apple")))]
pub fn resident_memory_bytes() -> Option<u64> {
    None
}

/// User + system CPU time consumed by this process so far.
#[cfg(unix)]
pub fn cpu_time() -> Option<Duration> {
    let mut usage = std::mem::MaybeUninit::<libc::rusage>::uninit();
    // SAFETY: getrusage fully initialises `usage` when it returns 0.
    if unsafe { libc::getrusage(libc::RUSAGE_SELF, usage.as_mut_ptr()) } != 0 {
        return None;
    }
    let usage = unsafe { usage.assume_init() };
    let to_duration =
        |t: libc::timeval| Duration::new(t.tv_sec as u64, (t.tv_usec as u32).saturating_mul(1000));
    Some(to_duration(usage.ru_utime) + to_duration(usage.ru_stime))
}

#[cfg(not(unix))]
pub fn cpu_time() -> Option<Duration> {
    None
}

/// CPU cores available to this process (respects container CPU quotas on Linux).
pub fn cpu_cores() -> usize {
    std::thread::available_parallelism().map_or(1, |n| n.get())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_process_resources_where_supported() {
        if cfg!(any(
            target_os = "linux",
            target_os = "android",
            target_vendor = "apple"
        )) {
            assert!(resident_memory_bytes().is_some_and(|b| b > 0));
        }
        if cfg!(unix) {
            assert!(cpu_time().is_some());
        }
        assert!(cpu_cores() >= 1);
    }
}
