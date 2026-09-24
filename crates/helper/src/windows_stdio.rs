use std::io;

use winapi::um::handleapi::{INVALID_HANDLE_VALUE, SetHandleInformation};
use winapi::um::processenv::GetStdHandle;
use winapi::um::winbase::{
    HANDLE_FLAG_INHERIT, STD_ERROR_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE,
};

/// Preserve helper I/O, but keep its original pipe handles out of the engine
/// and watchdog. Otherwise callers waiting for EOF can hang after we exit.
#[allow(unsafe_code)]
pub fn prevent_inheritance() -> io::Result<()> {
    for stream in [STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, STD_ERROR_HANDLE] {
        // SAFETY: GetStdHandle borrows the current process's standard handle.
        // We never close it or dereference it, and only change the INHERIT bit.
        // This runs at process startup, before creating any threads/children.
        unsafe {
            let handle = GetStdHandle(stream);
            if handle.is_null() || handle == INVALID_HANDLE_VALUE {
                continue;
            }
            if SetHandleInformation(handle, HANDLE_FLAG_INHERIT, 0) == 0 {
                return Err(io::Error::last_os_error());
            }
        }
    }
    Ok(())
}
