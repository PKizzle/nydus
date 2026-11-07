//! The fanotify event-buffer walk: metadata records and their info records (including
//! `FAN_EVENT_INFO_TYPE_RANGE`), as read from the group fd. Linux only.
#![no_main]

use libfuzzer_sys::fuzz_target;

#[cfg(target_os = "linux")]
fuzz_target!(|data: &[u8]| {
    nydus_service::fanotify::fuzz_event_buffer(data);
});

#[cfg(not(target_os = "linux"))]
fuzz_target!(|_data: &[u8]| {});
