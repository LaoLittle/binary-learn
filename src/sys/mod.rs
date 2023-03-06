use cfg_if::cfg_if;

cfg_if! {
    if #[cfg(windows)] {
        mod windows;
        pub use windows::*;
    } else if #[cfg(unix)] {

    } else {

    }
}
