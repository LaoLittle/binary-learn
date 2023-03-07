use cfg_aliases::cfg_aliases;

fn main() {
    cfg_aliases! {
        apple: { any(target_os = "ios", target_os = "macos") }
    }
}
