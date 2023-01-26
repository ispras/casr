pub mod analysis;
pub mod asan;
pub mod debug;
pub mod error;
pub mod execution_class;
pub mod python;
pub mod report;
pub mod stacktrace_constants;
pub mod util;

// This macro merges all [&str] slices into single Vec<String>.
#[macro_export]
macro_rules! concatall {
    ( $( $x:expr ),* ) => {
        {
            [$($x,)*].concat().iter().map(|x| x.to_string()).collect::<Vec<String>>()

        }
    };
}
