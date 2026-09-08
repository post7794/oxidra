use std::process::ExitCode;

fn main() -> ExitCode {
    let mut arguments = std::env::args_os();
    let _program = arguments.next();
    if arguments.next().as_deref()
        == Some(std::ffi::OsStr::new("__internal-mcp-execution-guardian-v1"))
    {
        return match oxidra::execution_guardian::guardian_main_entry(arguments) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("{error}");
                ExitCode::from(error.exit_code())
            }
        };
    }
    match oxidra::cli::main_entry() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::from(error.exit_code())
        }
    }
}
