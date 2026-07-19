use std::process::ExitCode;

fn main() -> ExitCode {
    match oxidra::cli::main_entry() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::from(error.exit_code())
        }
    }
}
