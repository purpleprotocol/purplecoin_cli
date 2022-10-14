use crate::wallet::gen_encrypted_simple_wallet;
use clap::{Parser, Subcommand};
use zeroize::Zeroize;

#[derive(Parser)]
#[clap(author, version, about, long_about = None)]
#[clap(propagate_version = true)]
struct Cli {
    #[clap(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate a simple encrypted wallet and print it to the screen
    GenSimpleWallet,
}


fn main() {
    let cli = Cli::parse();

    // You can check for the existence of subcommands, and if found use their
    // matches just as you would the top level cmd
    match &cli.command {
        Some(Commands::GenSimpleWallet) => {
            let mut password = rpassword::prompt_password("Your password: ").unwrap();
            let mut confirm_password = rpassword::prompt_password("Your password confirmation: ").unwrap();

            if password != confirm_password {
                println!("Password does not match password confirmation!");
                return;
            }

            let (address, encrypted_key) = gen_encrypted_simple_wallet(&password);
            password.zeroize();
            confirm_password.zeroize();
            println!("Your address is: {}", address);
            println!("Your encrypted key is: {}", encrypted_key);
        }
        None => {
            println!("No command given. Type \"purplecoincli help\" for a list of commands.")
        }
    }
}

mod primitives;
mod wallet;