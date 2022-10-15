// Copyright (c) 2022 Octavian Oncescu
// Copyright (c) 2022 The Purplecoin Core developers
// Licensed under the Apache License, Version 2.0 see LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0 or the MIT license, see
// LICENSE-MIT or http://opensource.org/licenses/MIT

use purplecoincli::wallet::gen_encrypted_simple_wallet;
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
    GenSimpleWalletBatch { batch_size: u64 },
}


fn main() {
    let cli = Cli::parse();

    match &cli.command {
        Some(Commands::GenSimpleWallet) => {
            let mut password = rpassword::prompt_password("Your password: ").unwrap();
            let mut confirm_password = rpassword::prompt_password("Your password confirmation: ").unwrap();

            if password != confirm_password {
                println!("Password does not match password confirmation!");
                return;
            }

            let addresses = gen_encrypted_simple_wallet(&password, 1);
            password.zeroize();
            confirm_password.zeroize();
            println!("Your address is: {}", addresses[0].0);
            println!("Your encrypted key is: {}", addresses[0].1);
        }
        Some(Commands::GenSimpleWalletBatch { batch_size }) => {
            if batch_size > &100_000 {
                println!("Max batch size is 100,000!");
                return;
            }

            let mut password = rpassword::prompt_password("Your password: ").unwrap();
            let mut confirm_password = rpassword::prompt_password("Your password confirmation: ").unwrap();

            if password != confirm_password {
                println!("Password does not match password confirmation!");
                return;
            }

            let batch = gen_encrypted_simple_wallet(&password, *batch_size);
            password.zeroize();
            confirm_password.zeroize();
            for (address, encrypted_key) in batch.iter() {
                println!("{} {}", address, encrypted_key);
            }
        }
        None => {
            println!("No command given. Type \"purplecoincli help\" for a list of commands.")
        }
    }
}
