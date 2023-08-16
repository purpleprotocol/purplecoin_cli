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
            println!("Choose a password to encrypt your private key with...");
            let mut password = rpassword::prompt_password("Your password: ").unwrap();
            let mut confirm_password = rpassword::prompt_password("Your password confirmation: ").unwrap();

            if password != confirm_password {
                println!("Password does not match password confirmation!");
                return;
            }

            let addresses = gen_encrypted_simple_wallet(&password, 1);
            password.zeroize();
            confirm_password.zeroize();
            println!("Address: {}", addresses[0].0);
            println!("Keypair is: {}\n", addresses[0].1);
            println!("These are safe to store on a computer connected to the internet, assuming no malware was present during generation.");
            println!("In order to safely reuse the address, make sure to spend any coins from an airgapped machine.\n");
            println!("Warning: Forgetting the chosen password or losing the keypair will result in losing your coins. Make sure to keep them safe.");
        }
        Some(Commands::GenSimpleWalletBatch { batch_size }) => {
            println!("Choose a password to encrypt your private key with...");
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
                println!("\nAddress: {}\nKeypair: {}", address, encrypted_key);
            }
            println!("\nThese are safe to store on a computer connected to the internet, assuming no malware was present during generation.");
            println!("In order to safely reuse the address, make sure to spend any coins from an airgapped machine.\n");
            println!("Warning: Forgetting the chosen password or losing the keypair will result in losing your coins. Make sure to keep them safe.");
        }
        None => {
            println!("No command given. Type \"purplecoincli help\" for a list of commands.")
        }
    }
}
