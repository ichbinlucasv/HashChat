//! Self-hosted store-and-forward relay.
//!
//! One process, loopback only, published as a Tor v3 onion when Tor's
//! ControlPort accepts SAFECOOKIE on 127.0.0.1:9051. See `docs/RELAY.md`.

use std::io::{self, Write};
use std::process::ExitCode;

use hashchat_rust::relay::{
    next_operator_line, parse_cli, parse_operator_line, CliRequest, LineRead, OperatorCommand,
    RelayCli, RelayServer, RELAY_HELP,
};
use hashchat_rust::{
    publish_onion_on_loopback, read_onion_key_file, write_onion_key_file, OnionPublication,
};
use zeroize::Zeroize;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let cli = match parse_cli(&args) {
        Ok(CliRequest::Help) => {
            print!("{RELAY_HELP}");
            return ExitCode::SUCCESS;
        }
        Ok(CliRequest::Run(cli)) => cli,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(1);
        }
    };

    let mut server = match RelayServer::start(cli.dir.clone(), cli.ttl_secs) {
        Ok(server) => server,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(1);
        }
    };

    let publication = if cli.loopback_only {
        println!("relay ready");
        println!("loopback {}", server.public_addr());
        None
    } else {
        match publish(&cli, server.public_addr().port()) {
            Ok(published) => {
                println!("relay ready");
                println!("onion {}", published.onion());
                Some(published)
            }
            Err(e) => {
                eprintln!("{e}");
                server.shutdown();
                return ExitCode::from(1);
            }
        }
    };

    let code = read_commands(&server);
    drop(publication);
    server.shutdown();
    code
}

fn publish(cli: &RelayCli, port: u16) -> Result<OnionPublication, String> {
    let mut existing = match &cli.dir {
        Some(dir) => read_onion_key_file(dir)?,
        None => None,
    };
    let published = match publish_onion_on_loopback("127.0.0.1", 9051, port, existing.as_deref()) {
        Ok(published) => published,
        Err(e) => {
            if let Some(key) = existing.as_mut() {
                key.zeroize();
            }
            return Err(e);
        }
    };
    if let Some(dir) = &cli.dir {
        let key = published.returned_private_key();
        if !key.is_empty() {
            if let Err(e) = write_onion_key_file(dir, key) {
                if let Some(key) = existing.as_mut() {
                    key.zeroize();
                }
                drop(published);
                return Err(e);
            }
        }
    }
    if let Some(key) = existing.as_mut() {
        key.zeroize();
    }
    Ok(published)
}

fn read_commands(server: &RelayServer) -> ExitCode {
    let stdin = io::stdin();
    let mut reader = stdin.lock();
    loop {
        match next_operator_line(&mut reader) {
            LineRead::Eof => return ExitCode::SUCCESS,
            LineRead::Stopped => {
                eprintln!("line refused");
                return ExitCode::from(1);
            }
            LineRead::Refused => eprintln!("line refused"),
            LineRead::Line(line) => {
                if line.trim().is_empty() {
                    continue;
                }
                match parse_operator_line(&line) {
                    Err(e) => eprintln!("{e}"),
                    Ok(cmd) => {
                        if !dispatch(server, cmd) {
                            return ExitCode::SUCCESS;
                        }
                    }
                }
            }
        }
    }
}

/// `false` means the operator asked to quit.
fn dispatch(server: &RelayServer, cmd: OperatorCommand) -> bool {
    match cmd {
        OperatorCommand::Quit => false,
        OperatorCommand::Help => {
            print!("{RELAY_HELP}");
            let _ = io::stdout().flush();
            true
        }
        OperatorCommand::Create => {
            match server.create_mailbox() {
                Ok(secrets) => {
                    let revealed = secrets.reveal();
                    println!("{revealed}");
                }
                Err(e) => eprintln!("{e}"),
            }
            true
        }
        OperatorCommand::Delete(mut id) => {
            match server.delete_mailbox(&id) {
                Ok(()) => println!("deleted"),
                Err(e) => eprintln!("{e}"),
            }
            id.zeroize();
            true
        }
        OperatorCommand::Status => {
            match server.status() {
                Ok(status) => {
                    println!("mailboxes={} frames={}", status.mailboxes, status.frames);
                }
                Err(e) => eprintln!("{e}"),
            }
            true
        }
        OperatorCommand::Wipe => {
            match server.wipe() {
                Ok(()) => println!("wiped"),
                Err(e) => eprintln!("{e}"),
            }
            true
        }
    }
}
