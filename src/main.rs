extern crate ssh2;
extern crate ansi_term;
extern crate clap;

use std::path::{Path, PathBuf};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::net::{TcpStream};
use ansi_term::{Colour, Style};
use clap::{Arg, App};
use ssh2::Session;

struct AppArgs {
    host: String,
    port: String,
    username: String,
    password: String,
    key_file: String,
    entry_name: String,
}

fn get_args() -> AppArgs {
    let mut default_key_file = PathBuf::new();
    default_key_file.push(std::env::home_dir().unwrap());
    default_key_file.push(".ssh/id_rsa.pub");
    let matches = App::new("autossh")
        .version("0.1")
        .author("Daniel Hauser")
        .about("foo")
        .arg(Arg::with_name("host").long("host").short("h").required(true).takes_value(true))
        .arg(Arg::with_name("port").long("port").short("P").required(false).takes_value(true))
        .arg(Arg::with_name("username").long("user").short("u").required(true).takes_value(true))
        .arg(Arg::with_name("password").long("pass").short("p").required(true).takes_value(true))
        .arg(Arg::with_name("public key file").long("key").short("k").required(false).takes_value(true))
        .arg(Arg::with_name("config host name").long("name").short("n").required(true).takes_value(true))
        .get_matches();
    AppArgs {
        host: matches.value_of("host").unwrap().to_owned(),
        port: matches.value_of("port").unwrap_or("22").to_owned(),
        username: matches.value_of("username").unwrap().to_owned(),
        password: matches.value_of("password").unwrap().to_owned(),
        key_file: matches.value_of("public key file").unwrap_or(default_key_file.to_str().unwrap_or("")).to_owned(),
        entry_name: matches.value_of("config host name").unwrap().to_owned(),
    }
}

fn file_content<P: AsRef<Path>>(path: P) -> std::io::Result<String> {
    match File::open(path) {
        Ok(mut f) => {
            let mut content = String::new();
            let _ = f.read_to_string(&mut content);
            Ok(content)
        },
        Err(e) => Err(e)
    }
}

fn main() {
    let AppArgs { host, port, username, password, key_file, entry_name } = get_args();

    let key = match file_content(&key_file) {
        Ok(k) => k,
        Err(reason) => {
            println!("{} Public key file `{}` does not exist!", Colour::Red.paint("Error!"), key_file);
            println!("Reason: {}", reason);
            return;
        }
    };

    let addr = format!("{}:{}", host, port);
    let addr: &str = &addr;
    let stream = TcpStream::connect(addr).unwrap();
    let mut sess = Session::new().unwrap();
    sess.handshake(&stream).unwrap();
    sess.userauth_password(&username, &password).unwrap();
    if !sess.authenticated() {
        println!("Not authenticated");
        return;
    }

    println!("{} connected to {} on port {}", Colour::Green.paint("Successfully"), host, port);

    let mut channel = sess.channel_session().unwrap();
    if let Err(_) = channel.exec("mkdir -p ~/.ssh/") {
        println!("{} Failed to create the directory {}, aborting.", Colour::Red.paint("Error!"), Style::new().bold().paint("~/.ssh"));
        return;
    }

    let mut channel = sess.channel_session().unwrap();
    match channel.exec(&format!("echo \"{}\" >> ~/.ssh/authorized_keys", key)) {
        Ok(_) => println!("{} written your key to {} \u{1F44D}", Colour::Green.paint("Successfully"), Style::new().bold().paint("authorized_keys")),
        Err(reason) => {
            println!("{} Writing to {} failed!", Colour::Red.paint("Error!"), Style::new().bold().paint("authorized_keys"));
            println!("Reason: {:?}", reason);
            return;
        }
    }

    let mut ssh_config = PathBuf::new();
    ssh_config.push(std::env::home_dir().unwrap());
    ssh_config.push(".ssh/config");
    if let Ok(mut ssh_config) = OpenOptions::new().append(true).open(ssh_config) {
        let entry = format!("\nHost {}\n  HostName {}\n  Port {}\n  User {}\n", entry_name, host, port, username);
        ssh_config.write_all(entry.as_bytes()).unwrap();
        println!("{} added the entry to your {}\n\u{1F389}  {} \u{1F389}", Colour::Green.paint("Successfully"), Style::new().bold().paint("~/.ssh/config"), Colour::Green.paint("All done"));
    }
    else {
        println!("{} Couldn't open your ~/.ssh/config !", Colour::Red.paint("Error!"));
    }
}
