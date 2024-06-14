use clap::Parser;

mod wol;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// MAC address to wake.
    #[arg(short, long)]
    mac: String,
}

fn main() {
    let args = Args::parse();

    match wol::create_magic_packet(&args.mac) {
        Ok(packet) => {
            packet.broadcast().expect("unable to send packet");
            println!("packet sent to 255.255.255.255 with MAC {}", args.mac);
        }
        Err(err) => eprintln!("unable to create magic packet: {}", err),
    }
}
