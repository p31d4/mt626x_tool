use std::io::Write;
use std::{thread, time::Duration, str, cmp};
use serialport::FlowControl;
use std::fs::File;
use std::path::Path;

use clap::{Arg, Command};

fn main() {

    let matches = Command::new("mt626x_tool - Performs memory operations on a mt626x chip")
        .about("Dumps the ROM flash memory from a mt626x device")
        .disable_version_flag(true)
        .arg(
            Arg::new("port")
                .help("Device to a serial port")
                .use_value_delimiter(false)
                .required(true),
        )
        .get_matches();

    let port_name = matches.get_one::<String>("port").unwrap();

    println!("[DEBUG] serial port: {}", port_name);

    let mut mt_port = open_serial(&port_name);

    connect(&mut *mt_port);
    read_flash(&mut *mt_port);
    reset(&mut *mt_port);
}

fn open_serial(port_name: &str) -> Box<dyn serialport::SerialPort> {

    println!("Waiting for serial port");

    let builder = serialport::new(port_name, 115_200)
        .timeout(Duration::from_millis(10))
        .flow_control(FlowControl::Hardware);

    loop {
        match builder.clone().open() {
            Ok(p) => break p,
            _ => {
                std::io::stdout().flush().expect("Error flushing stdout!");
                print!(".");
                thread::sleep(Duration::from_millis(100));
            }
        };
    }
}

fn send_cmd(serial_port: &mut dyn serialport::SerialPort, cmd: &[u8], read_size: usize) -> Vec::<u8> {

    let buf_size = cmp::max(32, cmd.len() + read_size);
    let mut serial_buf: Vec<u8> = vec![0; buf_size];

    serial_port.write(cmd).expect("Write failed!");
    thread::sleep(Duration::from_millis(30));

    match serial_port.read(serial_buf.as_mut_slice()) {
        Ok(_p) => {
            serial_buf[cmd.len() .. (cmd.len() + read_size)].to_vec()
        },
        Err(_) => panic!("Read from serial failed!"),
    }
}

fn read32(serial_port: &mut dyn serialport::SerialPort, addr: &[u8], value: &[u8], read_size: usize) -> Vec::<u8> {

    let mut cmd_buf: Vec<u8> = Vec::<u8>::new();
    cmd_buf.push(b"\xD1"[0]);
    cmd_buf.extend_from_slice(&addr); 
    cmd_buf.extend_from_slice(&value); 

    let cmd_answer: Vec::<u8> = send_cmd(&mut *serial_port, &cmd_buf, read_size);
    cmd_answer
}

fn clear_serial_input(serial_port:  &mut dyn serialport::SerialPort) {
    // workaround to clean input - FIXME
    let mut serial_buf: Vec<u8> = vec![0; 32];

    thread::sleep(Duration::from_millis(100));
    loop {
        match serial_port.read(serial_buf.as_mut_slice()) {
            Ok(_p) => continue,
            Err(_) => break,
        }
    }
}

fn connect(mt_port: &mut dyn serialport::SerialPort) {

    println!("\nSending BROM handshake ...");

    let mut serial_buf: Vec<u8> = vec![0; 32];

    loop {
        mt_port.write(b"\xA0").expect("Write failed!");

        match mt_port.read(serial_buf.as_mut_slice()) {
            Ok(_p) => {
                if 0x5F == serial_buf[0] {
                    break;
                }
            },
            Err(_) => continue,
        }
    }

    clear_serial_input(&mut *mt_port);

    mt_port.write(b"\x0A\x50\x05").expect("Write failed!");
    thread::sleep(Duration::from_millis(100));

    match mt_port.read(serial_buf.as_mut_slice()) {
        Ok(_p) => {
            assert_eq!(b"\xF5\xAF\xFA", &serial_buf[0..3]);
        },
        Err(_) => println!("Read failed!"),
    }

    //self.chip = self.read16(0x80000008)[0]
    let cmd_answer: Vec::<u8> = send_cmd(&mut *mt_port, b"\xA2\x80\x00\x00\x08\x00\x00\x00\x01", 2);
    println!("chip ID {:X?}", cmd_answer);

    //self.write16(0xa0030000, 0x2200) # disable system watchdog
    //-------------------------------------------------------------------------
    // addr
    let cmd_answer: Vec::<u8> = send_cmd(&mut *mt_port, b"\xD2\xA0\x03\x00\x00\x00\x00\x00\x01", 2);
    assert_eq!(b"\x00\x01", &cmd_answer[..]);
    // value
    let cmd_answer: Vec::<u8> = send_cmd(&mut *mt_port, b"\x22\x00", 2);
    assert_eq!(b"\x00\x01", &cmd_answer[..]);
    //-------------------------------------------------------------------------

    //self.write16(0xa0700a28, 0x8000) # enable USB download mode
    //-------------------------------------------------------------------------
    // addr
    let cmd_answer: Vec::<u8> = send_cmd(&mut *mt_port, b"\xD2\xA0\x70\x0A\x28\x00\x00\x00\x01", 2);
    assert_eq!(b"\x00\x01", &cmd_answer[..]);
    // value
    let cmd_answer: Vec::<u8> = send_cmd(&mut *mt_port, b"\x80\x00", 2);
    assert_eq!(b"\x00\x01", &cmd_answer[..]);
    //-------------------------------------------------------------------------

    //self.write16(0xa0700a24, 2) # disable battery watchdog
    //-------------------------------------------------------------------------
    // addr
    let cmd_answer: Vec::<u8> = send_cmd(&mut *mt_port, b"\xD2\xA0\x70\x0A\x24\x00\x00\x00\x01", 2);
    assert_eq!(b"\x00\x01", &cmd_answer[..]);
    // value
    let cmd_answer: Vec::<u8> = send_cmd(&mut *mt_port, b"\x00\x02", 2);
    assert_eq!(b"\x00\x01", &cmd_answer[..]);
    //-------------------------------------------------------------------------

    //chunk = self.read32(0xa0510000, 1, '<')
    let _chunk = read32(&mut *mt_port, b"\xA0\x51\x00\x00", b"\x00\x00\x00\x01", 2);
    //println!("chunk {:X?}", chunk);

    //self.write32(0xa0510000, 2) # enter memory map mode 2 to map ROM from the start of RAM
    //-------------------------------------------------------------------------
    // addr
    let cmd_answer: Vec::<u8> = send_cmd(&mut *mt_port, b"\xD4\xA0\x51\x00\x00\x00\x00\x00\x01", 2);
    assert_eq!(b"\x00\x01", &cmd_answer[..]);
    // value
    let cmd_answer: Vec::<u8> = send_cmd(&mut *mt_port, b"\x00\x00\x00\x02", 2);
    assert_eq!(b"\x00\x01", &cmd_answer[..]);
    //-------------------------------------------------------------------------
}

fn read_flash(mt_port: &mut dyn serialport::SerialPort) {

    println!("Dumping memory, do not disconnect...");

    let mut size: u32 = 4194304;
    let mut addr: u32 = 0;
    let block_size: u32 = 1024;

    let path = Path::new("rom.bin");
    let display = path.display();

    // Open a file in write-only mode, returns `io::Result<File>`
    let mut file = match File::create(&path) {
        Err(why) => panic!("couldn't create {}: {}", display, why),
        Ok(file) => file,
    };

    while size > 0 {
        let chunk = read32(&mut *mt_port, &addr.to_be_bytes(), b"\x00\x00\x01\x00", 1024 + 4);
        let chunk = &chunk[2..(chunk.len()-2)];
        let mut ordered_chunk = Vec::<u8>::new();

        // from little-endian to big-endian
        for idx in 1..257 {
            for offset in 0..4 {
                ordered_chunk.push(chunk[(idx*4)-offset-1]);
            }
        }

        // Write the chunk to rom.bin, returns `io::Result<()>`
        match file.write_all(&ordered_chunk) {
            Err(why) => panic!("couldn't write to {}: {}", display, why),
            Ok(_) => {
                std::io::stdout().flush().expect("Error flushing stdout!");
                print!(".");
            }
        }

        size -= block_size;
        addr += block_size;
    }
}

fn reset(mt_port: &mut dyn serialport::SerialPort) {
    //self.write16(0xa003001c, 0x1209)
    //-------------------------------------------------------------------------
    // addr
    let cmd_answer: Vec::<u8> = send_cmd(&mut *mt_port, b"\xD2\xA0\x03\x00\x1C\x00\x00\x00\x01", 2);
    assert_eq!(b"\x00\x01", &cmd_answer[..]);
    // value
    let cmd_answer: Vec::<u8> = send_cmd(&mut *mt_port, b"\x12\x09", 2);
    assert_eq!(b"\x00\x01", &cmd_answer[..]);
    //-------------------------------------------------------------------------
}
