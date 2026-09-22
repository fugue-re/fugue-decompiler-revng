//! Decompiles the same function in several threads, each with its own
//! `Decompiler`, to check that concurrent analyses do not interfere.
use std::thread;

use revng_fugue::{Address, Architecture, Decompiler};

fn main() {
    let path = std::env::args().nth(1).expect("usage: parallel <binary>");
    let bytes = std::fs::read(&path).expect("the binary is readable");
    let is_pe = bytes.starts_with(b"MZ");
    let threads = std::env::args()
        .nth(2)
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(4);

    let outputs = thread::scope(|scope| {
        let handles = (0..threads)
            .map(|index| {
                let bytes = bytes.clone();
                let path = path.clone();
                scope.spawn(move || {
                    let decompiler = if is_pe {
                        Decompiler::open(&path)
                            .expect("the PE loads")
                            .with_max_depth(2)
                            .with_returning_function(Address::new(0x40787E))
                    } else {
                        Decompiler::from_raw(bytes, Address::new(0x4092AA), Architecture::X86)
                            .expect("the raw binary loads")
                    };
                    let session = decompiler.into_session();
                    let mut total = 0;
                    let mut text = String::new();
                    for address in [0x409EE4u64, 0x40A51E, 0x40AB58, 0x40B730] {
                        let output = session
                            .function(Address::new(address))
                            .expect("the function decompiles");
                        total += output.c().len();
                        text.push_str(output.c());
                    }
                    (index, total, text)
                })
            })
            .collect::<Vec<_>>();
        handles
            .into_iter()
            .map(|handle| handle.join().expect("the thread did not panic"))
            .collect::<Vec<_>>()
    });

    for (index, length, _) in &outputs {
        println!("thread {index}: {length} bytes of C");
    }
    let first = &outputs[0].2;
    let identical = outputs.iter().all(|(_, _, text)| text == first);
    println!("all threads agree: {identical}");
}
