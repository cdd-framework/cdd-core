use std::env;

fn main() {
    // println!("Hello, world!");
    let args: Vec<String> = env::args().collect();

    println!("--- CDD Framework: Core Engine v0.1 ---");
    println!("Architecture: {}", env::consts::OS);

    if args.len() > 1{
        println!("Cible reçue: {}", args[1]);
    } else {
        println!("Aucune cible spécifiée. Essayez: ./cdd-core <url>");
    }
}
