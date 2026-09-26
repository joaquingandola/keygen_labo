//! Keygen por consola.
//! El algoritmo es público; lo que protege el esquema es el secreto.

use std::process::ExitCode;

use data_encoding::{Encoding, Specification};
use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

const LARGO_TAG: usize = 10;

const GRUPO: usize = 4;

const ALFABETO: &str = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

fn main() -> ExitCode {
    dotenvy::dotenv().ok();

    let args: Vec<String> = std::env::args().collect();

    match args.get(1).map(String::as_str) {
        Some("gen") if args.len() == 3 => {
            println!("{}", generar(&args[2]));
            ExitCode::SUCCESS
        }
        Some("check") if args.len() == 4 => {
            if validar(&args[2], &args[3]) {
                println!("VALIDA");
                ExitCode::SUCCESS
            } else {
                println!("INVALIDA");
                ExitCode::FAILURE
            }
        }
        _ => {
            eprintln!("uso:");
            eprintln!("  keygen gen   <id>          genera la clave para un ID");
            eprintln!("  keygen check <id> <clave>  verifica una clave");
            ExitCode::from(2)
        }
    }
}

fn generar(id: &str) -> String {
    let tag = mac(id).finalize().into_bytes();
    agrupar(&base32().encode(&tag[..LARGO_TAG]))
}

fn validar(id: &str, clave: &str) -> bool {
    let limpia = limpiar(clave);

    let bytes = match base32().decode(limpia.as_bytes()) {
        Ok(b) => b,
        // Caracteres inválidos o largo incorrecto: no es una clave.
        Err(_) => return false,
    };

    mac(id).verify_truncated_left(&bytes).is_ok()
}

fn mac(id: &str) -> HmacSha256 {
    let secreto = std::env::var("SECRETO")
        .expect("falta SECRETO: definilo en .env o como variable de entorno");
    let mut mac =
        HmacSha256::new_from_slice(secreto.as_bytes()).expect("HMAC acepta cualquier largo de clave");
    mac.update(id.trim().to_lowercase().as_bytes());
    mac
}

fn base32() -> Encoding {
    let mut spec = Specification::new();
    spec.symbols.push_str(ALFABETO);
    spec.translate.from.push_str("abcdefghjkmnpqrstvwxyzILOilo");
    spec.translate.to.push_str("ABCDEFGHJKMNPQRSTVWXYZ110110");
    spec.encoding().expect("el alfabeto es válido")
}

fn agrupar(clave: &str) -> String {
    clave
        .chars()
        .collect::<Vec<char>>()
        .chunks(GRUPO)
        .map(|c| c.iter().collect::<String>())
        .collect::<Vec<String>>()
        .join("-")
}

fn limpiar(clave: &str) -> String {
    clave
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .collect()
}