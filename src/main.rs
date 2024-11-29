mod aes;
use std::fs::{File,remove_file};
use std::io::{self, Read, Write};
use clap::{Arg, Command, ArgAction};
use rpassword;

fn encrypt_file(input_file: &str, output_file: &str, key: &str) -> io::Result<()> {
    // Открываем входной файл и считываем его содержимое
    let mut file = File::open(input_file)?;
    let mut buffer = String::new();
    file.read_to_string(&mut buffer)?;

    // Шифруем содержимое файла
    let encrypted = aes::encrypt_aes128(&buffer, key);

    // Записываем зашифрованные данные в выходной файл
    let mut output = File::create(output_file)?;
    output.write_all(encrypted.as_bytes())?;

    Ok(())
}

fn decrypt_file(input_file: &str, output_file: &str, key: &str) -> io::Result<()> {
    // Открываем входной файл и считываем его содержимое
    let mut file = File::open(input_file)?;
    let mut buffer = String::new();
    file.read_to_string(&mut buffer)?;

    // Дешифруем содержимое файла
    let decrypted = aes::decrypt_aes128(&buffer, key);

    // Записываем расшифрованные данные в выходной файл
    let mut output = File::create(output_file)?;
    output.write_all(decrypted.as_bytes())?;

    Ok(())
}




fn main() -> io::Result<()> {
    let matches = Command::new("AES File Encryptor")
        .version("1.0")
        .arg_required_else_help(true)
        .author("gluk0zka@systemli.org")
        .about("Шифрует и дешифрует файлы с использованием AES-128")
        .arg(Arg::new("encfile")
            .short('e')
            .long("encfile")
            .value_name("FILE")
            .help("Шифрует указанный файл")
            .required(false))
        .arg(Arg::new("decfile")
            .short('d')
            .long("decfile")
            .value_name("FILE")
            .help("Дешифрует указанный файл")
            .required(false))
        .arg(Arg::new("paranoid-mode")
            .short('p')
            .long("paranoid-mode")
            .help("Удаляет исходный файл после шифрования или дешифрования, режим \"паранои\" ")
            .default_value(None)
            .action(ArgAction::SetTrue)
            .required(false))
        .get_matches();

    let key = rpassword::prompt_password_stderr("Введите пароль: ").unwrap();

    if let Some(input_file) = matches.get_one::<String>("encfile") {
        let output_file = format!("{}.enc", input_file.replace(".dec", ""));
        encrypt_file(input_file, &output_file, &key)?;
        println!("Файл зашифрован: {}", output_file);

        // Удаляем исходный файл, если указан флаг -p
        if matches.contains_id("paranoid-mode") {
            remove_file(input_file)?;
            println!("Исходный файл удален: {}", input_file);
        }
    } else if let Some(input_file) = matches.get_one::<String>("decfile") {
        let output_file = format!("{}.dec", input_file.replace(".enc", ""));
        decrypt_file(input_file, &output_file, &key)?;
        println!("Файл расшифрован: {}", output_file);

        // Удаляем исходный файл, если указан флаг -p
        if matches.contains_id("paranoid-mode") {
            remove_file(input_file)?;
            println!("Исходный файл удален: {}", input_file);
        }
    }
    Ok(())
}
