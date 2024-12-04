static AES_SBOX: [[u8;16];16] = [ [0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76],
                                  [0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0],
                                  [0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15],
                                  [0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75],
                                  [0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84],
                                  [0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf],
                                  [0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8],
                                  [0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2],
                                  [0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73],
                                  [0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb],
                                  [0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79],
                                  [0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08],
                                  [0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a],
                                  [0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e],
                                  [0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf],
                                  [0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16] ];

static INVERSE_AES_SBOX: [[u8;16];16] = [ [0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb],
                                          [0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb],
                                          [0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e],
                                          [0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25],
                                          [0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92],
                                          [0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84],
                                          [0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06],
                                          [0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b],
                                          [0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73],
                                          [0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e],
                                          [0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b],
                                          [0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4],
                                          [0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f],
                                          [0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef],
                                          [0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61],
                                          [0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d] ];

static RCON: [u8;11] = [0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36];

fn key_schedule(key: &[u8;16]) -> [[u8;4];44]{
    let mut original_key = [[0u8;4];4];
    let mut expanded_key = [[0u8;4];44];
    for i in 0..16{
        original_key[i/4][i % 4] = key[i];
    }
    for i in 0..4{
        expanded_key[i] = original_key[i];
    }
    for i in 4..44{
        let mut tmp = expanded_key[i - 1];
        if  i % 4 == 0{
            tmp.rotate_left(1);
            for byte in &mut tmp{
                let row = (*byte >> 4) as usize;
                let col = (*byte & 0x0F) as usize;
                *byte = AES_SBOX[row][col];
            }
            tmp[0] ^= RCON[i / 4-1];
        }
        for j in 0..4{
            expanded_key[i][j] = expanded_key[i-4][j] ^ tmp[j];
        }
    }
    return expanded_key
}

fn sub_bytes(state: &mut [[u8;4];4], rev: bool){
    if !rev{
        for i in 0..4{
            for j in 0..4{
                let byte = state[i][j];
                let row = (byte >> 4) as usize;
                let col = (byte & 0x0F) as usize;
                state[i][j] = AES_SBOX[row][col];
            }
        }
    }
    else {
        for i in 0..4{
            for j in 0..4{
                let byte = state[i][j];
                let row = (byte >> 4) as usize;
                let col = (byte & 0x0F) as usize;
                state[i][j] = INVERSE_AES_SBOX[row][col];
            }
        }
    }
}

fn get_round_key(round_keys: &[[u8; 4]; 44], round: usize) -> [[u8; 4]; 4] {
    let mut round_key: [[u8; 4]; 4] = [[0; 4]; 4];
    for i in 0..4 {
        round_key[i] = round_keys[round * 4 + i];
    }
    round_key
}


fn add_round_key(state: &mut [[u8;4];4], round_key: &[[u8;4];4]){
    for i in 0..4{
        for j in 0..4{
            state[i][j] ^= round_key[i][j];
        }
    }

}

fn shift_rows(state: &mut [[u8;4];4], rev: bool){
    if !rev{
        state[1].rotate_left(1);
        state[2].rotate_left(2);
        state[3].rotate_left(3);
    }
    else{
        state[1].rotate_right(1);
        state[2].rotate_right(2);
        state[3].rotate_right(3);
    }
}

fn gal_mult(x: u8, y: u8) -> u8{
    let mut res = 0u8;
    let mut x = x;
    let mut y = y;
    for _ in 0..8{
        if y & 1 != 0{
            res  ^= x;
        }
        let high_bit = x & 0x80;
        x <<= 1;
        if high_bit != 0{
            x ^= 0x1b;
        }
        y >>= 1;
    }
    res
}

fn mix_columns(state: &mut [[u8;4];4], rev: bool){
    if !rev{
        for j in 0..4{
            let a = [
                state[0][j],
                state[1][j],
                state[2][j],
                state[3][j]
            ];
            state[0][j] = gal_mult(a[0], 2) ^ gal_mult(a[1], 3) ^ a[2] ^ a[3];
            state[1][j] = a[0] ^ gal_mult(a[1], 2) ^ gal_mult(a[2], 3) ^ a[3];
            state[2][j] = a[0] ^ a[1] ^ gal_mult(a[2], 2) ^ gal_mult(a[3], 3);
            state[3][j] = gal_mult(a[0], 3) ^ a[1] ^ a[2] ^ gal_mult(a[3], 2);
        }
    }
    else{
        for j in 0..4 {
            let a = [
                state[0][j],
                state[1][j],
                state[2][j],
                state[3][j],
            ];
            state[0][j] = gal_mult(a[0], 0x0e) ^ gal_mult(a[1], 0x0b) ^ gal_mult(a[2], 0x0d) ^ gal_mult(a[3], 0x09);
            state[1][j] = gal_mult(a[0], 0x09) ^ gal_mult(a[1], 0x0e) ^ gal_mult(a[2], 0x0b) ^ gal_mult(a[3], 0x0d);
            state[2][j] = gal_mult(a[0], 0x0d) ^ gal_mult(a[1], 0x09) ^ gal_mult(a[2], 0x0e) ^ gal_mult(a[3], 0x0b);
            state[3][j] = gal_mult(a[0], 0x0b) ^ gal_mult(a[1], 0x0d) ^ gal_mult(a[2], 0x09) ^ gal_mult(a[3], 0x0e);
        }
    }
}

fn encrypt_block_aes128(state: &mut [[u8;4];4], key: &[u8;16]){
    let round_keys = key_schedule(key);
    let mut current_round_key = get_round_key(&round_keys, 0);
    add_round_key(state, &current_round_key);
    for round in 1..10{
        sub_bytes(state, false);
        shift_rows(state, false);
        mix_columns(state, false);
        current_round_key = get_round_key(&round_keys, round);
        add_round_key(state, &current_round_key);
    }
    sub_bytes(state, false);
    shift_rows(state, false);
    current_round_key = get_round_key(&round_keys, 10);
    add_round_key(state, &current_round_key);

    
}

fn decrypt_block_aes128(state: &mut [[u8;4];4], key: &[u8;16]){
    let round_keys = key_schedule(key);
    let mut current_round_key = get_round_key(&round_keys, 10);
    add_round_key(state, &current_round_key);
    for round in (1..10).rev() {
        shift_rows(state, true);
        sub_bytes(state, true);
        current_round_key = get_round_key(&round_keys, round);
        add_round_key(state, &current_round_key);
        mix_columns(state, true);
    }
    shift_rows(state, true);
    sub_bytes(state, true);
    current_round_key = get_round_key(&round_keys, 0); 
    add_round_key(state, &current_round_key);
}

fn state_to_bytes(state: &[[u8; 4]; 4]) -> Vec<u8> {
    let mut output = Vec::new();
    for i in 0..4 {
        for j in 0..4 {
            output.push(state[j][i]);
        }
    }
    output
}

fn string_to_state(input: &str) -> [[u8; 4]; 4] {
    let bytes = input.as_bytes();
    let mut state: [[u8; 4]; 4] = [[0; 4]; 4];

    for i in 0..4 {
        for j in 0..4 {
            let index = i * 4 + j;
            state[j][i] = if index < bytes.len() {
                bytes[index]
            } else {
                0 // Заполняем нулями, если строка короче 16 байт
            };
        }
    }

    state
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{:02x}", byte)).collect()
}

fn hex_to_bytes(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect()
}

pub fn encrypt_aes128(input: &str, key_s: &str) -> String {
    let mut key = key_s.to_string();
    
    // Дополняем ключ до 16 символов
    while key.len() < 16 {
        key.push('1'); 
    }

    if key.len() != 16 {
        panic!("Ключ должен быть длиной 16 символов (128 бит).");
    }

    let key_bytes: [u8; 16] = key.as_bytes().try_into().expect("Ключ должен быть длиной 16 байт.");
    
    // Преобразуем входные данные в байты и дополняем
    let input_bytes = input.as_bytes();
    let padded_input = pkcs7_pad(input_bytes, 16);

    // Разбиваем на блоки
    let mut encrypted_data = Vec::new();
    
    for chunk in padded_input.chunks(16) {
        let mut state = string_to_state(std::str::from_utf8(chunk).unwrap());
        encrypt_block_aes128(&mut state, &key_bytes);
        let encrypted_bytes = state_to_bytes(&state);
        encrypted_data.extend(encrypted_bytes);
    }

    // Кодируем зашифрованные байты в строку в формате hex
    bytes_to_hex(&encrypted_data)
}


// Пример реализации функции дополнения
fn pkcs7_pad(data: &[u8], block_size: usize) -> Vec<u8> {
    let padding_length = block_size - (data.len() % block_size);
    let mut padded = data.to_vec();
    padded.extend(vec![padding_length as u8; padding_length]);
    padded
}

fn remove_pkcs7_padding(data: &[u8]) -> Vec<u8> {
    if data.is_empty() {
        return data.to_vec();
    }

    let padding_length = data[data.len() - 1] as usize;

    // Проверяем, что длина дополнения корректна
    if padding_length > 0 && padding_length <= 16 {
        let valid_padding = &data[data.len() - padding_length..];
        if valid_padding.iter().all(|&byte| byte == padding_length as u8) {
            return data[..data.len() - padding_length].to_vec();
        }
    }

    data.to_vec() // Если дополнение некорректно, возвращаем оригинальные данные
}

pub fn decrypt_aes128(input: &str, key_s: &str) -> String {
    let mut key = key_s.to_string();
    
    // Дополняем ключ до 16 символов
    while key.len() < 16 {
        key.push('1');
    }

    // Декодируем строку hex в байты
    let encrypted_bytes = hex_to_bytes(input);
    let key_bytes: [u8; 16] = key.as_bytes().try_into().expect("Ключ должен быть длиной 16 байт.");

    let mut decrypted_data = Vec::new();

    // Обрабатываем входные данные по блокам по 16 байт
    for chunk in encrypted_bytes.chunks(16) {
        let mut state: [[u8; 4]; 4] = [[0; 4]; 4];

        for i in 0..4 {
            for j in 0..4 {
                let index = i * 4 + j;
                state[j][i] = chunk[index];
            }
        }

        let mut state_copy = state; // Создаем изменяемую копию состояния
        decrypt_block_aes128(&mut state_copy, &key_bytes);

        // Добавляем расшифрованные байты в результирующий вектор
        decrypted_data.extend(state_to_bytes(&state_copy));
    }

    // Удаляем дополнение PKCS#7
    decrypted_data = remove_pkcs7_padding(&decrypted_data);

    // Преобразуем расшифрованные байты обратно в строку
    String::from_utf8_lossy(&decrypted_data).to_string()
}