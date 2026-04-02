#include <iostream>
#include "seal/seal.h"

int main()
{
    // Set encryption parameters
    seal::EncryptionParameters parms(seal::scheme_type::bfv);
    parms.set_poly_modulus_degree(4096);
    parms.set_coeff_modulus(seal::CoeffModulus::BFVDefault(4096));
    parms.set_plain_modulus(256);

    // Create SEALContext (no Create method in 4.1)
    seal::SEALContext context(parms);

    // Key generation
    seal::KeyGenerator keygen(context);
    seal::PublicKey public_key = keygen.public_key();
    seal::SecretKey secret_key = keygen.secret_key();

    // Encryptor, Decryptor, Evaluator
    seal::Encryptor encryptor(context, public_key);
    seal::Decryptor decryptor(context, secret_key);
    seal::Evaluator evaluator(context);

    // BatchEncoder
    seal::BatchEncoder batch_encoder(context);

    // Encode two numbers
    std::vector<uint64_t> input1(batch_encoder.slot_count(), 0ULL);
    std::vector<uint64_t> input2(batch_encoder.slot_count(), 0ULL);
    input1[0] = 3;
    input2[0] = 5;

    seal::Plaintext plain1, plain2;
    batch_encoder.encode(input1, plain1);
    batch_encoder.encode(input2, plain2);

    // Encrypt
    seal::Ciphertext encrypted1, encrypted2;
    encryptor.encrypt(plain1, encrypted1);
    encryptor.encrypt(plain2, encrypted2);

    // Add encrypted numbers
    seal::Ciphertext encrypted_result;
    evaluator.add(encrypted1, encrypted2, encrypted_result);

    // Decrypt result
    seal::Plaintext plain_result;
    decryptor.decrypt(encrypted_result, plain_result);

    // Decode
    std::vector<uint64_t> result;
    batch_encoder.decode(plain_result, result);

    std::cout << "Result: " << result[0] << std::endl;

    return 0;
}
