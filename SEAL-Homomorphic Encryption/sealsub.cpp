#include <iostream>
#include <seal/seal.h>

using namespace std;
using namespace seal;

int main()
{
    EncryptionParameters parms(scheme_type::bfv);
    parms.set_poly_modulus_degree(4096);
    parms.set_coeff_modulus(CoeffModulus::BFVDefault(4096));
    parms.set_plain_modulus(PlainModulus::Batching(4096, 20));

    SEALContext context(parms);

    KeyGenerator keygen(context);
    SecretKey secret_key = keygen.secret_key();
    PublicKey public_key;
    keygen.create_public_key(public_key);
    RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys);

    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);
    BatchEncoder encoder(context);

    int x, y;
    cout << "Enter first integer: ";
    cin >> x;
    cout << "Enter second integer: ";
    cin >> y;

    Plaintext plain_x, plain_y;
    encoder.encode(vector<uint64_t>{(uint64_t)x}, plain_x);
    encoder.encode(vector<uint64_t>{(uint64_t)y}, plain_y);

    Ciphertext encrypted_x, encrypted_y;
    encryptor.encrypt(plain_x, encrypted_x);
    encryptor.encrypt(plain_y, encrypted_y);

    Ciphertext encrypted_result;
    evaluator.add(encrypted_x, encrypted_y, encrypted_result);

    Plaintext plain_result;
    decryptor.decrypt(encrypted_result, plain_result);

    vector<uint64_t> result;
    encoder.decode(plain_result, result);

    cout << "Encrypted sum (decrypted): " << result[0] << endl;

    return 0;
}
