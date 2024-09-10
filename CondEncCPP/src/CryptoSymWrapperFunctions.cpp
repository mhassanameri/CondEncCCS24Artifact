//
// Created by mameriek on 9/7/21.
//

#include "CryptoSymWrapperFunctions.h"

#include <random>

// #include <bits/struct_stat.h>


string CryptoSymWrapperFunctions::Wrapper_pad(const string& msg, size_t len) {
    string s;
    s = msg;
    s.resize(len, '\1');
    return s;
}
string CryptoSymWrapperFunctions::Wrapper_unpad(const string& msg) {
    string s;
    size_t n;
    for(n = 0; n < msg.size(); n++){
        if(msg[n] == '\1')
            break;
    }
    s = msg;
    s.resize(n);
    return s;
}


string CryptoSymWrapperFunctions::Wrapper_pad_PKCS(const string& msg, size_t len) {
    string s;
    s = msg;
    size_t num_padded_elment;
    size_t msg_size = msg.size();
    num_padded_elment = len - msg_size;
    s.resize(len, msg_size);
    return s;
}
string CryptoSymWrapperFunctions::Wrapper_unpad_PKCS(const string& msg) {




    string s;
    size_t  msg_size = msg.size();
    size_t x  = msg[msg_size - 1];
    int count = 0;
    size_t n;
    for(n = 0; n < msg.size(); n++){
        if(msg[n] == x && count  == x)
        {
//            count++;
            break;
        }
        count++;
    }


    if(count != x)
    {
        return "\0";
    }
    else
    {
        s = msg;
        s.resize(x);
        return s;
    }
}


// void CryptoSymWrapperFunctions::Wrapper_b64encode(const byte* raw_bytes, ulong len, string& str) {
//     StringSource ss( raw_bytes, len, true, new Base64URLEncoder(new StringSink(str), true));
//     // StringSource ss( raw_bytes, len, true, new HexEncoder(new StringSink(str)));
// }
// void CryptoSymWrapperFunctions::Wrapper_b64decode(const string& str, string& byte_str){
//     StringSource ss(str, true, new Base64URLDecoder(new StringSink(byte_str)));
// }
// string CryptoSymWrapperFunctions::Wrapper_b64encode(SecByteBlock& raw_bytes) {
//     string s;
//     Wrapper_b64encode(raw_bytes.data(), raw_bytes.size(), s);
//     return s;
// }
// string CryptoSymWrapperFunctions::Wrapper_b64encode(const string& in) { string out; Wrapper_b64encode((const byte*)in.data(), in.size(), out); return out; }
// string CryptoSymWrapperFunctions::Wrapper_b64decode(const string& in) { string out; Wrapper_b64decode(in, out); return out; }



/*
 * Simply computes sha256 hash of a vector of msgs.
 */
void CryptoSymWrapperFunctions::Wrapper_hash256(const vector<string>& msgvec, SecByteBlock& digest ) {
    SHA256 hash;
    digest.resize((unsigned long) SHA256::DIGESTSIZE);
    for (auto it=msgvec.begin(); it != msgvec.end(); it++) {
        hash.Update((const CryptoPP::byte*)it->data(), it->size());
        string _it_size = std::to_string(it->size());
        hash.Update((const CryptoPP::byte*)(_it_size.c_str()), _it_size.size());
    }
    hash.Final(digest);

    const long n = 256;

}

 string CryptoSymWrapperFunctions::Wrapper_hmac256(const SecByteBlock& key, const string& msg) {
    HMAC< SHA256 > hmac(key, key.size());
    string res;
    StringSource ss(msg, true, new HashFilter(hmac, new StringSink(res)));
    return res;
}

void CryptoSymWrapperFunctions::Wrapper_slow_hash(const string &msg, const SecByteBlock& salt, SecByteBlock &hash) {

    uint8_t hash1[HASHOUT_BYTES_SIZE];

    uint8_t salt_Argon[SALTSIZE_BYTES_HASH];
    memcpy(salt_Argon, salt, SALTSIZE_BYTES_HASH );
    const char* MSG;
    MSG = &msg[0];
    uint8_t *m = (uint8_t *)strdup(MSG);
    uint32_t msglen = strlen((char *)m);

//    argon2i_hash_raw(t_cost, m_cost, parallelism, pwd, pwdlen, salt_Argon2, SALTLEN, hash1, HASHLEN);
    argon2id_hash_raw(T_COST, M_COST, PARALLELISM, m, msglen, salt_Argon, SALTSIZE_BYTES_HASH, hash1, HASHOUT_BYTES_SIZE);

    hash.CleanNew(HASHOUT_BYTES_SIZE);
    memcpy(hash, hash1, HASHOUT_BYTES_SIZE);

    free(m);
}

//void CryptoSymWrapperFunctions::Wrapper_slow_hash(const string &msg, const SecByteBlock& salt, SecByteBlock &hash) {
//    PKCS5_PBKDF2_HMAC<SHA512> pbkdf;
//
//    const byte unused = 0;
//    hash.CleanNew(KEYSIZE_BYTES);
//
//    pbkdf.DeriveKey(hash, hash.size(), unused,
//                    (const byte*)msg.data(), msg.size(),
//                    salt, salt.size(),
//                    1); //TODO: I may need to replace this with memory hard fucntion like Argon2 to comapre the performance
//
//}

/**
 * Generate key from the given pw and salt.
 * If the salt is not provided then it will generate a salt.
 * We just notified that the scypt impelementation is not  fast and decided
 *
 */
 bool CryptoSymWrapperFunctions::Wrapper_harden_pw(const string pw, SecByteBlock& salt, SecByteBlock& key) {
    if (salt.empty()) {
        salt.resize(SALTSIZE_BYTES_HASH);
        PRNG.GenerateBlock(salt, SALTSIZE_BYTES_HASH);
    }
    if (key.empty()) {
        CryptoSymWrapperFunctions::Wrapper_slow_hash(pw, salt, key);
        return false;
    } else {
        SecByteBlock n_key;
        CryptoSymWrapperFunctions::Wrapper_slow_hash(pw, salt, n_key);
        return (n_key == key);
    }
}


bool CryptoSymWrapperFunctions::Wrapper_AuthEncrypt(const string &k, const string &msg, string& ctx) {
    bool ret = false;
    try {
        if (!ctx.empty()) ctx.clear();
        SecByteBlock salt;
        if (salt.empty()) {
            salt.resize(KEYSIZE_BYTES);
            PRNG.GenerateBlock(salt, KEYSIZE_BYTES);
        }

        const SecByteBlock key(reinterpret_cast<const CryptoPP::byte*>(k.data()), k.size());

//        CryptoSymWrapperFunctions::Wrapper_harden_pw(k, salt, key);
        string base_ctx;


         ret = CryptoSymWrapperFunctions::Wrapper_encrypt(key, msg, "", base_ctx);

        size_t AECtxSize = 2 * KEYSIZE_BYTES + msg.size();
        // base_ctx.resize(AECtxSize * sizeof(char));

        // TODO:  <hash_algo>.<iteration_cnt>.<salt>.<ctx>
        CryptoPP::StringSink ss(ctx);
        // ss.Put((const byte*)"SHA256", 6, true);
        size_t base_ctx_size= base_ctx.size();
        // ss.Put(salt, salt.size(), true);

        cout << "AuthEncPre\n";
        ss.Put((const CryptoPP::byte*)base_ctx.data(),  base_ctx.size(), true);
        // ss.Put(reinterpret_cast<const CondEnc_byte*>(base_ctx.data()),  base_ctx.size(), true);
        // cout << "AuthEncSuccess\n";
        // cout << "AuthEncPost\n";

        // string recover;
        // ret = CryptoSymWrapperFunctions::Wrapper_decrypt(key, ctx, "",recover);
    } catch (CryptoPP::Exception& ex) {
         cerr << ex.what() << "Wrapper Auth Encryption error"<< endl;
        ret = false;
    }
    return ret;
}


bool CryptoSymWrapperFunctions::Wrapper_AuthDecrypt(const string &k, const string &ctx, string &msg) {
    bool ret = false;
    // SecByteBlock salt;
    const SecByteBlock key(reinterpret_cast<const CryptoPP::byte*>(k.data()), k.size());
    // SecByteBlock key(reinterpret_cast<const CondEnc_byte*>(k.data()), k.size());


    try {
        msg.clear();
        // SecByteBlock salt((CondEnc_byte*)ctx.substr(0, KEYSIZE_BYTES).data(), KEYSIZE_BYTES);

        // string base_ctx = ctx.substr(KEYSIZE_BYTES);
        // string base_ctx = ctx.substr(0,KEYSIZE_BYTES);

//        CryptoSymWrapperFunctions::Wrapper_harden_pw(k, salt, key);
        // CryptoSymWrapperFunctions::Wrapper_decrypt(key, base_ctx, "", msg);
        ret = CryptoSymWrapperFunctions::Wrapper_decrypt(key, ctx, "", msg);

        // ret = true;
    } catch (CryptoPP::Exception& ex) {
//         cerr << ex.what() << endl;
        ret = false;
    }
    // TODO:  <hash_algo>.<iteration_cnt>.<salt>.<ctx>
    return ret;
}


 bool CryptoSymWrapperFunctions::Wrapper_AuthEncrypt_Hardened(const string &k, const string &msg, string& ctx) {
    bool ret = false;
    try {
        ctx.clear();
        SecByteBlock salt, key;
        CryptoSymWrapperFunctions::Wrapper_harden_pw(k, salt, key); //Extracts the secret key "key" from the input value k.
        string base_ctx;
        ret = CryptoSymWrapperFunctions::Wrapper_encrypt(key, msg, "", base_ctx);
        // TODO:  <hash_algo>.<iteration_cnt>.<salt>.<ctx>
        CryptoPP::StringSink ss(ctx);
        // ss.Put((const byte*)"SHA256", 6, true);
        ss.Put(salt, salt.size(), true);
        ss.Put(reinterpret_cast<const CryptoPP::byte*>(base_ctx.data()), base_ctx.size(), true);
    } catch (CryptoPP::Exception& ex) {
//         cerr << ex.what() << endl;
        ret = false;
    }
    return ret;
}

 bool CryptoSymWrapperFunctions::Wrapper_AuthDecrypt_Hardened(const string &k, const string &ctx, string &msg) {
    bool ret = false;
    SecByteBlock key;
    try {
        msg.clear();
        SecByteBlock salt(reinterpret_cast<CryptoPP::byte*>(ctx.substr(0, KEYSIZE_BYTES).data()), KEYSIZE_BYTES);
        string base_ctx = ctx.substr(KEYSIZE_BYTES);
        CryptoSymWrapperFunctions::Wrapper_harden_pw(k, salt, key);
        CryptoSymWrapperFunctions::Wrapper_decrypt(key, base_ctx, "", msg);
        ret = true;
    } catch (CryptoPP::Exception& ex) {
//         cerr << ex.what() << endl;
         ret = false;
    }
    // TODO:  <hash_algo>.<iteration_cnt>.<salt>.<ctx>
    return ret;
}

//bool CryptoSymWrapperFunctions::Wrapper_pwdecrypt_V2(const string &pw, const string &ctx, string &msg) {
//    bool ret = false;
//    SecByteBlock key;
//    try {
//        msg.clear();
//        SecByteBlock salt((CryptoPP::byte*)ctx.substr(0, KEYSIZE_BYTES).data(), KEYSIZE_BYTES); //prev
//        string base_ctx = ctx.substr(KEYSIZE_BYTES);
//        Wrapper_harden_pw(pw, salt, key);
//        Wrapper_decrypt(key, base_ctx, "", msg);
//        ret = true;
//    } catch (CryptoPP::Exception& ex) {
//        // cerr << ex.what() << endl;
//        ret = false;
//    }
//    // TODO:  <hash_algo>.<iteration_cnt>.<salt>.<ctx>
//    return ret;
//}


/**
 *
 * @param key : Must of size AES::BLOCKSIZE
 * @param msg
 * @param extra_data
 * @param ctx : final output ciphertext is put in ctx.
 * AEAD scheme that encrypts msg and authenticate msg + extra_data. Return is pushed
 * ctx_format: <iv(AES::BLOCKSIZE)> + <msg_encryption> + <tag(MAC_SIZE_BYTES)>
 */
 bool CryptoSymWrapperFunctions::Wrapper_encrypt(const SecByteBlock &key, const string &msg, const string &extra_data, string& ctx) {
    GCM< AES, CryptoPP::GCM_2K_Tables>::Encryption encryptor;
    ctx.clear();
    assert( key.size() == AES::BLOCKSIZE );
    SecByteBlock iv(AES::BLOCKSIZE);
    PRNG.GenerateBlock(iv, AES::BLOCKSIZE);
    encryptor.SetKeyWithIV(key, key.size(), iv, iv.size());
    // StringSink* ctx_sink = new StringSink(ctx);
    auto ctx_sink = new StringSink(ctx);

    AuthenticatedEncryptionFilter ef(
            encryptor, ctx_sink, false, MAC_SIZE_BYTES
    );
    ctx_sink->Put(iv, iv.size(), true);

    // Authenticate the extra data first via AAD_CHANNEL.
    if (!extra_data.empty()) {
        ef.ChannelPut(AAD_CHANNEL, (const CryptoPP::byte*) extra_data.data(), extra_data.size(), true);
        ef.ChannelMessageEnd(AAD_CHANNEL);
    }
    // Now encrypt and auth real data
    bool MessageEncResult;

    ef.ChannelPut(DEFAULT_CHANNEL, (const CryptoPP::byte*) msg.data(), msg.size(), true);
    MessageEncResult = ef.ChannelMessageEnd(DEFAULT_CHANNEL);
    return  MessageEncResult;
}

 bool CryptoSymWrapperFunctions::Wrapper_decrypt(const SecByteBlock &key, const string &ctx, const string &extra_data, string& msg) {
    GCM< AES, CryptoPP::GCM_2K_Tables>::Decryption decryptor;
    string iv = ctx.substr(0, AES::BLOCKSIZE);
    string enc = ctx.substr(AES::BLOCKSIZE, ctx.length()-MAC_SIZE_BYTES-AES::BLOCKSIZE);
    string mac = ctx.substr(ctx.length()-MAC_SIZE_BYTES);
    // Sanity checks
//    cout << ctx.size() << " = " << iv.size() << " + "
//         << enc.size() << " + " << mac.size() << endl;

    assert( iv.size() == AES::BLOCKSIZE );
    assert( mac.size() == MAC_SIZE_BYTES );
    assert( ctx.size() == iv.size() + enc.size() + mac.size() );

    decryptor.SetKeyWithIV(key, key.size(), (const CryptoPP::byte*)iv.data(), iv.size());

    AuthenticatedDecryptionFilter df(
            decryptor, new StringSink(msg),
            AuthenticatedDecryptionFilter::MAC_AT_BEGIN | AuthenticatedDecryptionFilter::THROW_EXCEPTION,
            MAC_SIZE_BYTES
    );
    // The order of the following calls are important
    df.ChannelPut( DEFAULT_CHANNEL, (const CryptoPP::byte*)mac.data(), mac.size() );
    df.ChannelPut( AAD_CHANNEL,  (const CryptoPP::byte*)extra_data.data(), extra_data.size() );
    df.ChannelPut( DEFAULT_CHANNEL, (const CryptoPP::byte*)enc.data(), enc.size() );

    // If the object throws, it will most likely occur
    //   during ChannelMessageEnd()
    df.ChannelMessageEnd( AAD_CHANNEL );
    df.ChannelMessageEnd( DEFAULT_CHANNEL );

    // If the object does not throw, here's the only
    //  opportunity to check the data's integrity
    assert( df.GetLastResult() );
    return true;

    // Remove data from channel
    // df.SetRetrievalChannel( DEFAULT_CHANNEL );
    // size_t n = (size_t)df.MaxRetrievable();
    // msg.clear(); msg.resize( n );
    // if( n > 0 ) { df.Get( (byte*)msg.data(), msg.size() ); }
}


    // Function to split the secret (0 or 1 bit) into shares
    std::vector<uint8_t> ShamirSecretSharing::split(uint8_t secret) {
        assert(secret == 0 || secret == 1); // Secret must be 0 or 1

        // Generate random coefficients for the polynomial
        std::vector<uint8_t> coefficients(threshold - 1);
        generateRandomCoefficients(coefficients);

        // Create shares
        std::vector<uint8_t> shares(numShares);
        for (int i = 0; i < numShares; ++i) {
            uint8_t x = static_cast<uint8_t>(i + 1);
            shares[i] = evaluatePolynomial(secret, coefficients, x);
        }

        return shares;
    }

    // Function to combine the shares and recover the secret
    uint8_t ShamirSecretSharing::combine(const std::vector<uint8_t>& shares, const std::vector<uint8_t>& x_values) {
        assert(shares.size() >= threshold);

        uint8_t secret = 0;
        for (size_t i = 0; i < threshold; ++i) {
            uint8_t y = shares[i];
            uint8_t x = x_values[i];

            // Compute the Lagrange basis polynomial L_i(0)
            uint8_t Li = 1;
            for (size_t j = 0; j < threshold; ++j) {
                if (i != j) {
                    uint8_t xj = x_values[j];
                    Li *= (0 - xj) * modInverse(x - xj, 256);
                }
            }
            secret ^= y * Li;
            // secret += y * Li;

        }

        return secret;
    }

    int threshold;
    int numShares;

    // Generate random coefficients for the polynomial
    void ShamirSecretSharing::generateRandomCoefficients(std::vector<uint8_t>& coefficients) {
        auto seed = std::chrono::high_resolution_clock::now().time_since_epoch().count();
        // std::random_device rd;
        std::mt19937  gen(static_cast<unsigned int>(seed));
        std::uniform_int_distribution<uint8_t> dist(0, 255);

        for (auto& coef : coefficients) {
            coef = dist(gen);
        }
    }

    // Evaluate the polynomial at a given x value
    uint8_t ShamirSecretSharing::evaluatePolynomial(uint8_t secret, const std::vector<uint8_t>& coefficients, uint8_t x) {
        uint8_t result = secret;
        uint8_t x_power = 1;

        for (const auto& coef : coefficients) {
            x_power *= x;
            result ^= coef * x_power;
        }

        return result;
    }

    // Compute the multiplicative inverse of a modulo m
    uint8_t ShamirSecretSharing::modInverse(uint8_t a, uint8_t m) {
        for (uint8_t x = 1; x < m; ++x) {
            if ((a * x) % m == 1) {
                return x;
            }
        }
        return 1; // Should never happen if m is a prime number
    }



//
//void CryptoSymWrapperFunctions::Pad(const byte *input, size_t inputLen, byte *pkcsBlock, size_t pkcsBlockLen )
//{
////    CRYPTOPP_UNUSED(parameters);
////    CRYPTOPP_ASSERT (inputLen <= MaxUnpaddedLength(pkcsBlockLen));	// this should be checked by caller
//
//    // convert from bit length to byte length
//    if (pkcsBlockLen % 8 != 0)
//    {
//        pkcsBlock[0] = 0;
//        pkcsBlock++;
//    }
//    pkcsBlockLen /= 8;
//
//    pkcsBlock[0] = 2;  // block type 2
//
//    // pad with non-zero random bytes
////    for (unsigned i = 1; i < pkcsBlockLen-inputLen-1; i++)
////        pkcsBlock[i] = (byte)rng.GenerateWord32(1, 0xff);
//
//    pkcsBlock[pkcsBlockLen-inputLen-1] = 0;     // separator
//    memcpy(pkcsBlock+pkcsBlockLen-inputLen, input, inputLen);
//}