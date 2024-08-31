//
// Created by mameriek on 9/10/21.
//

#ifndef CONDENCCPP_CONDITIONALENCRYPTIONHAMDISTATMOSTT_H
#define CONDENCCPP_CONDITIONALENCRYPTIONHAMDISTATMOSTT_H

#if defined(CRYPTOPP_CXX11_NULLPTR) && !defined(NULLPTR)
# define NULLPTR nullptr
#elif !defined(NULLPTR)
# define NULLPTR NULL
#endif // CRYPTOPP_CXX11_NULLPTR

#include "PaillierWrapperFunctions.h"
#include "CryptoSymWrapperFunctions.h"
//#include "conditionalcrypto.h"

#include "aes.h"
using CryptoPP::AES;


#include "modes.h"
using CryptoPP::CBC_Mode;

#include "pwdbased.h"
using CryptoPP::PKCS5_PBKDF2_HMAC;

#include "hmac.h"
using CryptoPP::HMAC;

#include "base64.h"
using CryptoPP::Base64URLEncoder;
using CryptoPP::Base64URLDecoder;
const size_t SSShareSize = 28; //Indicating the secret sharing size;
/*
 * Class description:
 *          Conditional Encryption for Hamming Distance Two Predicate Using Shamir Secret Sharing
 * */
// public PaillerWrapperFunctions, public CryptoSymWrapperFunctions
class HamDistAtmostT {

public:



    /* API Documentation
	 * Algorithm description: Raw encryption scheme which uses the traditional encryption schemes (here we use Partially
     * homomorphic encryption scheme.
	 * Inputs:
	 *    paillier_pubkey_t* ppk                - the public key for our conditional encryption scheme
     *                                              (a pallier public key)
	 *    const string &msg                     - the input message msg of arbitrary length
     *  Output:
     *    string &tx                            - the output ciphertext will be written here.
     * */


    /*
     * API is similar to Enc, but the output ciphertext is pointer to byte array of unsigned char*
     * */
    static int Enc (paillier_pubkey_t* ppk, string &msg, char ctx_final[]);



    /*
     *
     * This function takes as input the public key ppk, the regualar ciphertext ctx, and the secret key psk and
     * the upper bound of the secret message size, and returns the plantext DecryptedMsg as the string. If the decryption
     * is successful, then it also outputs 1;
     *
     */
    static int RegDec(paillier_pubkey_t* ppk, char ctx [], paillier_prvkey_t* psk,
                            size_t _len, string &DecryptedMsg);






    /* API Documentation
	 * Algorithm description: Conditional Encryption algorithm which takes as input the traditional ctx and and then
     * based on the target predicate (hamming Distance two) generates the ciphertext using a secure secret sharing
     * scheme (here we use Shamir secret sharing which is provided by Crypto++ library).
	 * Inputs:
	 *    paillier_pubkey_t* ppk                - the public key for our conditional encryption scheme
     *                                              (a pallier public key)
	 *    const string& RlPwd_ctx_pull          - the input ciphertext of some (unknown) original message x
	 *    const string typo                     - input string which may or may not have ED(typo,x)<= 1
	 *    const string payload                  - the input message to be conditionally encypted based on the predicate ED(typo,x)<= 1
     *    size_t _len                           - Determines the size of padded message
     *  Output:
     *    string typo_ctx                       - the output ciphertext will be written here. If HD(typo,x) > 2
     *                                              the ciphertext reveals nothing about inputs typo or payload or
     *                                              otherwise if ED(typo,x)<=2 then the ciphertext can be decrypted to
     *                                              recover the string payload.     *
     * */


    /*
     * The functionality is similar to the CondEnc while the output is pointer to byte string of unsined char*
     *
     * Note: To achieve the Conditional Encryption for Hamming distance 2, we need to set the threshold value as
     * threshold  = _len - 2, and similarly for Hamming distance 2, we need threshold = _len - 3
     * */
    static string CondEnc(paillier_pubkey_t* ppk,
                        char RlPwd_ctx_pull[],
                        string& typo,
                        string& payload,
                        size_t _len,
                        int threshold,
                        char ctx_final[]);




    /* API Documenation
	 * Conditional Encryption for Hamming Distance Two Predicate Using Shamir Secret Sharing: Decryption Algorithm
	 * Inputs:
	 *    const string &typo_ctx                - the conditional ciphertext to decrypt
     *    paillier_pubkey_t* ppk                - the public key for our conditional encryption scheme
     *                                              (a pallier public key)
	 *    paillier_prvkey_t* psk                - the secrtet  key for our conditional encryption scheme
     *                                              (a pallier secret key)
     *    int threshold                         - the threshold number of requirecd valid shares
     *                                              to recover the shared secret
	 *    string recovered                      - the decrypted message will be written here (might be garbage )
     *    size_t _len                           - Determines the size of original padded message
     *
     *    Returns 1 if the message was successfully recovered; -1 if recovery failed
     * */

    static int CondDec(paillier_pubkey_t* ppk,
                        char typo_ctx [],
                        paillier_prvkey_t* psk,
                        int threshold,
                        string &recovered,
                        size_t _len);

    static int CondDec_NonSmallFieldCheck(paillier_pubkey_t* ppk,
                        char typo_ctx [],
                        paillier_prvkey_t* psk,
                        int threshold,
                        string &recovered,
                        size_t _len);

    static int CondDec_NewOPT(paillier_pubkey_t* ppk,
                        char typo_ctx [],
                        paillier_prvkey_t* psk,
                        int threshold,
                        string &recovered,
                        size_t _len);

    static int CondDec_2dif(paillier_pubkey_t* ppk,
                              char typo_ctx [],
                              paillier_prvkey_t* psk,
                              int threshold,
                              string &recovered,
                              size_t _len);

    static int CondDec_Optimized(paillier_pubkey_t* ppk,
                                      char typo_ctx [],
                                      paillier_prvkey_t* psk,
                                      int threshold,
                                      string &recovered,
                                      size_t _len,
                                      size_t l_m);


    static int CondDec_Optimized_UnknownMsgLength(paillier_pubkey_t* ppk,
                            char typo_ctx [],
                            paillier_prvkey_t* psk,
                            int threshold,
                            string &recovered,
                            size_t _len);



//private:

/*
 * Set of required wrapper function for Conditiona Encryption for Hamming Distance Two Predicate
 * Using Shamir Secret Sharing.
 *
 * TODO: I neeed to add the description of the API for the helper functions as well.
 * */

    /*
     * API Documentation:
     * Inputs:
     *      std::vector<std::string> &strShares                     - the string vector of the generated shares
     *      int threshold                                           - the threshold number of requirecd valid shares
     *      vector<int> &selected                                   - subset of selected shares of size threshold:
     *                                                                  We check to see if recovered small secre is
     *                                                                  valid or not. if yes, we recover the main share
     *                                                                  based on the index of the selected shares.
     *  Output:
     *      boolian value which is True if there exists a subset of valid shares; otherwise the ouput is False.
     *
     * */
//    void combinationUtil(int arr[], int n, int r,
//                         int index, int data[], int i);

    static bool TestIfTheSahreAreValid (vector<string> &strShares,
                                        int threshold, vector<int> &selected);

    static tuple<vector<paillier_ciphertext_t*>, string> Pail_Parse_Ctx_size_AECtx(paillier_pubkey_t* ppk,
                                                              char* ctx);

    static int  Pail_Parse_Ctx_size_AECtx2(paillier_pubkey_t* ppk, char* ctx, string& CtxtAEStr, vector<paillier_ciphertext_t*>& Vect_Ctx );

    /*
     * TODO: The API description will be added
     * */

    static void makeCombiUtil(vector<vector<int>>& ans, vector<int>& tmp, int n, int left, int k);



    /*
     * Informal Function Description:
     *      The function checks that if the selectes set of shares of the main secret is valid by recovering the secret
     *      and checking the Authenticated Decryption algorithm.
     *      TODO: Formal API will be added
     * */

    static bool RecoverSecretFromValidShares (vector<string> &strShares, int threshold,
                                              vector<int> &selected,
                                              string &RecoveredSecret );

    /*
     * TODO: The API description will be added
     * */

    static int generatesubsets(vector<string> &MainstrShares, vector<string> &strShares,
                        const string &DecoddCtxAE, string &recoveredMainSecret, string &plaintext_rcv, vector<int> choices,
                        int current, int K, vector<int> selected=vector<int>(),
                        vector<int> Valid_selected = vector<int>());


    /*
     * The folowing function, recursively extract all possible combinatiobs of n choose threshold in the
     * optimized way that we described.
     * The API is described as follows:
     *  Inputs:
     *      MainstsharesL:  the string vector of the shares
     *      strShares:      The shares of the small secret, i.e., "0000".
     *      DecoddCtxAE:    The ctxt of the authenticated encryption, which encryptes the actual payload using the secret key extracted from the secret value.
     *  OutputL
     *      recoveredMainSecret:    The fianl valid secret and we use it to recover the secret key.
     *      plainteext_rcv:         The final payload which is recovered by successful AuthenDecrypt.
     *      choices:                The vector of the current choices which will be updated, recuresively.
     *      current:                The index of the vector which implies the current index of the vector element
     *      K:                      The size current selected eleement.
     *      l_m:                    The size of the original message
     *
     * */
    static int generatesubsets_Optimized(vector<string> &MainstrShares, vector<string> &strShares,
                               const string &DecoddCtxAE, string &recoveredMainSecret, string &plaintext_rcv, vector<int> choices,
                               int current, size_t l_m, int threshold, vector<int> selected=vector<int>(),
                               vector<int> Valid_selected = vector<int>());


    static int generatesubsets_NonSmallFieldCheck(vector<string> &MainstrShares,
                    const string& DecoddCtxAE, string &recoveredMainSecret, string &plaintext_rcv, vector<int> choices,
                    int current, int K, vector<int> selected,
                    vector<int> Valid_selected= vector<int>());


    /*
     * API Documention for the helper functions Enc_SecretShr
     * Inputs:
     *      std::vector<std::string> strShares                      - The string vector of the generates share
     *                                                                  of the secret [Shamir secret Sharing is used]
     *      paillier_pubkey_t* ppk                                  - the public key for our conditional
     *                                                                  encryption scheme (a pallier public key)
     *      size_t ShareSize                                        - Size of the shares which are field elements of a
     *                                                                  specific size.
     *      size_t _len                                             - Determines the size of original padded message
     *
     *  Output:
     *      vector<paillier_ciphertext_t*> &Shar_Ctxt               - the generated encryption of each share will
     *                                                                  written as one of the vector elements of output
     *                                                                  vector ciphertext, i.e., Shar_Ctxt
     *      For successful execution of encryption algorithm it returns integer 1.
     *
     *
     * */
    static int Enc_SecrtShr(vector<string> strShares,  paillier_pubkey_t* ppk,
                     vector<paillier_ciphertext_t*> &Shar_Ctxt, size_t ShareSize, size_t _len );

    static vector<paillier_ciphertext_t*> Enc_SecrtShr_V2(vector<string> strShares,  paillier_pubkey_t* ppk,
                                                          size_t ShareSize, size_t _len );

    static vector<int> GnereateVectorOfIntegeres (int _len);
    static paillier_plaintext_t* RandEncod(string& share, size_t ShareSize, mpz_t N_p_floor, mpz_t P_GF);
    static paillier_plaintext_t* RandDecod(string& share, size_t ShareSize, mpz_t N_p_floor, mpz_t P_GF);

};


#endif //CONDENCCPP_CONDITIONALENCRYPTIONHAMDISTATMOSTT_H
