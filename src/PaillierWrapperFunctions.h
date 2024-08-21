//
// Created by mameriek on 9/7/21.
//


/*
 * This document introduces the required wrapper functions which are
 *      1. PaillierAdd:             which does ...
 *      2. PaillierSub:             which does ...
 *      3. PaillierRand:            Which does ...
 *      4. PaillierPlainCtxMult:
 * */

#ifndef CONDENCCPP_PAILLIERWRAPPERFUNCTIONS_H
#define CONDENCCPP_PAILLIERWRAPPERFUNCTIONS_H


#include <math.h>       /* pow */

#include "../paillier/pailliercpp.h"



#include<tuple>
#include<vector>
#include <iostream>
#include <string>
#include <cstring>
#include <sstream>
//#include "db.pb.h"
using namespace std;

// typedef unsigned char CondEnc_byte;		// put in global namespace to avoid ambiguity with other byte typedefs



class PaillerWrapperFunctions {
public:


    /*
     * This function, takse as input the Byte version of ciphretext ctx and parse it in
     * vectot of ciphertexts. The parsing is doen in term of the ciphertext size.  So
     * if the ctx size is |ctx| = orgimessage * sizeof(paillier_ciphertext_t*), each vector element
     * has size sizeof(paillier_ciphertext_t)
     * */
    static vector<paillier_ciphertext_t*> Pail_Parse_Ctx_size(paillier_pubkey_t* ppk,
                                                                   char* ctx);

    /*
 * This algorithm is used to define the encryption of the imput message as the whole message
 * : This algorithm basically takes as input the string of message and then uses the paillier
 * encryption algorithms and then encrypt it and outputs a pointer to an array of the char*.
 * The aim of this function is use to conside the traditional encrption scheme in the case we
 * dont use the conditionl encryption. It write the resulting ctxt on the array of the ctx final
 * array. If the encrytption algorithm is successfull (without any error, it outputs 1).
     * The input message is padded message of lent _len
 * */
    //TODO:  What is remaining is to write a code to trasnfer the char* to pail Ctxt and decrypt using the paillier sk.
    static int Pail_Classic_Enc(string& msg, paillier_pubkey_t* ppk, char ctx_final[]);

    /*
     *
     * */

    static int Pail_Classic_Dec( paillier_pubkey_t* ppk,
                        char* pail_ctx,
                        paillier_prvkey_t* psk,
                        string &plaintext,int _len);

    static int Pail_Parse_Ctx_Classic(paillier_pubkey_t* ppk,
                                                  char* ctx,
                                                  vector<paillier_ciphertext_t*> &Vect_Ctx);





    /*
 * This function takes as input the message msg of size |msg| bytes, and outputs
 * C = PailEnc(msg[0]) || ... || PailEnc(msg[|msg|]) and the size of the C is |msg| * sizeof(paillier_ciphertext_t*)
 * */
    static int Enc_Byte_By_Byte(string& msg, paillier_pubkey_t* ppk, char ctx_final[]);


    static vector<paillier_ciphertext_t*> Pail_Parse_Real_Pass_Ctx(paillier_pubkey_t* ppk,
                                                                   string& ctx,
                                                                   int& VecSize,
                                                                   string &CtxAE,
                                                                   int b);

    /*
    * Inputs:
    *  paillier_pubkey_t* ppk                   - pallier public key
    *  paillier_ciphertext_t* ctx_1             - pallier encryption of unknown message m1
    *  paillier_ciphertext_t* ctx_2             - pallier encryption of unknown message m2
    *  Returns paillier_ciphertext_t* res       - pallier encryption of message m1+m2
    */
    static paillier_ciphertext_t* Pail_Add(paillier_pubkey_t* ppk, paillier_ciphertext_t* ctx_1,
                                           paillier_ciphertext_t* ctx_2) ;

    /*
	* Inputs:
	*  paillier_pubkey_t* ppk                   - pallier public key.
	*  paillier_ciphertext_t* ct                - pallier encryption of unknown message m.
	*  paillier_plaintext_t* pt                 - known plaintext x.
	* Returns paillier_ciphertext_t* res        - pallier encryption of message m * x.
	*/
    static paillier_ciphertext_t* Pail_Mult_PtxCtx( paillier_pubkey_t* pub,
                                                    paillier_ciphertext_t* ct,
                                                    paillier_plaintext_t* pt);

    /*
     * Inputs:
     *  paillier_pubkey_t* ppk                  - pallier public key.
     *  paillier_ciphertext_t* ctx_1            - pallier encryption of unknown message m1.
     *  paillier_ciphertext_t* ctx_2            - pallier encryption of unknown message m2.
     *  Returns paillier_ciphertext_t* res      - pallier encryption of message m1 - m2
     *
     * */

    static paillier_ciphertext_t* Pail_Subtct(paillier_pubkey_t* ppk,
                                              paillier_ciphertext_t* ctx_1,
                                              paillier_ciphertext_t* ctx_2);

    /*
     * Inputs:
     *  gmp_randstate_t rand                    - Random number generation algorith's specification parameter
     *  paillier_get_rand_t get_rand            - Type of callback function for obtaining the needed randomness.
     *  int bytes                               - number of bytes for the output randomness.
     * Output: void* buf                        - The buffer of random elements: bytes.
     * */
    // static void init_rand( gmp_randstate_t rand, paillier_get_rand_t get_rand, int bytes );
 static void init_rand( gmp_randstate_t rand, int bytes );



    /*
     * Inputs:
     *  paillier_pubkey_t* ppk                  - pallier public key.
     * Output:
     *  returns paillier_plaintext_t* RR        - a random element in the plaintext space of paillier cryptosystem
     * */

    static paillier_plaintext_t* Rand_Plain_Pail(const paillier_pubkey_t* ppk );


    /*
     * Input:
     *  const string msg                                - the string of the input message to be encrypted byte by byte.
     *  paillier_pubkey_t* ppk                          - pallier public key.
     * Output:
     *  returns vector<paillier_ciphertext_t*> vctx     - a vector of size msg.size() encrypts each bytes of msg
     * */
    static vector<paillier_ciphertext_t*> Enc_Vec_Typo(string& msg,  paillier_pubkey_t* ppk);

    static void makeCombiUtil(vector<vector<int> >& ans,
                              vector<int>& tmp, int n, int left, int k);

    static vector<vector<int> > makeCombi(int n, int k);
    static vector<byte> mpz_to_vector(mpz_t x, size_t _ShareStreamSizer);
    static vector<char> mpz_to_vector_char(mpz_t x, size_t _ShareStreamSizer);







    /*TODO: Adding the functions for the modified encrytpion fucntions like byte by byte*/

//    vector<paillier_ciphertext_t *> Enc_Vec_Typo(const string msg, paillier_pubkey_t *ppk);
};


#endif //TYPTOP_PAILLIERWRAPPERFUNCTIONS_H
