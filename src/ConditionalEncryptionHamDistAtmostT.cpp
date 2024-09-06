//
// Created by mameriek on 9/10/21.
//
#include<chrono>
#include "ConditionalEncryptionHamDistAtmostT.h"

/*Small shared size of 8*/
bool HamDistAtmostT::TestIfTheSahreAreValid (vector<string> &strShares, int threshold, vector<int> &selected)
{
    string channel;
    const unsigned int CHID_LENGTH = 4;
    string recovered;
    CryptoPP::SecretRecovery recovery(threshold, new StringSink(recovered), false);

    CryptoPP::vector_member_ptrs<StringSource> strSources(threshold);
    channel.resize(CHID_LENGTH);
    for (unsigned int i=0; i<threshold; i++)
    {
        strSources[i].reset(new StringSource(strShares[selected[i]], false));
        strSources[i]->Pump(CHID_LENGTH);
        strSources[i]->Get((CryptoPP::byte*)&channel[0], CHID_LENGTH);
        strSources[i]->Attach(new CryptoPP::ChannelSwitch(recovery, channel));
    }

    while (strSources[0]->Pump(256))
    {
        for (unsigned int i=1; i<threshold; i++)
            strSources[i]->Pump(256);
    }

    for (unsigned int i=0; i<threshold; i++)
        strSources[i]->PumpAll();

    bool fail = false;
    // string subsRcvr= recovered.substr(0, 4);

    const char* Zero_str = "0\000\000\000";
    fail = (Zero_str[0] == recovered[0] && Zero_str[1] == recovered[1] && Zero_str[2] == recovered[2] && Zero_str[3] == recovered[3]);
    // fail = (Zero_str[0] == recovered[0] );



    // fail = ("0000" == recovered);//for Optimized solution, TODO: make the non optimum without cancelling it
    // fail = ("0\000\000" == recovered.substr(0,3));//for Optimized soulution, TODO: make the non optimum without cancelling it


    //    fail  = true;
    return fail;
}



bool HamDistAtmostT::TestIfTheSahreAreValid_GF256 (shares* strShares, int threshold, vector<int> &selected, int _len)
{


    scheme GF256_SSscheme(_len,threshold);
    shares* GF256_shares = new shares(threshold);
    for(int i= 0; i< threshold; i++) {
        for(auto val:(*strShares)[selected[i]]) {
            (*GF256_shares)[i].push_back(val);
        }
    }

    string recovered = GF256_SSscheme.getSecret(GF256_shares);

    bool fail = false;
    fail = (recovered == "0");
    //    fail  = true;
    return fail;
}



//  bool HamDistAtmostT::TestIfTheSahreAreValid (vector<string> &strShares, int threshold, vector<int> &selected)
// {
//     string channel;
//     const unsigned int CHID_LENGTH = 4;
//     string recovered;
//     CryptoPP::SecretRecovery recovery(threshold, new StringSink(recovered), false);
//
//     CryptoPP::vector_member_ptrs<StringSource> strSources(threshold);
//     channel.resize(CHID_LENGTH);
//     for (unsigned int i=0; i<threshold; i++)
//     {
//         strSources[i].reset(new StringSource(strShares[selected[i]], false));
//         strSources[i]->Pump(CHID_LENGTH);
//         strSources[i]->Get((CryptoPP::byte*)&channel[0], CHID_LENGTH);
//         strSources[i]->Attach(new CryptoPP::ChannelSwitch(recovery, channel));
//     }
//
//     while (strSources[0]->Pump(256))
//     {
//         for (unsigned int i=1; i<threshold; i++)
//             strSources[i]->Pump(256);
//     }
//
//     for (unsigned int i=0; i<threshold; i++)
//         strSources[i]->PumpAll();
//
//     bool fail = false;
//      // string subsRcvr= recovered.substr(0, 4);
//
//      const char* Zero_str = "0\000\000\000";
//      fail = (Zero_str[0] == recovered[0] && Zero_str[1] == recovered[1] && Zero_str[2] == recovered[2] && Zero_str[3] == recovered[3]);
//
//
//
//     // fail = ("0000" == recovered);//for Optimized solution, TODO: make the non optimum without cancelling it
//     // fail = ("0\000\000" == recovered.substr(0,3));//for Optimized soulution, TODO: make the non optimum without cancelling it
//
//
// //    fail  = true;
//     return fail;
// }


  void HamDistAtmostT::makeCombiUtil(vector<vector<int> >& ans,
                   vector<int>& tmp, int n, int left, int k)
{
    // Pushing this vector to a vector of vector
    if (k == 0) {
        ans.push_back(tmp);
        return;
    }

    // i iterates from left to n. First time
    // left will be 1
    for (int i = left; i <= n; ++i)
    {
        tmp.push_back(i);
        makeCombiUtil(ans, tmp, n, i + 1, k - 1);

        // Popping out last inserted element
        // from the vector
        tmp.pop_back();
    }
}


 bool HamDistAtmostT::RecoverSecretFromValidShares (vector<string> &strShares,
                                                int threshold,
                                                vector<int> &selected,
                                                string &RecoveredSecret)
{

     string channel;
    const unsigned int CHID_LENGTH = 4;
    string recovered;
    CryptoPP::SecretRecovery recovery(threshold, new StringSink(recovered), false);

    CryptoPP::vector_member_ptrs<StringSource> strSources(threshold);
    channel.resize(CHID_LENGTH);

    for (unsigned int i=0; i<threshold; i++)
    {
        strSources[i].reset(new StringSource(strShares[selected[i]], false));
        strSources[i]->Pump(CHID_LENGTH);
        strSources[i]->Get((CryptoPP::byte*)&channel[0], CHID_LENGTH);
        strSources[i]->Attach(new CryptoPP::ChannelSwitch(recovery, channel));
    }

    while (strSources[0]->Pump(256))
    {
        for (unsigned int i=1; i<threshold; i++)
            strSources[i]->Pump(256);
    }

    for (unsigned int i=0; i<threshold; i++)
        strSources[i]->PumpAll();
    size_t keySize = recovered.size();
     size_t KeySizePut;
//    memcpy(&RecoveredSecret, &recovered, recovered.size()-1 );
//    RecoveredSecret =  recovered;

     CryptoPP::StringSink ss_RecoveredSecret(RecoveredSecret);
cout << "";
    KeySizePut =  ss_RecoveredSecret.Put((const CryptoPP::byte*)recovered.data(),  recovered.size(), false);

     return true;
}


//void HamDistAtmostT::combinationUtil(int arr[], int n, int r, int index,
//                     int data[], int i, std::vector<std::string> &MainstrShares, std::vector<std::string> &strShares)
//{
//    // Current combination is ready, print it
//    if (index == r) {
//        bool fail;
//        vector<int> selected= reinterpret_cast<const vector<int, allocator<int>> &>(data);
//        fail = TestIfTheSahreAreValid(strShares, r, selected );
//        return;
//    }
//
//    // When no more elements are there to put in data[]
//    if (i >= n)
//        return;
//
//    // current is included, put next at next location
//    data[index] = arr[i];
//    combinationUtil(arr, n, r, index + 1, data, i + 1, std::vector<std::string> &MainstrShares, std::vector<std::string> &strShares);
//
//    // current is excluded, replace it with next
//    // (Note that i+1 is passed, but index is not
//    // changed)
//    combinationUtil(arr, n, r, index, data, i + 1, std::vector<std::string> &MainstrShares, std::vector<std::string> &strShares);
//}


int HamDistAtmostT::generatesubsets_GF256(vector<string> &MainstrShares,shares* strShares,
                    const string& DecoddCtxAE, string &recoveredMainSecret, string &plaintext_rcv, vector<int> choices,
                    int current, int K, vector<int> selected,
                    vector<int> Valid_selected, int _len) {

//    const string CTXT_AE = DecoddCtxAE;
    if(choices.size()-current<K-selected.size())
        return 0;
    if(selected.size()==K){
        // vector<std::string> o[selected];
        //process subset
        bool pass;
        // auto start_checkShare = std::chrono::high_resolution_clock::now();
        pass = HamDistAtmostT::TestIfTheSahreAreValid_GF256(strShares, K, selected , _len);

        // auto stop_CheckShare = std::chrono::high_resolution_clock::now();

        // auto duration_CondDec_HD = std::chrono::duration_cast<std::chrono::microseconds>(stop_CheckShare - start_checkShare);
        // cout  << "OPT Share Checking time: " << duration_CondDec_HD.count() << "\n";
        if (pass)
        {


            Valid_selected = selected;
            string recoverTheMainSecret;

            bool ifCorrectShareVec;
            ifCorrectShareVec = HamDistAtmostT::RecoverSecretFromValidShares (MainstrShares, K, selected, recoverTheMainSecret );
            size_t key_size = recoverTheMainSecret.size();
            CryptoPP::StringSink ss_recoveredMainSecret(recoveredMainSecret);
            cout << "";
            auto reMainSecrtSize = ss_recoveredMainSecret.Put((const CryptoPP::byte*)recoverTheMainSecret.data(),  recoverTheMainSecret.size(), false);
            bool AEReslt = false;
            AEReslt = CryptoSymWrapperFunctions::Wrapper_AuthDecrypt(recoverTheMainSecret, DecoddCtxAE,plaintext_rcv );


            if(AEReslt)
            {
                // cout << "The recovered payload is = " << plaintext_rcv << "\n";
                return 1;
            }

        }
        return 0;
    }
    if(current==choices.size())
        return 0;

    selected.push_back(choices[current]);
    if (HamDistAtmostT::generatesubsets_GF256(MainstrShares, strShares, DecoddCtxAE, recoveredMainSecret, plaintext_rcv,
                        choices,current+1,K,selected,  Valid_selected, _len) == 1) return 1;
    selected.pop_back();
    if (HamDistAtmostT::generatesubsets_GF256(MainstrShares, strShares, DecoddCtxAE, recoveredMainSecret, plaintext_rcv,
                        choices,current+1,K,selected, Valid_selected, _len) == 1) return 1;

    return 0;
}




int HamDistAtmostT::generatesubsets(vector<string> &MainstrShares, vector<string> &strShares,
                    const string& DecoddCtxAE, string &recoveredMainSecret, string &plaintext_rcv, vector<int> choices,
                    int current, int K, vector<int> selected,
                    vector<int> Valid_selected) {

//    const string CTXT_AE = DecoddCtxAE;
    if(choices.size()-current<K-selected.size())
        return 0;
    if(selected.size()==K){
        // vector<std::string> o[selected];
        //process subset
        bool pass;
        auto start_checkShare = std::chrono::high_resolution_clock::now();
        // int _len = MainstrShares.size();
        pass = HamDistAtmostT::TestIfTheSahreAreValid(strShares, K, selected );//For the optimized solution
        // pass = HamDistAtmostT::TestIfTheSahreAreValid_GF256(strShares, K, selected , _len);

        auto stop_CheckShare = std::chrono::high_resolution_clock::now();

        auto duration_CondDec_HD = std::chrono::duration_cast<std::chrono::microseconds>(stop_CheckShare - start_checkShare);
        cout  << "OPT Share Checking time: " << duration_CondDec_HD.count() << "\n";
        if (pass)
        {


            Valid_selected = selected;
            string recoverTheMainSecret;

            bool ifCorrectShareVec;
            ifCorrectShareVec = HamDistAtmostT::RecoverSecretFromValidShares (MainstrShares, K, selected, recoverTheMainSecret );
            size_t key_size = recoverTheMainSecret.size();
            CryptoPP::StringSink ss_recoveredMainSecret(recoveredMainSecret);
            cout << "Hi\n";
            auto reMainSecrtSize = ss_recoveredMainSecret.Put((const CryptoPP::byte*)recoverTheMainSecret.data(),  recoverTheMainSecret.size(), false);
            bool AEReslt = false;
            AEReslt = CryptoSymWrapperFunctions::Wrapper_AuthDecrypt(recoverTheMainSecret, DecoddCtxAE,plaintext_rcv );


            if(AEReslt)
            {
                // cout << "The recovered payload is = " << plaintext_rcv << "\n";
                return 1;
            }

        }
//            for(auto i:selected)
//                cout<<i<<" ";
//            cout<<endl;
        return 0;
    }
    if(current==choices.size())
        return 0;

    selected.push_back(choices[current]);
    if (HamDistAtmostT::generatesubsets(MainstrShares, strShares, DecoddCtxAE, recoveredMainSecret, plaintext_rcv,
                        choices,current+1,K,selected,  Valid_selected) == 1) return 1;
    selected.pop_back();
    if (HamDistAtmostT::generatesubsets(MainstrShares, strShares, DecoddCtxAE, recoveredMainSecret, plaintext_rcv,
                        choices,current+1,K,selected, Valid_selected) == 1) return 1;

    return 0;
}


 int HamDistAtmostT::generatesubsets_NonSmallFieldCheck(vector<string> &MainstrShares,
                    const string& DecoddCtxAE, string &recoveredMainSecret, string &plaintext_rcv, vector<int> choices,
                    int current, int K, vector<int> selected,
                    vector<int> Valid_selected) {

//    const string CTXT_AE = DecoddCtxAE;
    if(choices.size()-current<K-selected.size())
        return 0;
    if(selected.size()==K){

        // auto start_checkShare = std::chrono::high_resolution_clock::now();

        Valid_selected = selected;
        string recoverTheMainSecret;

        bool SSRecoverRsl = HamDistAtmostT::RecoverSecretFromValidShares (MainstrShares, K, selected, recoverTheMainSecret );

        size_t key_size = recoverTheMainSecret.size();
        CryptoPP::StringSink ss_recoveredMainSecret(recoveredMainSecret);
        cout << "";
        ss_recoveredMainSecret.Put((const CryptoPP::byte*)recoverTheMainSecret.data(),  recoverTheMainSecret.size(), false);

        bool AEReslt;


        AEReslt = CryptoSymWrapperFunctions::Wrapper_AuthDecrypt(recoverTheMainSecret, DecoddCtxAE,plaintext_rcv );
        // auto stop_CheckShare = std::chrono::high_resolution_clock::now();

        // auto duration_CondDec_HD = std::chrono::duration_cast<std::chrono::microseconds>(stop_CheckShare - start_checkShare);
        // cout  << "Non_OPT Share Checking time: " << duration_CondDec_HD.count() << "\n";
        /*
         * TODO: Here based on the Jeremiah Suggestion, we need to check if the authenticated decryption outputs
         * true or not. If yes, we retun the resulting secret which is the typo. We need to use RecoverMainSecet
         * for doing so. We also need the value of the decoded ciphretext (STATE: Is done!)
         * */
        if (AEReslt==true)
        {
            return 1;
        }

    }
    if(current==choices.size())
        return 0;

    selected.push_back(choices[current]);
    if (HamDistAtmostT::generatesubsets_NonSmallFieldCheck(MainstrShares, DecoddCtxAE, recoveredMainSecret, plaintext_rcv,
                        choices,current+1,K,selected,  Valid_selected) == 1) return 1;
    selected.pop_back();
    if (HamDistAtmostT::generatesubsets_NonSmallFieldCheck(MainstrShares, DecoddCtxAE, recoveredMainSecret, plaintext_rcv,
                        choices,current+1,K,selected, Valid_selected) == 1) return 1;

    return 0;
}


int HamDistAtmostT::generatesubsets_Optimized(vector<string> &MainstrShares, vector<string> &strShares,
                                const string& DecoddCtxAE, string &recoveredMainSecret, string &plaintext_rcv, vector<int> choices,
                                int current, size_t l_m, int K, vector<int> selected,
                                vector<int> Valid_selected) {

//    const string CTXT_AE = DecoddCtxAE;
    if(choices.size()-current<K-selected.size())
        return 0;
    if(selected.size()==K){
        // vector<std::string> o[selected];
        //process subset
        bool pass;
        pass = HamDistAtmostT::TestIfTheSahreAreValid(strShares, K, selected );//For the optimized solution
        if (pass)
        {
            Valid_selected = selected;
            string recoverTheMainSecret;
            HamDistAtmostT::RecoverSecretFromValidShares (MainstrShares, K, selected, recoverTheMainSecret );
            size_t key_size = recoverTheMainSecret.size();
//            recoveredMainSecret = recoverTheMainSecret;

            CryptoPP::StringSink ss_recoveredMainSecret(recoveredMainSecret);
            ss_recoveredMainSecret.Put((const CryptoPP::byte*)recoverTheMainSecret.data(),  recoverTheMainSecret.size(), false);

//            memcpy(&recoveredMainSecret, &recoverTheMainSecret, recoverTheMainSecret.size());
//            recoveredMainSecret = recoverTheMainSecret; //This will be potential secret key for the Authenticated decryption

            // bool AEReslt;

            // AEReslt = CryptoSymWrapperFunctions::Wrapper_AuthDecrypt(recoverTheMainSecret, DecoddCtxAE,plaintext_rcv );

            /*
             * TODO: Here based on the Jeremiah Suggestion, we need to check if the authenticated decryption outputs
             * true or not. If yes, we retun the resulting secret which is the typo. We need to use RecoverMainSecet
             * for doing so. We also need the value of the decoded ciphretext (STATE: Is done!)
             * */
            // if (AEReslt==true) return 1;
            return 1;
        }
//            for(auto i:selected)
//                cout<<i<<" ";
//            cout<<endl;
        return 0;
    }
    if(current==l_m + 2)
        return 0;

    selected.push_back(choices[current]);
    if (HamDistAtmostT::generatesubsets_Optimized(MainstrShares, strShares, DecoddCtxAE, recoveredMainSecret, plaintext_rcv,
                                    choices,current+1, l_m, K,  selected,  Valid_selected) == 1) return 1;
    selected.pop_back();
    if (HamDistAtmostT::generatesubsets_Optimized(MainstrShares, strShares, DecoddCtxAE, recoveredMainSecret, plaintext_rcv,
                                    choices,current+1, l_m, K,  selected, Valid_selected) == 1) return 1;

    return 0;
}


/*
 * This function takes as input the Base64 encoded (using b64Encode fucntion) and concetenated shares of and then
 * first endodce them as an integer and then runs RandEncode function on it. All the computations are helndle with
 * gmp library.
 * */
//    vector<paillier_ciphertext_t*> Enc_SecrtShr(std::vector<std::string> strShares,  paillier_pubkey_t* ppk) const {
int HamDistAtmostT::Enc_SecrtShr(vector<string> strShares,  paillier_pubkey_t* ppk,
                                                  vector<paillier_ciphertext_t*> &Shar_Ctxt, size_t ShareSize,
                                                  size_t _len )  {

    /*Computing the maximum value of the share*/



    mpz_t P_GF;
    mpz_init(P_GF);
    size_t ShareStreamSizer = ShareSize;
    int max_power_int = (ShareStreamSizer * 8) + 1;
    mpz_ui_pow_ui(P_GF, 2, max_power_int);
    mpz_sub_ui(P_GF, P_GF, 1); // computing the value of P_GF based on the size of the input value.
    mpz_t N_p_floor;
    mpz_init(N_p_floor);
    mpz_fdiv_q(N_p_floor,ppk->n,P_GF); // Here, we have P_GF = 2^(36 * 8 +1 ) -1
    mpz_sub_ui(N_p_floor,N_p_floor, 1 ); // We have N_p_floor = floor(N/P_GF - 1) (This is correct with the assumption that p = 2 ^32.
//    paillier_plaintext_t* m_rcv_aftermod;
//    m_rcv_aftermod = (paillier_plaintext_t*) malloc(sizeof(paillier_plaintext_t));
//    mpz_init(m_rcv_aftermod->m);
    mpz_t a_i;
    mpz_init(a_i);
    paillier_plaintext_t* m;
    m = (paillier_plaintext_t*) malloc(sizeof(paillier_plaintext_t));
    mpz_init(m->m);
//    mpz_t aux;
//    mpz_init(aux);
//    paillier_plaintext_t* m_Rand;
    for(int i = 0; i < _len; i++){


//        paillier_plaintext_t* m_Rand;
        auto& str_Shrs = strShares[i];
        unsigned char a[ShareSize];
        for (int j = 0; j <ShareSize ; ++j)
        {
            a[j] =  str_Shrs[j];
        }
        mpz_import(m->m, ShareSize, -1, 1, 0, 0, &a[0]);
//        mpz_init_set(m->m, aux);

//        m = paillier_plaintext_from_bytes(&a[0],ShareSize );
        gmp_randstate_t rand_i;
        gmp_randinit_mt(rand_i);
        mpz_urandomm (a_i, rand_i, N_p_floor); // Generates a random number in range [1, N_p_floor] in which N_p_floor =  floor(N/p - 1).
        mpz_mul(a_i, a_i, P_GF); //multiplying a_i with P_GF and set as m_Rand->m;
        mpz_add(m->m, m->m, a_i); // Computing m_Rand = m_i + a_i * p mod N.
        Shar_Ctxt[i] = paillier_enc(NULL, ppk, m, paillier_get_rand_devrandom);
        gmp_randclear(rand_i);
    }

//    paillier_freeplaintext(m_rcv_aftermod);
    paillier_freeplaintext(m);
    mpz_clear(a_i);
    mpz_clear(P_GF);
    mpz_clear(N_p_floor);
//    mpz_clear(aux);
    return 1;
}

vector<paillier_ciphertext_t*> HamDistAtmostT::Enc_SecrtShr_V2(vector<string> strShares,  paillier_pubkey_t* ppk,
                                               size_t ShareSize, size_t _len )
{
    vector<paillier_ciphertext_t*> Shar_Ctxt(_len);

    mpz_t P_GF;
    mpz_init(P_GF);
    int max_power_int = (ShareSize * 8) + 1;
    mpz_ui_pow_ui(P_GF, 2, max_power_int);
    mpz_sub_ui(P_GF, P_GF, 1); // computing the value of P_GF based on the size of the input value.
    mpz_t N_p_floor;
    mpz_init(N_p_floor);
    mpz_fdiv_q(N_p_floor,ppk->n,P_GF); // Here, we have P_GF = 2^(36 * 8 +1 ) -1
    mpz_sub_ui(N_p_floor,N_p_floor, 1 ); // We have N_p_floor = floor(N/P_GF - 1) (This is correct with the assumption that p = 2 ^32.

    for(int i = 0; i < _len; i++){
        paillier_plaintext_t* m;
        m = RandEncod(strShares[i], ShareSize, N_p_floor, P_GF);
        Shar_Ctxt[i] = paillier_enc(NULL, ppk, m, paillier_get_rand_devrandom);
        paillier_freeplaintext(m);
    }

    mpz_clear(P_GF);
    mpz_clear(N_p_floor);
    return Shar_Ctxt;
}

paillier_plaintext_t* HamDistAtmostT::RandEncod(string &share, size_t ShareSize, mpz_t N_p_floor, mpz_t P_GF)
{

    mpz_t a_i;
    mpz_init(a_i);
    auto& str_Shrs = share;
//    unsigned char a[ShareSize];
    char a[ShareSize];
//    unsigned long a[ShareSize];

    for (int j = 0; j <ShareSize ; ++j)
    {
        a[j] =  str_Shrs[j];
    }
    paillier_plaintext_t* m;
    m = (paillier_plaintext_t*) malloc(sizeof(paillier_plaintext_t));
    mpz_init(m->m);
    mpz_import(m->m, ShareSize, -1, 1, 0, 0, a);
//    mpz_import(m->m, ShareSize, -1, 1, 0, 0, &a[0]);

    gmp_randstate_t rand_i;
    gmp_randinit_mt(rand_i);
    mpz_urandomm (a_i, rand_i, N_p_floor); // Generates a random number in range [1, N_p_floor] in which N_p_floor =  floor(N/p - 1).
    mpz_mul(a_i, a_i, P_GF); //multiplying a_i with P_GF and set as m_Rand->m;
    mpz_add(m->m, m->m, a_i); // Computing m_Rand = m_i + a_i * p mod N.

    gmp_randclear(rand_i);
    mpz_clear(a_i);
    return m;
}



//RandomNumberGenerator & GlobalRNG()
//{
//    static CryptoPP::OFB_Mode<AES>::Encryption s_globalRNG;
//    return dynamic_cast<RandomNumberGenerator&>(s_globalRNG);
//}


 int HamDistAtmostT::Enc(paillier_pubkey_t* ppk, string &msg, char ctx_final[])
 {
     auto& str = msg;
     string s(begin(str), end(str));
     size_t Ctxt_Vec_size = s.size();
     assert(s==msg);
     size_t Ctxt_Byte_size =  PAILLIER_BITS_TO_BYTES(ppk->bits)*2;
     int EncBytesRslt =0;
//     char* ctx_final;
//     char* ctx_final =(char*) malloc ((Ctxt_Vec_size + 1 ) * sizeof(size_t) + Ctxt_Vec_size *  Ctxt_Byte_size);
     EncBytesRslt = PaillerWrapperFunctions::Enc_Byte_By_Byte(s, ppk, ctx_final);

     return 1;
 }


 int HamDistAtmostT::RegDec(paillier_pubkey_t* ppk, char ctx [], paillier_prvkey_t* psk,
                            size_t _len, string &DecryptedMsg)
 {
     int ret =0;
     paillier_plaintext_t* dec;
     vector<paillier_ciphertext_t*> vctx(_len);
     vctx = PaillerWrapperFunctions::Pail_Parse_Ctx_size(ppk, ctx);
     string DecreyptedCharByCha;
     for (int j = 0; j<_len; j++)
     {
         dec = paillier_dec(NULL, ppk, psk, vctx[j]);
         DecreyptedCharByCha += paillier_plaintext_to_str_NegOrd(dec);
         paillier_freeplaintext(dec);
     }
     DecryptedMsg = CryptoSymWrapperFunctions::Wrapper_unpad(DecreyptedCharByCha); //orig_typo TODO: make sure the correct input is added here perviously was orig_typo extract from encoded typo. It should be handled outside this fubnction

    ret =1;

    return 1;
 }




string HamDistAtmostT::CondEnc(paillier_pubkey_t* ppk,
                               char RlPwd_ctx_pull[],
                               string& typo,
                               string& payload,
                               size_t _len,
                               int threshold,
                               char ctx_final[])
{

     string seed = CryptoPP::IntToString(time(NULL));
     seed.resize(AES::DEFAULT_KEYLENGTH, ' '); //The defualt key length is 16
     CryptoPP::RandomPool rng;
     rng.IncorporateEntropy((CryptoPP::byte*)seed.data(), strlen(seed.data()));
     int shares = _len;
     const unsigned int CHID_LENGTH = 4;
     bool fail, pass;
     string cipherText, encoded;

    // size_t AECtxSize = 24; // for 128  bit, the output is 192 bit as the size of the EncryptedKey.
     size_t AECtxSize = 2 * KEYSIZE_BYTES + payload.size();

     size_t Ctxt_Vec_size =_len; //1 for the numeber of elemements, 2 for the AE and its lenght, and 2 * _len PaillerCtxt samples
     size_t Ctxt_Byte_size =  PAILLIER_BITS_TO_BYTES(ppk->bits)*2;
     memcpy(ctx_final, &Ctxt_Vec_size, sizeof(size_t));
     memcpy(ctx_final + sizeof(size_t), &AECtxSize, sizeof(size_t));
     memcpy(ctx_final + 2 * sizeof(size_t), &Ctxt_Byte_size, sizeof(size_t));
     /*
* Randomly selecting 16 bytes of secret and derive the AES key from it for Authenticated encryption.
* */

     std::string* EncrypteKey = new std::string[1];
     string b(AES::DEFAULT_KEYLENGTH, 0);
     PRNG.GenerateBlock((CryptoPP::byte*) b.data(), b.size());
     bool kEncCtxtRst;
     kEncCtxtRst = CryptoSymWrapperFunctions::Wrapper_AuthEncrypt(b, payload, EncrypteKey[0]);
     size_t sizeEncKey = EncrypteKey[0].size();
     assert(sizeEncKey == AECtxSize);


     memcpy(ctx_final + 3 * sizeof(size_t), EncrypteKey[0].c_str(),  sizeof(char) * sizeEncKey); //Appending the AECtxt to the begining of the ctxt vector.
     //    memcpy(ctx_final + 3 * sizeof(size_t), &EncrypteKey[0],  sizeof(char) * AECtxSize); //Appending the AECtxt to the begining of the ctxt vector.
     // free(EncrypteKey);
     delete[] EncrypteKey;


     size_t ShareSize = SSShareSize;
     string msg = CryptoSymWrapperFunctions::Wrapper_pad(typo,_len); //orig_typo TODO: make sure the correct input is added here perviously was orig_typo extract from encoded typo. It should be handled outside this fubnction
     vector<paillier_ciphertext_t*> vctx(_len);
     vector<paillier_ciphertext_t*> vctx1(_len); //Used for encrypting the chars of typo.
     vector<paillier_ciphertext_t*> vctx_Shrs(_len);
//    vector<paillier_ciphertext_t *> V_ctx_typo(_len);
     int VecSize;
     string Ctxt_0;

     vctx = PaillerWrapperFunctions::Pail_Parse_Ctx_size(ppk, RlPwd_ctx_pull); // Extracting the ctxt of each char of the original meesage using the parsing function desined in Paillier Wrapper functions.

     vctx1 = PaillerWrapperFunctions::Enc_Vec_Typo(msg, ppk);


     string message = CryptoSymWrapperFunctions::Wrapper_pad(typo,_len); // pad(typo);  TODO: Double check if we need to make sure that we need pad here?
     string Zero_secret = "0";

    CryptoPP::ChannelSwitch *channelSwitch;
    channelSwitch = NULLPTR;
    CryptoPP::ChannelSwitch *channelSwitch_Zero;
    channelSwitch_Zero = NULLPTR;
//        CryptoPP::StringSource source(message.c_str(), false, new CryptoPP::SecretSharing(rng, threshold, shares,
//                                                                                          channelSwitch = new CryptoPP::ChannelSwitch));
    CryptoPP::StringSource source(b, false,
                                  new CryptoPP::SecretSharing(rng, threshold, shares,
                                                              channelSwitch = new CryptoPP::ChannelSwitch, false));

    CryptoPP::StringSource source_Zero(Zero_secret, false, new CryptoPP::SecretSharing(rng, threshold, shares,
                                                                                       channelSwitch_Zero = new CryptoPP::ChannelSwitch,false)); //Genreating the shares for Zero: "0"



    vector<string> strShares(shares);
    vector<string> strShares_for_Enc(shares);
    vector<string> Plain_strShares(shares);
    CryptoPP::vector_member_ptrs<CryptoPP::StringSink> strSinks(shares);
    string channel;

    /*
    * Generating the shares for the zero part.
    * */

    vector<string> strShares_Zero(shares);
    vector<string> strShares_for_Enc_Zero(shares);
    vector<string> Plain_strShares_Zero(shares);
    CryptoPP::vector_member_ptrs<CryptoPP::StringSink> strSinks_Zero(shares);
    string channel_Zero;
    //*-*-*-*-*-*-*-*-*

    // ********** Create Shares for the AES secret information "b".
    for (unsigned int i = 0; i < shares; i++) {
        strSinks[i].reset(new CryptoPP::StringSink(strShares[i]));
        channel = CryptoPP::WordToString<word32>(i);
        strSinks[i]->Put((CryptoPP::byte*) channel.data(), CHID_LENGTH);
        channelSwitch->AddRoute(channel, *strSinks[i],DEFAULT_CHANNEL  ); //CryptoPP::BufferedTransformation::NULL_CHANNEL
    }
    source.PumpAll();


    // ********** Create and assigns the Shares for the zero part
    for (unsigned int i = 0; i < shares; i++) {
        strSinks_Zero[i].reset(new CryptoPP::StringSink(strShares_Zero[i]));
        // channel_Zero = CryptoPP::WordToString<uint16_t>(i);
        channel_Zero = CryptoPP::WordToString<word32>(i);
        strSinks_Zero[i]->Put((CryptoPP::byte*) channel_Zero.data(), CHID_LENGTH);
        // strSinks_Zero[i]->Put((CryptoPP::byte*) channel_Zero.data(), 1);
        channelSwitch_Zero->AddRoute(channel_Zero, *strSinks_Zero[i], DEFAULT_CHANNEL); //CryptoPP::BufferedTransformation::NULL_CHANNEL
    }
    source_Zero.PumpAll();

/*New Share of 0*/
    // shamir::init();//to initialise the library functions.Must be used to use the library.
    // scheme GF256SS(static_cast<int>(_len),threshold); //creating a scheme with 8 shares and 5 threshold.
    // shamir::shares* GF256_shares = GF256SS.createShares("0");



    for(unsigned int j=0; j<shares; j++ )
    {

        // std::string str_GF256_shares;
        // for(auto val:(*GF256_shares)[j]) {
        //     str_GF256_shares = std::to_string(static_cast<unsigned int>(val.y.num));
        // }
        CryptoPP::StringSink ss(strShares_for_Enc[j] );
        ss.Put((const CryptoPP::byte*)(strShares[j] + strShares_Zero[j]).data(),  (strShares[j] + strShares_Zero[j]).size(), false);
        // ss.Put((const CryptoPP::byte*)(strShares[j] + str_GF256_shares + " ").data(),  (strShares[j] + str_GF256_shares).size(), false);

        // int z_length =  str_GF256_shares.size();
        int z_length =  strShares_Zero.size();
        int M_length =  strShares[j].size();
    }
    vctx_Shrs = HamDistAtmostT::Enc_SecrtShr_V2(strShares_for_Enc, ppk, ShareSize, _len); // Encrypt the shares to extract a vector of ctxts elemets.


    for (int j = 0; j <_len ; j++) {
        paillier_ciphertext_t* Aux_Ctx;
        paillier_ciphertext_t* Aux_Ctx1;
        paillier_ciphertext_t* V_ctx_typo;
        paillier_plaintext_t *R;
        char* byteCtxt1;

        Aux_Ctx1 =paillier_create_enc_zero();
        Aux_Ctx = PaillerWrapperFunctions::Pail_Subtct(ppk, vctx[j], vctx1[j]);

        R = PaillerWrapperFunctions::Rand_Plain_Pail(ppk); //I need to describe a function to generate random number in plaintext.
//        mpz_powm(Aux_Ctx1->c, Aux_Ctx->c, R->m, ppk->n_squared);
        Aux_Ctx1 = PaillerWrapperFunctions::Pail_Mult_PtxCtx(ppk, Aux_Ctx, R);
        V_ctx_typo = PaillerWrapperFunctions::Pail_Add(ppk, vctx_Shrs[j], Aux_Ctx1); //TODO: Continue using the functions which will be defined in the Paillier Wrapper function.

        byteCtxt1 = (char*)paillier_ciphertext_to_bytes(Ctxt_Byte_size, V_ctx_typo);//TODO: Temproray
//        byteCtxt1 = (char*)paillier_ciphertext_to_bytes(Ctxt_Byte_size, vctx_Shrs[j]);
        memcpy(ctx_final + 3 * sizeof(size_t) + AECtxSize + j * Ctxt_Byte_size, byteCtxt1, Ctxt_Byte_size);

        paillier_freeciphertext(Aux_Ctx);
        paillier_freeciphertext(Aux_Ctx1);
        paillier_freeciphertext(V_ctx_typo);
        paillier_freeplaintext(R);
//        free(byteCtxt1);
    }


//    ctx_final[3 * sizeof(size_t) + AECtxSize + _len * Ctxt_Byte_size] = '\0';
    for (int i = 0; i< _len; i++)
    {
        paillier_freeciphertext(vctx[i]);
        paillier_freeciphertext(vctx1[i]);
        paillier_freeciphertext(vctx_Shrs[i]);
    }
    return "EncrypteKey[0]";
//    return ctx_final;
}





// string HamDistAtmostT::CondEnc(paillier_pubkey_t* ppk,
//                                char RlPwd_ctx_pull[],
//                                string& typo,
//                                string& payload,
//                                size_t _len,
//                                int threshold,
//                                char ctx_final[])
// {
//
//      string seed = CryptoPP::IntToString(time(NULL));
//      seed.resize(AES::DEFAULT_KEYLENGTH, ' '); //The defualt key length is 16
//      CryptoPP::RandomPool rng;
//      rng.IncorporateEntropy((CryptoPP::byte*)seed.data(), strlen(seed.data()));
//      int shares = _len;
//      const unsigned int CHID_LENGTH = 4;
//      bool fail, pass;
//      string cipherText, encoded;
//
//      size_t AECtxSize = 2 * KEYSIZE_BYTES + payload.size();
//
//      size_t Ctxt_Vec_size =_len; //1 for the numeber of elemements, 2 for the AE and its lenght, and 2 * _len PaillerCtxt samples
//      size_t Ctxt_Byte_size =  PAILLIER_BITS_TO_BYTES(ppk->bits)*2;
//      memcpy(ctx_final, &Ctxt_Vec_size, sizeof(size_t));
//      memcpy(ctx_final + sizeof(size_t), &AECtxSize, sizeof(size_t));
//      memcpy(ctx_final + 2 * sizeof(size_t), &Ctxt_Byte_size, sizeof(size_t));
//      /*
// * Randomly selecting 16 bytes of secret and derive the AES key from it for Authenticated encryption.
// * */
//
//      std::string* EncrypteKey = new std::string[1];
//      string b(AES::DEFAULT_KEYLENGTH, 0);
//      PRNG.GenerateBlock((CryptoPP::byte*) b.data(), b.size());
//      bool kEncCtxtRst;
//      kEncCtxtRst = CryptoSymWrapperFunctions::Wrapper_AuthEncrypt(b, payload, EncrypteKey[0]);
//      size_t sizeEncKey = EncrypteKey[0].size();
//      assert(sizeEncKey == AECtxSize);
//
//
//      memcpy(ctx_final + 3 * sizeof(size_t), EncrypteKey[0].c_str(),  sizeof(char) * sizeEncKey); //Appending the AECtxt to the begining of the ctxt vector.
//      delete[] EncrypteKey;
//
//
//      size_t ShareSize = SSShareSize;
//      string msg = CryptoSymWrapperFunctions::Wrapper_pad(typo,_len); //orig_typo TODO: make sure the correct input is added here perviously was orig_typo extract from encoded typo. It should be handled outside this fubnction
//      vector<paillier_ciphertext_t*> vctx(_len);
//      vector<paillier_ciphertext_t*> vctx1(_len); //Used for encrypting the chars of typo.
//      vector<paillier_ciphertext_t*> vctx_Shrs(_len);
// //    vector<paillier_ciphertext_t *> V_ctx_typo(_len);
//      int VecSize;
//      string Ctxt_0;
//
//      vctx = PaillerWrapperFunctions::Pail_Parse_Ctx_size(ppk, RlPwd_ctx_pull); // Extracting the ctxt of each char of the original meesage using the parsing function desined in Paillier Wrapper functions.
//
//      vctx1 = PaillerWrapperFunctions::Enc_Vec_Typo(msg, ppk);
//
//
//      string message = CryptoSymWrapperFunctions::Wrapper_pad(typo,_len); // pad(typo);  TODO: Double check if we need to make sure that we need pad here?
//      string Zero_secret = "0";
//
//
//     CryptoPP::ChannelSwitch *channelSwitch;
//     channelSwitch = NULLPTR;
//     CryptoPP::ChannelSwitch *channelSwitch_Zero;
//     channelSwitch_Zero = NULLPTR;
// //        CryptoPP::StringSource source(message.c_str(), false, new CryptoPP::SecretSharing(rng, threshold, shares,
// //                                                                                          channelSwitch = new CryptoPP::ChannelSwitch));
//     CryptoPP::StringSource source(b, false,
//                                   new CryptoPP::SecretSharing(rng, threshold, shares,
//                                                               channelSwitch = new CryptoPP::ChannelSwitch, false));
//
//     CryptoPP::StringSource source_Zero(Zero_secret, false, new CryptoPP::SecretSharing(rng, threshold, shares,
//                                                                                        channelSwitch_Zero = new CryptoPP::ChannelSwitch,false)); //Genreating the shares for Zero: "0"
//
//
//
//     vector<string> strShares(shares);
//     vector<string> strShares_for_Enc(shares);
//     vector<string> Plain_strShares(shares);
//     CryptoPP::vector_member_ptrs<CryptoPP::StringSink> strSinks(shares);
//     string channel;
//
//     /*
//     * Generating the shares for the zero part.
//     * */
//
//     vector<string> strShares_Zero(shares);
//     vector<string> strShares_for_Enc_Zero(shares);
//     vector<string> Plain_strShares_Zero(shares);
//     CryptoPP::vector_member_ptrs<CryptoPP::StringSink> strSinks_Zero(shares);
//     string channel_Zero;
//     //*-*-*-*-*-*-*-*-*
//
//     // ********** Create Shares for the AES secret information "b".
//     for (unsigned int i = 0; i < shares; i++) {
//         strSinks[i].reset(new CryptoPP::StringSink(strShares[i]));
//         channel = CryptoPP::WordToString<word32>(i);
//         strSinks[i]->Put((CryptoPP::byte*) channel.data(), CHID_LENGTH);
//         channelSwitch->AddRoute(channel, *strSinks[i],DEFAULT_CHANNEL  ); //CryptoPP::BufferedTransformation::NULL_CHANNEL
//     }
//     source.PumpAll();
//
//
//     // ********** Create and assigns the Shares for the zero part
//     for (unsigned int i = 0; i < shares; i++) {
//         strSinks_Zero[i].reset(new CryptoPP::StringSink(strShares_Zero[i]));
//         channel_Zero = CryptoPP::WordToString<word32>(i);
//         strSinks_Zero[i]->Put((CryptoPP::byte*) channel_Zero.data(), CHID_LENGTH);
//         channelSwitch_Zero->AddRoute(channel_Zero, *strSinks_Zero[i], DEFAULT_CHANNEL); //CryptoPP::BufferedTransformation::NULL_CHANNEL
//     }
//     source_Zero.PumpAll();
//
//     /*Transferring the shares to another aux array for feeding it to the encryption fuacntion*/
//
//     for(unsigned int j=0; j<shares; j++ )
//     {
//         CryptoPP::StringSink ss(strShares_for_Enc[j] );
//         ss.Put((const CryptoPP::byte*)(strShares[j] + strShares_Zero[j]).data(),  (strShares[j] + strShares_Zero[j]).size(), false);
//
//     }
// //    int out = Enc_SecrtShr(strShares_for_Enc,  ppk, vctx_Shrs, ShareSize, _len); // Encrypt the shares to extract a vector of ctxts elemets.
//     vctx_Shrs = HamDistAtmostT::Enc_SecrtShr_V2(strShares_for_Enc, ppk, ShareSize, _len); // Encrypt the shares to extract a vector of ctxts elemets.
//
//
//
// //    char* ctx_final =(char*) malloc (  3 * sizeof(size_t) + AECtxSize + _len *  Ctxt_Byte_size);
//
//
//
//     for (int j = 0; j <_len ; j++) {
//         paillier_ciphertext_t* Aux_Ctx;
//         paillier_ciphertext_t* Aux_Ctx1;
//         paillier_ciphertext_t* V_ctx_typo;
//         paillier_plaintext_t *R;
//         char* byteCtxt1;
//
//         Aux_Ctx1 =paillier_create_enc_zero();
//         Aux_Ctx = PaillerWrapperFunctions::Pail_Subtct(ppk, vctx[j], vctx1[j]);
//
//         R = PaillerWrapperFunctions::Rand_Plain_Pail(ppk); //I need to describe a function to generate random number in plaintext.
// //        mpz_powm(Aux_Ctx1->c, Aux_Ctx->c, R->m, ppk->n_squared);
//         Aux_Ctx1 = PaillerWrapperFunctions::Pail_Mult_PtxCtx(ppk, Aux_Ctx, R);
//         V_ctx_typo = PaillerWrapperFunctions::Pail_Add(ppk, vctx_Shrs[j], Aux_Ctx1); //TODO: Continue using the functions which will be defined in the Paillier Wrapper function.
//
//         byteCtxt1 = (char*)paillier_ciphertext_to_bytes(Ctxt_Byte_size, V_ctx_typo);//TODO: Temproray
// //        byteCtxt1 = (char*)paillier_ciphertext_to_bytes(Ctxt_Byte_size, vctx_Shrs[j]);
//         memcpy(ctx_final + 3 * sizeof(size_t) + AECtxSize + j * Ctxt_Byte_size, byteCtxt1, Ctxt_Byte_size);
//
//         paillier_freeciphertext(Aux_Ctx);
//         paillier_freeciphertext(Aux_Ctx1);
//         paillier_freeciphertext(V_ctx_typo);
//         paillier_freeplaintext(R);
// //        free(byteCtxt1);
//     }
//
//
// //    ctx_final[3 * sizeof(size_t) + AECtxSize + _len * Ctxt_Byte_size] = '\0';
//     for (int i = 0; i< _len; i++)
//     {
//         paillier_freeciphertext(vctx[i]);
//         paillier_freeciphertext(vctx1[i]);
//         paillier_freeciphertext(vctx_Shrs[i]);
//     }
//     return "EncrypteKey[0]";
// //    return ctx_final;
// }
//
//



tuple<vector<paillier_ciphertext_t*>, string>  HamDistAtmostT::Pail_Parse_Ctx_size_AECtx(paillier_pubkey_t* ppk,
                                                                     char* ctx)
{

    tuple<vector<paillier_ciphertext_t*>, string> tuple_out;
    size_t size;
    memcpy(&size, ctx , sizeof(size_t));
    size_t AE_Ctx_size;
    memcpy(&AE_Ctx_size, ctx  + sizeof(size_t), sizeof(size_t));
    size_t Ctxt_Element_Size;

    string CtxtAEStr;
//    string* CtxtAEStr = (string*) malloc(AE_Ctx_size);
//    string* CtxtAEStr = new string("");
    memcpy(&CtxtAEStr, ctx + (size + 1) * sizeof(size_t), AE_Ctx_size);
//    memcpy(CtxtAEStr, ctx + (size + 1) * sizeof(size_t), AE_Ctx_size);



//    tuple<vector<paillier_ciphertext_t*>, string> Output_Tuple;
//    string CTXAE = CtxtAEStr;
//    string CTXAE = CtxtAEStr[0];
//    assert(CTXAE == CtxtAEStr);
//    CtxAE= CtxtAEStr;
//    size_t* msg_size =(size_t*) malloc(sizeof(size_t));
//    free(msg_size);


//    size_t* Elements_Size =(size_t*) malloc(sizeof(size_t));
//    free(Elements_Size);

//    size_t* AECtxtSize =(size_t*) malloc(sizeof(size_t));
//    free((size_t*)AECtxtSize);

    size_t Accum_ptr = 0;
//    memcpy(&msg_size, ctx , sizeof(size_t));
//    const size_t size = (size_t) msg_size;
//    memcpy(&AECtxtSize, ctx  + sizeof(size_t), sizeof(size_t));
//    const size_t AE_Ctx_size = (size_t) AECtxtSize;

//    string* CtxAE_Char = (string*) malloc(AE_Ctx_size);

//    memcpy(CtxAE_Char, ctx + (size + 1) * sizeof(size_t), AE_Ctx_size);
//    CtxAE = CtxAE_Char[0];
//    free(CtxAE_Char);
    Accum_ptr =  Accum_ptr + AE_Ctx_size;

    vector<paillier_ciphertext_t*> Vect_Ctx(size-1  );


//    char *byteCtxt1 = new char [PAILLIER_BITS_TO_BYTES(ppk->bits)*2];

//    delete [] byteCtxt1;
//    char byteCtxt1[PAILLIER_BITS_TO_BYTES(ppk->bits)*2];
//    void* byteCtxt1 = malloc(PAILLIER_BITS_TO_BYTES(ppk->bits)*2);
    char* byteCtxt1 = (char*)malloc(PAILLIER_BITS_TO_BYTES(ppk->bits)*2);

//    paillier_ciphertext_t* ctxt1;
    for(int i = 0; i< size-1; i++ )
    {
//
        memcpy(&Ctxt_Element_Size, ctx + (i + 2) * sizeof(size_t), sizeof(size_t));
//        size_t Ctxt_Elemnt_Size = (size_t) Elements_Size;
        memcpy(byteCtxt1,  ctx + (1 + size) * sizeof(size_t) + Accum_ptr, Ctxt_Element_Size);
        Accum_ptr = Accum_ptr + Ctxt_Element_Size;
        Vect_Ctx[i] = paillier_ciphertext_from_bytes((void*)byteCtxt1, PAILLIER_BITS_TO_BYTES(ppk->bits)*2);

//        Vect_Ctx[i]  = ctxt1;
    }

//    Output_Tuple =  make_tuple(Vect_Ctx,CtxtAEStr);

//    for(int i =0; i< size-1; i++ )
//    {
//        paillier_freeciphertext(Vect_Ctx[i]);
//    }
    tuple_out = make_tuple(Vect_Ctx,CtxtAEStr);
    //TODO Free the variables
    free(byteCtxt1);
    for (int i=0; i< size-1; i++)
    {
        paillier_freeciphertext(Vect_Ctx[i]);
    }
//    free(ctx);
//    free(&CtxtAEStr[0]);
//    free(CtxtAEStr);
//    delete CtxtAEStr;
    return tuple_out;
}


int HamDistAtmostT::Pail_Parse_Ctx_size_AECtx2(paillier_pubkey_t* ppk,
                                            char* ctx, string& CtxtAEStr,
                                            vector<paillier_ciphertext_t*> &Vect_Ctx)
{

//    tuple<vector<paillier_ciphertext_t*>, string> tuple_out;
    size_t size;
    memcpy(&size, ctx , sizeof(size_t));
    size_t AE_Ctx_size;
    memcpy(&AE_Ctx_size, ctx  + sizeof(size_t), sizeof(size_t));
    size_t Ctxt_Element_Size;
    memcpy(&Ctxt_Element_Size, ctx +  2 * sizeof(size_t), sizeof(size_t));

    // cout << "PayloadCtxtSize = "<<AE_Ctx_size<<" \n" << endl;
    // cout << Ctxt_Element_Size << endl;


//    void* vp = malloc (24);
//    memcpy(vp, ctx + 3 * sizeof(size_t), 24);
//    std::string *sp = static_cast<std::string*>(vp);
//    CtxtAEStr = *sp;
//    delete sp;
     CryptoPP::StringSink ss(CtxtAEStr);
     std::string* CtxtAEStrPre = new std::string[1];
     CtxtAEStrPre[0].resize(AE_Ctx_size );
     memcpy(&CtxtAEStrPre[0][0], ctx + 3 * sizeof(size_t),  AE_Ctx_size * sizeof(char)); //Correct
     // memcpy(&CtxtAEStr[0], ctx + 3 * sizeof(size_t),  AE_Ctx_size * sizeof(char)); //Correct
     // cout << "Dec pre Parsing  ...\n";

    ss.Put((const CryptoPP::byte*)CtxtAEStrPre[0].data(),  CtxtAEStrPre[0].size(), false);
//    string A = CtxtAEStrPre[0];
//    CtxtAEStr = CtxtAEStrPre[0];
    // free(CtxtAEStrPre);
     delete [] CtxtAEStrPre;


//    byte a[AE_Ctx_size];
//    memcpy(a, ctx + 3 * sizeof(size_t),  AE_Ctx_size); //Correct
//    CryptoPP::StringSource ss(a,AE_Ctx_size, true /*pumpAll*/,new StringSink(CtxtAEStr)); // StringSink



//    string* CtxtAEStrPre = (string*) malloc(sizeof(char) * 24);
//    memcpy(&CtxtAEStrPre[0], ctx + (3 * sizeof(size_t)), sizeof(char) * 24);


//    memcpy(&CtxtAEStr, ctx + 3 * sizeof(size_t), sizeof(char) * 24);
//    CtxtAEStr = CtxtAEStrPre[0];

//    memcpy(&CtxtAEStr, &CtxtAEStrPre[0], AE_Ctx_size);
//    CtxtAEStr = CtxtAEStrPre[0];
//    free(CtxtAEStrPre);
//    CtxtAEStr = &CtxtAEStrPre[0];
    size_t Accum_ptr = 0;

    Accum_ptr =  Accum_ptr + AE_Ctx_size;

//    vector<paillier_ciphertext_t*> Vect_Ctx(size-1  );

    char* byteCtxt1 = (char*)malloc(PAILLIER_BITS_TO_BYTES(ppk->bits)*2);
//    void* byteCtxt = malloc(PAILLIER_BITS_TO_BYTES(ppk->bits)*2);

    for(int i = 0; i< size; i++ )
    {
//
//        memcpy(&Ctxt_Element_Size, ctx + (i + 2) * sizeof(size_t), sizeof(size_t));
//        size_t Ctxt_Elemnt_Size = (size_t) Elements_Size;
//        memcpy(byteCtxt1,  ctx + (1 + size) * sizeof(size_t) + Accum_ptr, Ctxt_Element_Size);
//        memcpy(byteCtxt1,  ctx + (1 + size) * sizeof(size_t) + Accum_ptr, Ctxt_Element_Size);
        memcpy(byteCtxt1,  ctx + 3 * sizeof(size_t) + Accum_ptr, Ctxt_Element_Size);

        Accum_ptr = Accum_ptr + Ctxt_Element_Size;
//        memcpy(&Vect_Ctx[i], paillier_ciphertext_from_bytes((void*)byteCtxt1, PAILLIER_BITS_TO_BYTES(ppk->bits)*2), PAILLIER_BITS_TO_BYTES(ppk->bits)*2);
//        Vect_Ctx[i] = paillier_ciphertext_from_bytes((void*)byteCtxt1, PAILLIER_BITS_TO_BYTES(ppk->bits)*2);
        Vect_Ctx[i] = paillier_ciphertext_from_bytes(byteCtxt1, PAILLIER_BITS_TO_BYTES(ppk->bits)*2);

//        Vect_Ctx[i]  = ctxt1;
    }



    //TODO Free the variables
    free(byteCtxt1);
//    free(ctx);
//    free(ctx);
//    free(&CtxtAEStr[0]);
//    free(CtxtAEStr);
//    delete CtxtAEStr;
    return 1;
}

int HamDistAtmostT::CondDec_NonSmallFieldCheck(paillier_pubkey_t* ppk,
                              char typo_ctx [],
                              paillier_prvkey_t* psk,
                              int threshold,
                              string &recovered,
                              size_t _len)
{
    int ret =0;
    string CtxAE;
    vector<paillier_ciphertext_t*> V_ctx_typo(_len);
    int pars_rslt =0;


    pars_rslt = HamDistAtmostT::Pail_Parse_Ctx_size_AECtx2(ppk, typo_ctx, CtxAE, V_ctx_typo );


    vector<string> strShares_Zero(_len);
    vector<string> strShares_Main(_len);
    paillier_plaintext_t* dec;
    const unsigned int CHID_LENGTH = 4;


    mpz_t P_GF;
    mpz_init(P_GF);
     size_t ShareSize =  SSShareSize;
    int max_power_int = (ShareSize * 8) + 1;
    // int max_power_int = (ShareSize * 5) + 1;
    mpz_ui_pow_ui(P_GF, 2, max_power_int);
    mpz_sub_ui(P_GF, P_GF, 1); // computing the value of P_GF based on the size of the input value.
    void* ByteDec;
    for  (int j = 0; j <_len; j++)
    {
        dec = paillier_dec(NULL, ppk, psk, V_ctx_typo[j]);
        mpz_mod(dec->m, dec->m, P_GF); // The DRand function which transfers which cancelouts the term a_i * GF_P which was added previously.
        //Jsut now we need to export the mpz_t element to byte stream which are elements of the secret sharing scheme.

        vector<CryptoPP::byte> ab (ShareSize);
//        vector<char> ab (ShareSize);
//        string* ab = (string*) malloc(ShareSize);
//        string s;
        ByteDec = paillier_plaintext_to_bytes_NegOrd(ShareSize, dec);
        memcpy(&ab[0],ByteDec, ShareSize);
//        string s  = ab[0];
//        ab = PaillerWrapperFunctions::mpz_to_vector(dec->m, ShareSize);
        string s(ab.begin(), ab.end());
        strShares_Main[j] =  s.substr (0,20);
        // strShares_Zero[j] =  s.substr (20,8);
        strShares_Zero[j] =  s.substr (20,8);

        free(ByteDec);
//        free(ab);
        paillier_freeplaintext(dec);
//        paillier_freeciphertext(V_ctx_typo[j]);

    }



    vector<int> Valid_selected;
    string MainRecoveredSecret;
    string plaintext_rcv;
    int rsltRcVr;

    vector<int> v(_len);

    v = HamDistAtmostT::GnereateVectorOfIntegeres(_len);
    rsltRcVr = HamDistAtmostT::generatesubsets_NonSmallFieldCheck(strShares_Main, CtxAE, MainRecoveredSecret,
                                           plaintext_rcv, v,0,threshold, Valid_selected);

    bool AEReslt = false;
//    HamDistAtmostT::ToConstStringConvert(CtxAE2);
    /*I have modified the function for handling the following part*/

     // if (rsltRcVr == 1)
     // {
     //     AEReslt = CryptoSymWrapperFunctions::Wrapper_AuthDecrypt(MainRecoveredSecret, CtxAE,plaintext_rcv );
     // }



//    AEReslt = CryptoSymWrapperFunctions::Wrapper_AuthDecrypt(MainRecoverShare, CtxAE,recovered );

//    AEReslt = CryptoSymWrapperFunctions::Wrapper_AuthDecrypt(MainRecoverShare, std::get<1>(ParsedCtxt),plaintext_rcv );

    mpz_clear(P_GF);
    if (rsltRcVr == 1)
    {
        recovered = plaintext_rcv;
        ret =1;
    }
    else
    {
//        recovered = ""; //(The original agreed i one)
        // recovered = plaintext_rcv;
        recovered = "The predicate is not holding";
        ret = -1;
    }

//    for (int i=0; i< _len; i++)
//    {
//        paillier_freeciphertext(V_ctx_typo[i]);
//    }
//    paillier_freeplaintext(dec);


    return rsltRcVr;
}

int HamDistAtmostT::CondDec_SmallGF256(paillier_pubkey_t* ppk,
                              char typo_ctx [],
                              paillier_prvkey_t* psk,
                              int threshold,
                              string &recovered,
                              size_t _len)
{
     int ret =0;
     string CtxAE;
     vector<paillier_ciphertext_t*> V_ctx_typo(_len);
     int pars_rslt =0;


     pars_rslt = HamDistAtmostT::Pail_Parse_Ctx_size_AECtx2(ppk, typo_ctx, CtxAE, V_ctx_typo );
//    std::string CtxAE;
//    CtxAE = CtxAE2;
//    memcpy(&CtxAE, &CtxAE2, 24);

//    CtxAE2.clear();
//    memcpy(&CtxAE, &CtxAE2[0], CtxAE2.size() );

     vector<string> strShares_Zero(_len);
     vector<string> strShares_Main(_len);
    shares* GF256_shares = new shares(_len);
    point temp;

     paillier_plaintext_t* dec;
     const unsigned int CHID_LENGTH = 4;


     mpz_t P_GF;
     mpz_init(P_GF);
     size_t ShareSize = SSShareSize;
     int max_power_int = (ShareSize * 8) + 1;
    // int max_power_int = (ShareSize * 5) + 1;
     mpz_ui_pow_ui(P_GF, 2, max_power_int);
     mpz_sub_ui(P_GF, P_GF, 1); // computing the value of P_GF based on the size of the input value.
     void* ByteDec;
     for  (int j = 0; j <_len; j++)
     {
        dec = paillier_dec(NULL, ppk, psk, V_ctx_typo[j]);
        mpz_mod(dec->m, dec->m, P_GF); // The DRand function which transfers which cancelouts the term a_i * GF_P which was added previously.
        //Jsut now we need to export the mpz_t element to byte stream which are elements of the secret sharing scheme.

        vector<CryptoPP::byte> ab (ShareSize);
//        vector<char> ab (ShareSize);
//        string* ab = (string*) malloc(ShareSize);
//        string s;
        ByteDec = paillier_plaintext_to_bytes_NegOrd(ShareSize, dec);
        memcpy(&ab[0],ByteDec, ShareSize);
//        string s  = ab[0];
//        ab = PaillerWrapperFunctions::mpz_to_vector(dec->m, ShareSize);
        string s(ab.begin(), ab.end());
        strShares_Main[j] =  s.substr (0,20);
        // strShares_Zero[j] =  s.substr (20,8);
         // strShares_Zero[j] =  s.substr (20,8);
         strShares_Zero[j] =  s.substr (20, 3);


         scheme GF256_SSscheme(_len,threshold);
         unsigned char c;
         temp.x = GF256::byte(j+1);
         try {
             c =static_cast<unsigned char>(static_cast<unsigned int>(std::stoi(strShares_Zero[j])) % 256);
         } catch (const std::invalid_argument& e) {
             // Generate a random number between 0 and 255
             std::srand(std::time(0));
             c = std::rand() % 256;
             // std::cerr << "Invalid argument: The string does not contain a valid integer. Error: " << e.what() << std::endl;
         } catch (const std::out_of_range& e) {
             std::srand(std::time(0));
             c = std::rand() % 256;
             // std::cerr << "Out of range: The number is too large to fit in an int. Error: " << e.what() << std::endl;
         }

         temp.y = GF256::byte(static_cast<unsigned char>(c));
         (*GF256_shares)[j].push_back(temp);
         }

        free(ByteDec);
//        free(ab);
        paillier_freeplaintext(dec);
//        paillier_freeciphertext(V_ctx_typo[j]);




    vector<int> Valid_selected;
    string MainRecoveredSecret;
    string plaintext_rcv;
    int rsltRcVr =0;

    vector<int> v(_len);
    vector<int> ValidSelected(threshold);
    v = HamDistAtmostT::GnereateVectorOfIntegeres(_len);


    // rsltRcVr = HamDistAtmostT::generatesubsets(strShares_Main, strShares_Zero,  CtxAE, MainRecoveredSecret,
                                           // plaintext_rcv, v,0,threshold, Valid_selected, ValidSelected);

    rsltRcVr = HamDistAtmostT::generatesubsets_GF256(strShares_Main, GF256_shares,  CtxAE, MainRecoveredSecret,
                                           plaintext_rcv, v,0,threshold, Valid_selected, ValidSelected, _len);

//    string ciphertext_rcv;
    // bool AEReslt;
//    HamDistAtmostT::ToConstStringConvert(CtxAE2);
    /*I have modified the function for handling the following part*/

    // AEReslt = CryptoSymWrapperFunctions::Wrapper_AuthDecrypt(MainRecoveredSecret, CtxAE,plaintext_rcv );


    mpz_clear(P_GF);
    if (rsltRcVr == 1)
    {
        recovered = plaintext_rcv;
        ret =1;
    }
    else
    {
//        recovered = ""; //(The original agreed i one)
        recovered = plaintext_rcv;
        ret = -1;
    }

//    for (int i=0; i< _len; i++)
//    {
//        paillier_freeciphertext(V_ctx_typo[i]);
//    }
//    paillier_freeplaintext(dec);


    return ret;
}



int HamDistAtmostT::CondDec(paillier_pubkey_t* ppk,
                              char typo_ctx [],
                              paillier_prvkey_t* psk,
                              int threshold,
                              string &recovered,
                              size_t _len)
{
     int ret =0;
     string CtxAE;
     vector<paillier_ciphertext_t*> V_ctx_typo(_len);
     int pars_rslt =0;


     pars_rslt = HamDistAtmostT::Pail_Parse_Ctx_size_AECtx2(ppk, typo_ctx, CtxAE, V_ctx_typo );
//    std::string CtxAE;
//    CtxAE = CtxAE2;
//    memcpy(&CtxAE, &CtxAE2, 24);

//    CtxAE2.clear();
//    memcpy(&CtxAE, &CtxAE2[0], CtxAE2.size() );

     vector<string> strShares_Zero(_len);
     vector<string> strShares_Main(_len);

     paillier_plaintext_t* dec;
     const unsigned int CHID_LENGTH = 4;


     mpz_t P_GF;
     mpz_init(P_GF);
     size_t ShareSize = SSShareSize;
     int max_power_int = (ShareSize * 8) + 1;
    // int max_power_int = (ShareSize * 5) + 1;
     mpz_ui_pow_ui(P_GF, 2, max_power_int);
     mpz_sub_ui(P_GF, P_GF, 1); // computing the value of P_GF based on the size of the input value.
     void* ByteDec;
     for  (int j = 0; j <_len; j++)
     {
        dec = paillier_dec(NULL, ppk, psk, V_ctx_typo[j]);
        mpz_mod(dec->m, dec->m, P_GF); // The DRand function which transfers which cancelouts the term a_i * GF_P which was added previously.
        //Jsut now we need to export the mpz_t element to byte stream which are elements of the secret sharing scheme.

        vector<CryptoPP::byte> ab (ShareSize);
//        vector<char> ab (ShareSize);
//        string* ab = (string*) malloc(ShareSize);
//        string s;
        ByteDec = paillier_plaintext_to_bytes_NegOrd(ShareSize, dec);
        memcpy(&ab[0],ByteDec, ShareSize);
//        string s  = ab[0];
//        ab = PaillerWrapperFunctions::mpz_to_vector(dec->m, ShareSize);
        string s(ab.begin(), ab.end());
        strShares_Main[j] =  s.substr (0,20);
        // strShares_Zero[j] =  s.substr (20,8);
         // strShares_Zero[j] =  s.substr (20,8);
         strShares_Zero[j] =  s.substr (20, 8);
         }

        free(ByteDec);
//        free(ab);
        paillier_freeplaintext(dec);
//        paillier_freeciphertext(V_ctx_typo[j]);




    vector<int> Valid_selected;
    string MainRecoveredSecret;
    string plaintext_rcv;
    int rsltRcVr =0;

    vector<int> v(_len);
    vector<int> ValidSelected(threshold);
    v = HamDistAtmostT::GnereateVectorOfIntegeres(_len);


    rsltRcVr = HamDistAtmostT::generatesubsets(strShares_Main, strShares_Zero,  CtxAE, MainRecoveredSecret,
                                           plaintext_rcv, v,0,threshold, Valid_selected, ValidSelected);

    // rsltRcVr = HamDistAtmostT::generatesubsets_GF256(strShares_Main, GF256_shares,  CtxAE, MainRecoveredSecret,
                                           // plaintext_rcv, v,0,threshold, Valid_selected, ValidSelected, _len);

//    string ciphertext_rcv;
    // bool AEReslt;
//    HamDistAtmostT::ToConstStringConvert(CtxAE2);
    /*I have modified the function for handling the following part*/

    // AEReslt = CryptoSymWrapperFunctions::Wrapper_AuthDecrypt(MainRecoveredSecret, CtxAE,plaintext_rcv );


    mpz_clear(P_GF);
    if (rsltRcVr == 1)
    {
        recovered = plaintext_rcv;
        ret =1;
    }
    else
    {
//        recovered = ""; //(The original agreed i one)
        recovered = plaintext_rcv;
        ret = -1;
    }

//    for (int i=0; i< _len; i++)
//    {
//        paillier_freeciphertext(V_ctx_typo[i]);
//    }
//    paillier_freeplaintext(dec);


    return ret;
}


int HamDistAtmostT::CondDec_2dif(paillier_pubkey_t* ppk,
                              char typo_ctx [],
                              paillier_prvkey_t* psk,
                              int threshold,
                              string &recovered,
                              size_t _len)
 {
     int ret =0;
     string CtxAE;
     vector<paillier_ciphertext_t*> V_ctx_typo(_len);
     int pars_rslt =0;


     pars_rslt = HamDistAtmostT::Pail_Parse_Ctx_size_AECtx2(ppk, typo_ctx, CtxAE, V_ctx_typo );

     vector<string> strShares_Zero(_len);
     vector<string> strShares_Main(_len);
     paillier_plaintext_t* dec;
     const unsigned int CHID_LENGTH = 4;


     mpz_t P_GF;
     mpz_init(P_GF);
     size_t ShareSize = SSShareSize;

     int max_power_int = (ShareSize * 8) + 1;
     mpz_ui_pow_ui(P_GF, 2, max_power_int);
     mpz_sub_ui(P_GF, P_GF, 1); // computing the value of P_GF based on the size of the input value.
     void* ByteDec;
     for  (int j = 0; j <_len; j++)
     {
         dec = paillier_dec(NULL, ppk, psk, V_ctx_typo[j]);
         mpz_mod(dec->m, dec->m, P_GF); // The DRand function which transfers which cancelouts the term a_i * GF_P which was added previously.
         //Jsut now we need to export the mpz_t element to byte stream which are elements of the secret sharing scheme.

         vector<CryptoPP::byte> ab (ShareSize);

         ByteDec = paillier_plaintext_to_bytes_NegOrd(ShareSize, dec);
         memcpy(&ab[0],ByteDec, ShareSize);
         string s(ab.begin(), ab.end());
         strShares_Main[j] =  s.substr (0,20);
         strShares_Zero[j] =  s.substr (20,8);

         free(ByteDec);
         paillier_freeplaintext(dec);
     }

     vector<int> Valid_selected;
     string MainRecoveredSecret;
     string plaintext_rcv;
     int rsltRcVr;

     vector<int> v(_len);
     vector<int> ValidSelected;

     v = HamDistAtmostT::GnereateVectorOfIntegeres(_len);


     for (int i = 1; i<_len; i += 2)
     {
         vector<int> selected;
         for (int j = 0; j< _len; j++)
         {
             if(j != i && j != i-1)
             {
                 selected.push_back(j);
             }
         }
         bool pass;
         pass = HamDistAtmostT::TestIfTheSahreAreValid(strShares_Zero, threshold, selected );//For the optimized solution
         if (pass)
         {
             string recoverTheMainSecret;
             HamDistAtmostT::RecoverSecretFromValidShares (strShares_Main, threshold, selected, recoverTheMainSecret );
             size_t key_size = recoverTheMainSecret.size();
             //            recoveredMainSecret = recoverTheMainSecret;

             CryptoPP::StringSink ss_recoveredMainSecret(MainRecoveredSecret);
             ss_recoveredMainSecret.Put((const CryptoPP::byte*)recoverTheMainSecret.data(),  recoverTheMainSecret.size(), false);


             bool AEReslt;

             AEReslt = CryptoSymWrapperFunctions::Wrapper_AuthDecrypt(MainRecoveredSecret, CtxAE,plaintext_rcv );
             mpz_clear(P_GF);
             if (AEReslt == true)
             {
                 recovered = plaintext_rcv;
                 ret =1;
             }
             return ret;
         }
     }



     for(int k = 2; k< _len; k++)
         {
             vector<int> selected;
             int end = (k% 2==0)? k-1: k-2;
             for(int i = 0; i<end; i++)
             {

                 for(int j =0; j<_len; j++)
                 {
                     if (j != i && j != k) selected.push_back(j);
                 }
             }
             bool pass;
             pass = HamDistAtmostT::TestIfTheSahreAreValid(strShares_Zero, threshold, selected );//For the optimized solution
             if (pass)
             {
                 string recoverTheMainSecret;
                 HamDistAtmostT::RecoverSecretFromValidShares (strShares_Main, threshold, selected, recoverTheMainSecret );
                 size_t key_size = recoverTheMainSecret.size();
                 //            recoveredMainSecret = recoverTheMainSecret;

                 CryptoPP::StringSink ss_recoveredMainSecret(MainRecoveredSecret);
                 ss_recoveredMainSecret.Put((const CryptoPP::byte*)recoverTheMainSecret.data(),  recoverTheMainSecret.size(), false);


                 bool AEReslt;

                 AEReslt = CryptoSymWrapperFunctions::Wrapper_AuthDecrypt(MainRecoveredSecret, CtxAE,plaintext_rcv );
                 mpz_clear(P_GF);
                 if (AEReslt == true)
                 {
                     recovered = plaintext_rcv;
                     ret =1;
                 }
                 return ret;
             }

         }

     return ret;
 }


int HamDistAtmostT::CondDec_NewOPT(paillier_pubkey_t* ppk,
                              char typo_ctx [],
                              paillier_prvkey_t* psk,
                              int threshold,
                              string &recovered,
                              size_t _len)
 {
     int ret  = -1;
     size_t max_num_typos =  _len-threshold;
     for(size_t k = max_num_typos - 1; k< _len-1; k++ )
     {
         int CondDecOut = 0;
         CondDecOut = HamDistAtmostT::CondDec_Optimized(ppk, typo_ctx, psk, threshold , recovered, _len, k);
         if (CondDecOut == 1)
         {
             cout << recovered << "\n";
             return ret =1;
         }
         cout << k <<"\t";

     }

     return ret;
 }




int HamDistAtmostT::CondDec_Optimized(paillier_pubkey_t* ppk,
                        char typo_ctx [],
                        paillier_prvkey_t* psk,
                        int threshold,
                        string &recovered,
                        size_t _len,
                        size_t l_m)
{
    int ret =0;
    string CtxAE;
    vector<paillier_ciphertext_t*> V_ctx_typo(_len);
    int pars_rslt =0;
    pars_rslt = HamDistAtmostT::Pail_Parse_Ctx_size_AECtx2(ppk, typo_ctx, CtxAE, V_ctx_typo );

    vector<string> strShares_Zero(_len);
    vector<string> strShares_Main(_len);
    paillier_plaintext_t* dec;
    const unsigned int CHID_LENGTH = 4;

    mpz_t P_GF;
    mpz_init(P_GF);
    size_t ShareSize = SSShareSize;
    int max_power_int = (ShareSize * 8) + 1;
    mpz_ui_pow_ui(P_GF, 2, max_power_int);
    mpz_sub_ui(P_GF, P_GF, 1); // computing the value of P_GF based on the size of the input value.
    void* ByteDec;
    for  (int j = 0; j <_len; j++)
    {
        dec = paillier_dec(NULL, ppk, psk, V_ctx_typo[j]);
        mpz_mod(dec->m, dec->m, P_GF);
        vector<CryptoPP::byte> ab (ShareSize);
        ByteDec = paillier_plaintext_to_bytes_NegOrd(ShareSize, dec);
        memcpy(&ab[0],ByteDec, ShareSize);
        string s(ab.begin(), ab.end());
        strShares_Main[j] =  s.substr (0,20);
        strShares_Zero[j] =  s.substr (20,8);
        free(ByteDec);
        paillier_freeplaintext(dec);
    }
    /*
     * Now the shares are exteracted and we know that all the shares from l_m to _len are valid. We need to find
     * the remaining l_m- (_len-threshold) shares.
     * */


    vector<int> Valid_selected;
    for (int i = l_m + 2;i<_len ; i++)
    {
        Valid_selected.push_back(i);
    }

    string MainRecoveredSecret;
    string plaintext_rcv;
    int rsltRcVr;

    vector<int> v(_len);
    v = HamDistAtmostT::GnereateVectorOfIntegeres(_len);

    rsltRcVr = HamDistAtmostT::generatesubsets_Optimized(strShares_Main, strShares_Zero,  CtxAE, MainRecoveredSecret,
                                           plaintext_rcv, v,0, l_m,  threshold, Valid_selected);
    int AEReslt;

    AEReslt = CryptoSymWrapperFunctions::Wrapper_AuthDecrypt(MainRecoveredSecret, CtxAE,plaintext_rcv );

    mpz_clear(P_GF);
    if (AEReslt == true)
    {
        recovered = plaintext_rcv;
        ret =1;
    }
    else
    {
        recovered = "";

        ret = -1;
    }
    return rsltRcVr;
}


int HamDistAtmostT::CondDec_Optimized_UnknownMsgLength(paillier_pubkey_t* ppk,
                        char typo_ctx [],
                        paillier_prvkey_t* psk,
                        int threshold,
                        string &recovered,
                        size_t _len)
{
    int ret =0;
    string CtxAE;
    vector<paillier_ciphertext_t*> V_ctx_typo(_len);
    int pars_rslt =0;
    pars_rslt = HamDistAtmostT::Pail_Parse_Ctx_size_AECtx2(ppk, typo_ctx, CtxAE, V_ctx_typo );

    vector<string> strShares_Zero(_len);
    vector<string> strShares_Main(_len);
    paillier_plaintext_t* dec;
    const unsigned int CHID_LENGTH = 4;

    mpz_t P_GF;
    mpz_init(P_GF);
    size_t ShareSize = SSShareSize;

    int max_power_int = (ShareSize * 8) + 1;
    mpz_ui_pow_ui(P_GF, 2, max_power_int);
    mpz_sub_ui(P_GF, P_GF, 1); // computing the value of P_GF based on the size of the input value.
    void* ByteDec;
    for  (int j = 0; j <_len; j++)
    {
        dec = paillier_dec(NULL, ppk, psk, V_ctx_typo[j]);
        mpz_mod(dec->m, dec->m, P_GF);
        vector<CryptoPP::byte> ab (ShareSize);
        ByteDec = paillier_plaintext_to_bytes_NegOrd(ShareSize, dec);
        memcpy(&ab[0],ByteDec, ShareSize);
        string s(ab.begin(), ab.end());
        strShares_Main[j] =  s.substr (0,20);
        strShares_Zero[j] =  s.substr (20,8);
        free(ByteDec);
        paillier_freeplaintext(dec);
    }
    /*
     * Now the shares are exteracted and we know that all the shares from l_m to _len are valid. We need to find
     * the remaining l_m- (_len-threshold) shares.
     * */

    for (int l_m = _len-threshold; l_m < _len; l_m++)
    {
        vector<int> Valid_selected;
        for (int i = l_m + 2;i<_len ; i++)
        {
            Valid_selected.push_back(i);
        }

        string MainRecoveredSecret;
        string plaintext_rcv;
        int rsltRcVr;

        vector<int> v(_len);
        v = HamDistAtmostT::GnereateVectorOfIntegeres(_len);

        rsltRcVr = HamDistAtmostT::generatesubsets_Optimized(strShares_Main, strShares_Zero,  CtxAE, MainRecoveredSecret,
                                               plaintext_rcv, v,0, l_m,  threshold, Valid_selected);

        int AEReslt;

        AEReslt = CryptoSymWrapperFunctions::Wrapper_AuthDecrypt(MainRecoveredSecret, CtxAE,plaintext_rcv );


        if (AEReslt == true)
        {
            recovered = plaintext_rcv;
            ret =1;
        }
        else
        {
            recovered = "";

            ret = -1;
        }
    }
     mpz_clear(P_GF);

    return ret;
}

vector<int> HamDistAtmostT::GnereateVectorOfIntegeres (int _len)
{
    vector<int> Result;
    for (int i = 0; i<_len; i++)
    {
        Result.push_back(i);
    }

    return Result;
}