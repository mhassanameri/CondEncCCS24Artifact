//
// Created by mameriek on 9/26/23.
//

#include "testCondEncEvaluation.h"

string SelectRandPwd()
{
    string pwd;
    std::random_device rd;

    /* Random number generator */
    std::default_random_engine generator(rd());

    /* Distribution on which to apply the generator */
    std::uniform_int_distribution<long long unsigned> distribution(0,0xFFFFFFFFF);
    long long int  index = distribution(generator) % 14344383;
    assert (index < 14344383); //14344383 is the number of passwords in Rockyou.txt. Here we just randomly select a random line in the rockyou.txt

    std::string line;
    std::ifstream myfile("/Users/mameriek/Downloads/rockyou.txt");
    if (myfile.is_open()) {
        for (int lineno = 0; getline(myfile, line) && lineno < index + 1; lineno++) {
            if (lineno == index) {
                pwd = line;
            }
        }
        myfile.close();
    }
    else cout << "rockyou.txt unable to be opened";
    return pwd;
}



string HamDisMakeTypo(string &msg, int NumOfErrs)
{
    char err1, err2, err3, err4, err5;
    string typo =msg;
    unsigned seed= time(0);

    if (NumOfErrs == 1)
    {
        err1 = 32 + (rand() % 95);
        int ErrLction;
        ErrLction = rand() % (msg.size());
        typo[ErrLction] = err1;
    } else if (NumOfErrs == 2)
    {
        err1 = 32 + (rand() % 95);
        err2 = 32 + (rand() % 95);
        int ErrLction1, ErrLction2;
        ErrLction1 = rand() % msg.size();
        ErrLction2 = rand() % msg.size();
        typo[ErrLction1] = err1;
        typo[ErrLction2] = err2;
    } else if (NumOfErrs == 3)
    {
        err1 = 32 + (rand() % 95);
        err2 = 32 + (rand() % 95);
        err3 = 32 + (rand() % 95);
        int ErrLction1, ErrLction2, ErrLction3;
        ErrLction1 = rand() % msg.size();
        ErrLction2 = rand() % msg.size();
        ErrLction3 = rand() % msg.size();
        typo[ErrLction1] = err1;
        typo[ErrLction2] = err2;
        typo[ErrLction3] = err3;
    } else if (NumOfErrs == 4)
    {
        err1 = 32 + (rand() % 95);
        err2 = 32 + (rand() % 95);
        err3 = 32 + (rand() % 95);
        err4 = 32 + (rand() % 95);
        int ErrLction1, ErrLction2, ErrLction3, ErrLction4;
        ErrLction1 = rand() % msg.size();
        ErrLction2 = rand() % msg.size();
        ErrLction3 = rand() % msg.size();
        ErrLction4 = rand() % msg.size();
        typo[ErrLction1] = err1;
        typo[ErrLction2] = err2;
        typo[ErrLction3] = err3;
        typo[ErrLction4] = err4;
    } else if (NumOfErrs == 5)
    {
        err1 = 32 + (rand() % 95);
        err2 = 32 + (rand() % 95);
        err3 = 32 + (rand() % 95);
        err4 = 32 + (rand() % 95);
        err5 = 32 + (rand() % 95);
        int ErrLction1, ErrLction2, ErrLction3, ErrLction4, ErrLction5;
        ErrLction1 = rand() % msg.size();
        ErrLction2 = rand() % msg.size();
        ErrLction3 = rand() % msg.size();
        ErrLction4 = rand() % msg.size();
        ErrLction5 = rand() % msg.size();
        typo[ErrLction1] = err1;
        typo[ErrLction2] = err2;
        typo[ErrLction3] = err3;
        typo[ErrLction4] = err4;
        typo[ErrLction5] = err5;
    }
    return typo;
}

string ED1MakeTypo(string &msg, int NumOfErrs, int _len)
{
    unsigned seed= time(0);
    string typo;
    char err1;
    srand(seed);
//        NumOfErrs =rand() % 3;
    NumOfErrs = 1;
    if (NumOfErrs== 0)
    {
        typo = msg;
    }
    else if (NumOfErrs == 1)
    {
        err1 = _len + (rand() % 95);
        int ErrLction;
        ErrLction = rand() % msg.size();
        typo = msg.substr(0, ErrLction) +  err1 + msg.substr(ErrLction, msg.size()) + err1;
//            ErrLction++;
//            typo[ErrLction] = err1;
    } else if (NumOfErrs == 2)
    {
        int ErrLction, ErrLction2;
        ErrLction = rand() % msg.size();
        typo = msg.substr(0, ErrLction) + msg.substr(ErrLction+1, msg.size());
    }
    return typo;
}

string ORMakeTypo(string &msg)
{
    unsigned seed = time(0);
    char err1, err2, err3, err4;
    string typo;
    srand(seed);

    /*
     * Making sure that the resulting typo does not satisfy any
     * predicate for the achieving the worst case scenario of
     * execution time.
     * */
    err1 = 32 + (rand() % 95);
    err2 = 32 + (rand() % 95);
    err3 = 32 + (rand() % 95);
    err4 = 32 + (rand() % 95);
    typo = msg + err1;

    return typo;
}

int testCondEncEDist(int n_lambda,  int Num_tests, size_t _len,  int Threshold,  size_t AE_CtxtSize, int NumOfErrs)
{
    PwPkCrypto pkobj;
    pkobj.Paill_pk_init(n_lambda);
    size_t PailCtxtSize =  PAILLIER_BITS_TO_BYTES(pkobj._ppk->bits)*2;


    size_t TradCtxSize = 2 * sizeof(size_t) + ( _len+1) * PailCtxtSize;
    size_t CondCtxSize = 3 * sizeof(size_t) + AE_CtxtSize + (_len + _len +1) * PailCtxtSize;

    double duration_CondEnc_ED1_Sum = 0;
    double duration_Enc_ED1_Sum = 0;
    double duration_CondDec_ED1_Sum = 0;


    string msg;
    string payload;
    ofstream CondEncEDatMost1;
    CondEncEDatMost1.open("CondEncEDatMost1.txt");

    CondEncEDatMost1 << "The predicate is Eidit distannce at most one [# of errors as the worst case:2  _len = " <<
    _len << "and KeySize = " << n_lambda <<  "****\n";




    for(int T = 0; T< Num_tests; T++) {
        char ED1_Char_ORigCTx[TradCtxSize];
        char ED1_ctx_typo_Bytes[CondCtxSize];
        msg = SelectRandPwd();

        string typo = ED1MakeTypo(msg, NumOfErrs, _len);
        payload = typo;

        string pad_typo = CryptoSymWrapperFunctions::Wrapper_pad(typo, _len);
        string msg_pad = CryptoSymWrapperFunctions::Wrapper_pad(msg, _len);


        auto start_Enc_HD2 = high_resolution_clock::now();
        int OrigEncRst = 0;
        OrigEncRst = EditDistOne::Enc(pkobj._ppk, msg_pad, ED1_Char_ORigCTx);
        auto stop_Enc_HD2 = high_resolution_clock::now();
        auto duration_Enc_HD2 = duration_cast<milliseconds>(stop_Enc_HD2 - start_Enc_HD2);

        auto start_CondEnc_HD2 = high_resolution_clock::now();
//        int ED1CondEncRstl =0;
        auto ctx_final = EditDistOne::CondEnc(pkobj._ppk, ED1_Char_ORigCTx, pad_typo, payload, _len,
                                              ED1_ctx_typo_Bytes);
        auto stop_CondEnc_HD2 = high_resolution_clock::now();
        auto duration_CondEnc_HD2 = duration_cast<milliseconds>(stop_CondEnc_HD2 - start_CondEnc_HD2);


        auto start_CondDec_HD2 = high_resolution_clock::now();
        string recovered_hd2Bytes;
        int CondDecOut = 0;
        CondDecOut = EditDistOne::CondDec(pkobj._ppk, ED1_ctx_typo_Bytes, pkobj._psk, recovered_hd2Bytes,
                                          _len);
        auto stop_CondDec_HD2 = high_resolution_clock::now();
        auto duration_CondDec_HD2 = duration_cast<milliseconds>(stop_CondDec_HD2 - start_CondDec_HD2);

        CondEncEDatMost1 << "Enc.Time, CondEnc.Time, Cond.Dec.Time, Ctx.Size, CondCtx.Size, CondDecRslt: (" <<
                         duration_Enc_HD2.count()
                         << ", " << duration_CondEnc_HD2.count()
                         << ", " << duration_CondDec_HD2.count()
                         << ", " << TradCtxSize
                         << ", " << CondCtxSize
                         << ", " << CondDecOut << " )\n";

        duration_Enc_ED1_Sum = duration_Enc_ED1_Sum + duration_Enc_HD2.count();
        duration_CondEnc_ED1_Sum = duration_CondEnc_ED1_Sum + duration_CondEnc_HD2.count();
        duration_CondDec_ED1_Sum = duration_CondDec_ED1_Sum + duration_CondDec_HD2.count();

        cout << T << "\n";
    }
        string File1 = "EDOnedataL.dat";
        std::ofstream EDOnedataL(File1, std::ios_base::app | std::ios_base::out);
        EDOnedataL << _len << "\t" << duration_Enc_ED1_Sum / Num_tests << "\t"
                   << duration_CondEnc_ED1_Sum / Num_tests << "\t"
                   << duration_CondDec_ED1_Sum / Num_tests << "\t"
                   << TradCtxSize << "\t"
                   << CondCtxSize << "\n";

        CondEncEDatMost1.close();
        paillier_freepubkey(pkobj._ppk);
        paillier_freeprvkey(pkobj._psk);

        CondEncEDatMost1 << "The predicate is Eidit distannce at most one [# of errors as the worst case:2  _len = " <<
                     _len << "and KeySize = " << n_lambda <<  "****\n";
}


int testCondEncHamDist(int n_lambda, int Num_tests, size_t _len, int Threshold, size_t AE_CtxtSize, size_t SizeShare)
{
    PwPkCrypto pkobj;
    pkobj.Paill_pk_init(n_lambda);
    size_t PailCtxtSize =  PAILLIER_BITS_TO_BYTES(pkobj._ppk->bits)*2;

    size_t TradCtxSize = 2 * sizeof(size_t) + _len *  PailCtxtSize;
    size_t CondCtxSize = 3 * sizeof(size_t) + AE_CtxtSize + (_len *  PailCtxtSize);

    double duration_CondEnc_HD_Sum = 0;
    double duration_Enc_HD_Sum = 0;
    double duration_CondDec_HD_Sum = 0;

    string msg;
    string payload;

    size_t NumOfErrs = _len - Threshold + 1;

    ofstream CondEncHD;
    CondEncHD.open("CondEncHDAtmostT.txt");

    CondEncHD << "OPT The predicate is Hamming distance at most Threshold =" << _len - Threshold <<
    "[# of errors as the worst case: "<< NumOfErrs << " _len = " << _len << "and KeySize = " << n_lambda <<
    "****\n";

    for(int T = 0; T< Num_tests; T++)
    {
        char HD_Char_ORigCTx [TradCtxSize];
        char HD_ctx_typo_Bytes[CondCtxSize];
        msg = SelectRandPwd();
        string typo = HamDisMakeTypo(msg, NumOfErrs);
        payload =  typo;
        string msg_pad  = CryptoSymWrapperFunctions::Wrapper_pad(msg, _len);
        string pad_typo = CryptoSymWrapperFunctions::Wrapper_pad(typo, _len);

        /*  Running the traditional Encryption of chosen*/
        auto start_Enc_HD = high_resolution_clock::now();
        int tradEncRslt =0;
        tradEncRslt = HamDistAtmostT::Enc(pkobj._ppk, msg_pad, HD_Char_ORigCTx);
        auto stop_Enc_HD = high_resolution_clock::now();
        auto duration_Enc_HD = duration_cast<milliseconds>(stop_Enc_HD - start_Enc_HD);

        /*Running the Conditional Encryption*/
        auto start_CondEnc_HD = high_resolution_clock::now();
        auto ctx_final = HamDistAtmostT::CondEnc(pkobj._ppk, HD_Char_ORigCTx, typo, payload,_len, Threshold, HD_ctx_typo_Bytes);
        auto stop_CondEnc_HD = high_resolution_clock::now();
        auto duration_CondEnc_HD = duration_cast<milliseconds>(stop_CondEnc_HD - start_CondEnc_HD);

        /*Running the Conditional Decryption */
        auto start_CondDec_HD = high_resolution_clock::now();
        string recovered_hdBytes;
        int CondDecOut  = 0;
        CondDecOut = HamDistAtmostT::CondDec(pkobj._ppk, HD_ctx_typo_Bytes, pkobj._psk, Threshold, recovered_hdBytes, _len, SizeShare);
//        CondDecOut = HamDistAtmostT::CondDec_Optimized(pkobj._ppk, HD_ctx_typo_Bytes, pkobj._psk, Threshold, recovered_hdBytes, _len, SizeShare, msg.size());

        auto stop_CondDec_HD = high_resolution_clock::now();
        auto duration_CondDec_HD = duration_cast<milliseconds>(stop_CondDec_HD - start_CondDec_HD);

        CondEncHD << "Enc.Time, CondEnc.Time, Cond.Dec.Time, Ctx.Size, CondCtx.Size, CondDecRslt: (" <<
                   duration_Enc_HD.count()
                   << ", " << duration_CondEnc_HD.count()
                   << ", " << duration_CondDec_HD.count()
                   << ", " << TradCtxSize
                   << ", " << CondCtxSize
                   << ", " << CondDecOut << " )\n";

        duration_Enc_HD_Sum =  duration_Enc_HD_Sum + duration_Enc_HD.count();
        duration_CondEnc_HD_Sum =  duration_CondEnc_HD_Sum + duration_CondEnc_HD.count();
        duration_CondDec_HD_Sum =  duration_CondDec_HD_Sum + duration_CondDec_HD.count();
        cout <<T << "\n";

    }

    string File1 = "OPT_HDdataL_T" + std::to_string(NumOfErrs -1) + ".dat";
    string File2 = "OPT_HDdataL" + std::to_string(_len) + "_T.dat";

    std::ofstream HDdataL(File1, std::ios_base::app | std::ios_base::out);
    std::ofstream HDdataT(File2, std::ios_base::app | std::ios_base::out);
//    std::ofstream HDdataL("HDdataL.dat", std::ios_base::app | std::ios_base::out);
//    std::ofstream HDdataT("HDdataT.dat", std::ios_base::app | std::ios_base::out);
    size_t MaxDist  = _len - Threshold;

//    HDdataT << "The predicate is Hamming distance at most Threshold =" << _len - Threshold <<
//            "[# of errors as the worst case: "<< NumOfErrs << " _len = " << _len << "and KeySize = " << n_lambda <<
//            "****\n";

    HDdataT << MaxDist << "\t"<< _len << "\t" << duration_Enc_HD_Sum / Num_tests << "\t"
            << duration_CondEnc_HD_Sum / Num_tests << "\t"
            << duration_CondDec_HD_Sum / Num_tests << "\t"
            << TradCtxSize  << "\t"
            << CondCtxSize  << "\n";

//    HDdataL << "The predicate is Hamming distance at most Threshold =" << _len - Threshold <<
//            "[# of errors as the worst case: "<< NumOfErrs << " _len = " << _len << "and KeySize = " << n_lambda <<
//            "****\n";

    HDdataL << MaxDist << "\t"<< _len << "\t" << duration_Enc_HD_Sum / Num_tests << "\t"
            << duration_CondEnc_HD_Sum / Num_tests << "\t"
            << duration_CondDec_HD_Sum / Num_tests << "\t"
            << TradCtxSize << "\t"
            << CondCtxSize << "\n";

    CondEncHD.close();
    paillier_freepubkey(pkobj._ppk);
    paillier_freeprvkey(pkobj._psk);
    cout << "OPT_The predicate is Hamming distance at most Threshold =" << _len - Threshold <<
         "[# of errors as the worst case: "<< NumOfErrs << " _len = " << _len << "and KeySize = " << n_lambda <<
         "****\n";
}

int testCondEncOR(int n_lambda, int Num_tests, size_t _len, int Threshold, size_t AE_CtxtSize, size_t SizeShare)
{
    PwPkCrypto pkobj;
    pkobj.Paill_pk_init(n_lambda);

    size_t PailCtxtSize =  PAILLIER_BITS_TO_BYTES(pkobj._ppk->bits)*2;

    size_t EDOneOrigCtxSize   = 2 * sizeof(size_t) + (_len + 1)  *  PailCtxtSize;
    size_t HDTwoOrigCtxSize   = 2 * sizeof(size_t) + _len *  PailCtxtSize;
    size_t CAPSLocOrigCtxSize = 2 * sizeof(size_t) +  PailCtxtSize;

    size_t ORPrdrigCtxSize = CAPSLocOrigCtxSize + EDOneOrigCtxSize + HDTwoOrigCtxSize;

    size_t CondEncEDOneCtxSize = 3 * sizeof(size_t) + (sizeof(char) * AE_CtxtSize) + ((2 * _len) + 1) *  PailCtxtSize;
    size_t CondEncHDTwoCtxSize = 3 * sizeof(size_t) + (sizeof(char) * AE_CtxtSize) + (_len *  PailCtxtSize);
    size_t CondEncCPSLKCtxSize = 3 * sizeof(size_t) + (sizeof(char) * AE_CtxtSize) +  PailCtxtSize;

    size_t CondEncOR_CtxSize = CondEncCPSLKCtxSize + CondEncEDOneCtxSize + CondEncHDTwoCtxSize;

    double duration_CondEnc_ED1_Sum = 0;
    double duration_Enc_ED1_Sum = 0;
    double duration_CondDec_ED1_Sum = 0;

    string msg;
    string typo;
    string payload;

//    typo  = msg + 'a' + 'v' + 's';


//    payload = typo;
    ofstream CondEncHD;
    CondEncHD.open("CondEncHDAtmostT.txt");

    CondEncHD << "Or predicate of of Hamming distance at most two, Edit distance "
                 "at most One, CAPASLOCK on Error for _len = " << _len << "and KeySize = " << n_lambda <<
              "****\n";



    char* OrPred_Char_ORigCTx = (char*) malloc(ORPrdrigCtxSize);
    char* OrPred_ctx_typo_Bytes = (char*) malloc(CondEncOR_CtxSize);


    for(int T = 0; T< Num_tests; T++)
    {

        int control = 1;
        string typo;

        while(control ==1)
        {
            msg = SelectRandPwd();
            typo = ORMakeTypo(msg);

            if(msg.size() >=  _len || typo.size() >= _len-1 )
            {
                control = 1;
            }else
            {control = 0; }

        }

        if (typo.size() >= _len)
        {
            cout << "typo is greater than _len";
            break;
        }



        payload = typo;
        cout  <<msg << "\n" << typo << "\n";

        string msg_pad  = CryptoSymWrapperFunctions::Wrapper_pad(msg, _len);
        string pad_typo = CryptoSymWrapperFunctions::Wrapper_pad(typo, _len);

        std::unique_ptr<OrPredicate> Class_OrPredicate(new OrPredicate());

        auto start_Enc_HD2 = high_resolution_clock::now();
        int OrigEncRst = 0;
        OrigEncRst = Class_OrPredicate->Enc(pkobj._ppk, msg, OrPred_Char_ORigCTx, _len);
        auto stop_Enc_HD2 = high_resolution_clock::now();
        auto duration_Enc_HD2 = duration_cast<milliseconds>(stop_Enc_HD2 - start_Enc_HD2);


        std::string ctx_final;
//        OrPredicate*  Class_OrPredicate = new OrPredicate;
        auto start_CondEnc_HD2 = high_resolution_clock::now();
//        int ED1CondEncRstl =0;
        ctx_final = Class_OrPredicate->CondEnc(pkobj._ppk, OrPred_Char_ORigCTx, typo, payload,_len, Threshold, OrPred_ctx_typo_Bytes);

        auto stop_CondEnc_HD2 = high_resolution_clock::now();
        auto duration_CondEnc_HD2 = duration_cast<milliseconds>(stop_CondEnc_HD2 - start_CondEnc_HD2);

        string recovered_hd2Bytes;
        int CondDecOut = 0;
        auto start_CondDec_HD2 = high_resolution_clock::now();
        CondDecOut = Class_OrPredicate->CondDec(pkobj._ppk, OrPred_ctx_typo_Bytes, pkobj._psk, Threshold, recovered_hd2Bytes, _len, SizeShare);
//        CondDecOut = OrPredicate::CondDec(pkobj._ppk, &ctx_final[0], pkobj._psk, 30, recovered_hd2Bytes, 32, 28);

        auto stop_CondDec_HD2 = high_resolution_clock::now();
        auto duration_CondDec_HD2 = duration_cast<milliseconds>(stop_CondDec_HD2 - start_CondDec_HD2);

//        free(ED1_Char_ORigCTx);
//        free(ED1_ctx_typo_Bytes);

        CondEncHD << "Enc.Time, CondEnc.Time, Cond.Dec.Time, Ctx.Size, CondCtx.Size, CondDecRslt: (" <<
                      duration_Enc_HD2.count()
                      << ", " << duration_CondEnc_HD2.count()
                      << ", " << duration_CondDec_HD2.count()
                      << ", " << ORPrdrigCtxSize
                      << ", " << CondEncOR_CtxSize
                      << ", " << CondDecOut << " )\n";



        duration_Enc_ED1_Sum =  duration_Enc_ED1_Sum + duration_Enc_HD2.count();
        duration_CondEnc_ED1_Sum =  duration_CondEnc_ED1_Sum + duration_CondEnc_HD2.count();
        duration_CondDec_ED1_Sum =  duration_CondDec_ED1_Sum + duration_CondDec_HD2.count();

        Class_OrPredicate.reset();
//        delete Class_OrPredicate;
//        Class_OrPredicate = NULL;
//        Class_OrPredicate = nullptr;
        cout << T << "\n";
    }

    string File1 = "ORdataL.dat";
    std::ofstream CondEncORpred(File1, std::ios_base::app | std::ios_base::out);

    CondEncORpred << _len << "\t" << duration_Enc_ED1_Sum / Num_tests << "\t"
               << duration_CondEnc_ED1_Sum / Num_tests << "\t"
               << duration_CondDec_ED1_Sum / Num_tests << "\t"
               << ORPrdrigCtxSize << "\t"
               << CondEncOR_CtxSize << "\n";

    CondEncORpred.close();
    paillier_freepubkey(pkobj._ppk);
//    paillier_freeprvkey(pkobj._psk);
    free(OrPred_Char_ORigCTx);
    free(OrPred_ctx_typo_Bytes);
    cout << "OR predicate is finished L =" <<_len << "\n";

}

int testCondEncCAPSLOCK(int n_lambda, int Num_tests, size_t _len, int Threshold, size_t AE_CtxtSize, size_t SizeShare)
{
    PwPkCrypto pkobj;
    pkobj.Paill_pk_init(n_lambda);
    size_t PailCtxtSize =  PAILLIER_BITS_TO_BYTES(pkobj._ppk->bits)*2;

    size_t CAPSLocOrigCtxSize = 2 * sizeof(size_t) +  PailCtxtSize;

    size_t ORPrdrigCtxSize = CAPSLocOrigCtxSize;

    size_t CondEncCPSLKCtxSize = 3 * sizeof(size_t) + (sizeof(char) * AE_CtxtSize) +  PailCtxtSize;

    size_t CondEncOR_CtxSize = CondEncCPSLKCtxSize ;

    double duration_CondEnc_ED1_Sum = 0;
    double duration_Enc_ED1_Sum = 0;
    double duration_CondDec_ED1_Sum = 0;

    string msg;
    string typo;
    string payload;



//    payload = typo;
    ofstream CondEncHD;
    CondEncHD.open("CondEncCAPSLOCOn.txt");

    CondEncHD << "Performance evaluation of the conditional encryption for the CAPSLOCK Error on "
                 "for _len = " << _len << "and KeySize = " << n_lambda <<
              "****\n";



    char* OrPred_Char_ORigCTx = (char*) malloc(ORPrdrigCtxSize);
    char* OrPred_ctx_typo_Bytes = (char*) malloc(CondEncOR_CtxSize);


    for(int T = 0; T< Num_tests; T++)
    {

        int b = 1;
        string typo;
        while (b==1)
        {
            msg = SelectRandPwd();
            typo = ORMakeTypo(msg);
            if (typo.size() > _len)
            {
                b = 1;
            }
            else{
                b= 0;
            };
        }

        payload = typo;

        cout  <<msg << "\n" << typo << "\n";

//        string msg_pad  = CryptoSymWrapperFunctions::Wrapper_pad(msg, _len);
//        string pad_typo = CryptoSymWrapperFunctions::Wrapper_pad(typo, _len);

//        std::unique_ptr<CAPLOCKpredicate> CAPLOCKpredicate(new OrPredicate());

        auto start_Enc_HD2 = high_resolution_clock::now();
        int OrigEncRst = 0;
        OrigEncRst = CAPLOCKpredicate::Enc(pkobj._ppk, msg, OrPred_Char_ORigCTx);
        auto stop_Enc_HD2 = high_resolution_clock::now();
        auto duration_Enc_HD2 = duration_cast<milliseconds>(stop_Enc_HD2 - start_Enc_HD2);


        std::string ctx_final;
//        OrPredicate*  Class_OrPredicate = new OrPredicate;
        auto start_CondEnc_HD2 = high_resolution_clock::now();
//        int ED1CondEncRstl =0;
        ctx_final = CAPLOCKpredicate::CondEnc(pkobj._ppk, OrPred_Char_ORigCTx, typo, payload, OrPred_ctx_typo_Bytes);

        auto stop_CondEnc_HD2 = high_resolution_clock::now();
        auto duration_CondEnc_HD2 = duration_cast<milliseconds>(stop_CondEnc_HD2 - start_CondEnc_HD2);

        string recovered_hd2Bytes;
        int CondDecOut = 0;
        auto start_CondDec_HD2 = high_resolution_clock::now();
        CondDecOut = CAPLOCKpredicate::CondDec(pkobj._ppk, OrPred_ctx_typo_Bytes, pkobj._psk, recovered_hd2Bytes);
//        CondDecOut = OrPredicate::CondDec(pkobj._ppk, &ctx_final[0], pkobj._psk, 30, recovered_hd2Bytes, 32, 28);

        auto stop_CondDec_HD2 = high_resolution_clock::now();
        auto duration_CondDec_HD2 = duration_cast<milliseconds>(stop_CondDec_HD2 - start_CondDec_HD2);

//        free(ED1_Char_ORigCTx);
//        free(ED1_ctx_typo_Bytes);

        CondEncHD << "Enc.Time, CondEnc.Time, Cond.Dec.Time, Ctx.Size, CondCtx.Size, CondDecRslt: (" <<
                  duration_Enc_HD2.count()
                  << ", " << duration_CondEnc_HD2.count()
                  << ", " << duration_CondDec_HD2.count()
                  << ", " << ORPrdrigCtxSize
                  << ", " << CondEncOR_CtxSize
                  << ", " << CondDecOut << " )\n";



        duration_Enc_ED1_Sum =  duration_Enc_ED1_Sum + duration_Enc_HD2.count();
        duration_CondEnc_ED1_Sum =  duration_CondEnc_ED1_Sum + duration_CondEnc_HD2.count();
        duration_CondDec_ED1_Sum =  duration_CondDec_ED1_Sum + duration_CondDec_HD2.count();

//        Class_OrPredicate.reset();
//        delete Class_OrPredicate;
//        Class_OrPredicate = NULL;
//        Class_OrPredicate = nullptr;
        cout << T << "\n";
    }

    string File1 = "CAPSLKdataL.dat";
    std::ofstream CondEncORpred(File1, std::ios_base::app | std::ios_base::out);

    CondEncORpred << _len << "\t" << duration_Enc_ED1_Sum / Num_tests << "\t"
                  << duration_CondEnc_ED1_Sum / Num_tests << "\t"
                  << duration_CondDec_ED1_Sum / Num_tests << "\t"
                  << ORPrdrigCtxSize << "\t"
                  << CondEncOR_CtxSize << "\n";

    CondEncORpred.close();
    paillier_freepubkey(pkobj._ppk);
    paillier_freeprvkey(pkobj._psk);
    free(OrPred_Char_ORigCTx);
    free(OrPred_ctx_typo_Bytes);
    cout << "CAPSLOCK Error predicate is finished L =" <<_len << "\n";
}
