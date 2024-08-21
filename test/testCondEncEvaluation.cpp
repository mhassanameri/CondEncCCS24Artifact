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
    const char path [] = "/home/hassan/CLionProjects/CondEncCCS24/rockyou.txt";
    if (std::ifstream myfile(path); myfile.is_open()) {
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


std::vector<std::pair<std::string, std::string>> LoadPWDvsTypoForTEST(const std::string& FileName)
{
    std::vector<std::pair<std::string, std::string>> data;
    std::ifstream file(FileName);
    if (!file)
    {
        std::cerr <<"Unable to open the PWD and Typo pair related file:" << FileName << std::endl;
        return data;
    }
    std::string line;
    const std::string delimiter = "\t\t****\t\t";

    while (std::getline(file, line)) {
        // Find the delimiter position
        size_t pos = line.find(delimiter);
        if (pos != std::string::npos) {
            // Extract the two columns
            std::string column1 = line.substr(0, pos);
            std::string column2 = line.substr(pos + delimiter.length());
            // Store the pair in the vector
            data.emplace_back(column1, column2);
        }
    }


    file.close();
    return data;
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
    size_t ell = _len - 31;
    std::string filename = "PWDvsTyposDataSet/PWDvsTypoDataSetLessThan"+to_string(_len)+".txt";
    std::vector<std::pair<std::string, std::string>> data = LoadPWDvsTypoForTEST(filename);

    // std::string filename = "PWDvsTyposDataSet/PWDvsTypoDataSetLessThan"+to_string(_len)+"HamDisHold" +to_string(ell)+".txt";
    // std::vector<std::pair<std::string, std::string>> data = LoadPWDvsTypoForTEST(filename);


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
    string typo;
    ofstream CondEncEDatMost1;
    CondEncEDatMost1.open("CondEncEDatMost1.txt");

    CondEncEDatMost1 << "The predicate is Eidit distannce at most one [# of errors as the worst case:2  _len = " <<
    _len << "and KeySize = " << n_lambda <<  "****\n";




    for(int T = 0; T< Num_tests; T++) {

        msg = data[T].first;
        typo = data[T].second;
        payload = typo;

        char ED1_Char_ORigCTx[TradCtxSize];
        char ED1_ctx_typo_Bytes[CondCtxSize];
        // msg = SelectRandPwd();
        //
        // string typo = ED1MakeTypo(msg, NumOfErrs, _len);
        // payload = typo;
        cout << msg + "\n" << typo <<"\n";
        string pad_typo = CryptoSymWrapperFunctions::Wrapper_pad(typo, _len);
        string msg_pad = CryptoSymWrapperFunctions::Wrapper_pad(msg, _len);


        auto start_Enc_HD2 = high_resolution_clock::now();
        int OrigEncRst = 0;
        OrigEncRst = EditDistOne::Enc(pkobj._ppk, msg_pad, ED1_Char_ORigCTx);
        auto stop_Enc_HD2 = high_resolution_clock::now();
        auto duration_Enc_HD2 = duration_cast<milliseconds>(stop_Enc_HD2 - start_Enc_HD2);

        auto start_CondEnc_HD2 = high_resolution_clock::now();
//        int ED1CondEncRstl =0;
        auto ctx_final = EditDistOne::CondEnc(pkobj._ppk, ED1_Char_ORigCTx, pad_typo, payload, _len, Threshold,
                                              ED1_ctx_typo_Bytes);
        auto stop_CondEnc_HD2 = high_resolution_clock::now();
        auto duration_CondEnc_HD2 = duration_cast<milliseconds>(stop_CondEnc_HD2 - start_CondEnc_HD2);

        cout << "\n";
        auto start_CondDec_HD2 = high_resolution_clock::now();
        string recovered_hd2Bytes;
        int CondDecOut = 0;
        CondDecOut = EditDistOne::CondDec(pkobj._ppk, ED1_ctx_typo_Bytes, pkobj._psk, Threshold, recovered_hd2Bytes,
                                          _len, 28);
        cout <<CondDecOut <<"\n";

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
    return 1;
}


int testCondEncHamDist(int n_lambda, int Num_tests, size_t _len, int Threshold, size_t AE_CtxtSize1, size_t SizeShare)
{

    size_t ell = _len - Threshold;
    // std::string filename = "PWDvsTyposDataSet/PWDvsTypoDataSetLessThan"+to_string(_len)+"OrNotHold.txt";
    // std::vector<std::pair<std::string, std::string>> data = LoadPWDvsTypoForTEST(filename);
    std::string filename = "PWDvsTyposDataSet/PWDvsTypoDataSetLessThan"+to_string(_len)+"HamDisNotHold"+to_string(ell)+".txt";
    std::vector<std::pair<std::string, std::string>> data = LoadPWDvsTypoForTEST(filename);

    PwPkCrypto pkobj;
    pkobj.Paill_pk_init(n_lambda);
    size_t PailCtxtSize =  PAILLIER_BITS_TO_BYTES(pkobj._ppk->bits)*2;

    size_t TradCtxSize = 2 * sizeof(size_t) + _len *  PailCtxtSize;

    double duration_CondEnc_HD_Sum = 0;
    double duration_Enc_HD_Sum = 0;
    double duration_CondDec_HD_Sum = 0;
    double CondCtxSize_HD_Sum = 0;

    string msg;
    string payload;
    string typo;

    size_t NumOfErrs = _len - Threshold + 1;

    ofstream CondEncHD;
    CondEncHD.open("CondEncHDAtmostT.txt");

    CondEncHD << "OPT The predicate is Hamming distance at most Threshold =" << _len - Threshold <<
    "[# of errors as the worst case: "<< NumOfErrs << " _len = " << _len << "and KeySize = " << n_lambda <<
    "****\n";

    for(int T = 0; T< Num_tests; T++)
    {

        msg = data[T].first;
        typo = data[T].second;
        payload = CryptoSymWrapperFunctions::Wrapper_pad( typo, _len);
        cout << msg.size() << "\t" <<typo.size() << "\n";
        cout << msg << "\t" <<typo << "\n";


        // msg  = "TTTTTTTTTTTTTTTTTTTTTTTTT";
        // typo = "TTTTTTTTTTTTTTTTTTTTrrrrr";
        // msg  = "Test1";
        // typo = "dddd2";
        // msg = "T111f";
        // string typo = "T112j";
        // string typo = "T";

        // msg = SelectRandPwd();
        // string typo = HamDisMakeTypo(msg, NumOfErrs);
        payload =  typo;
        CondCtxSize_HD_Sum = CondCtxSize_HD_Sum + _len;
        size_t AE_CtxtSize = 2 * KEYSIZE_BYTES + _len;
        char HD_Char_ORigCTx [TradCtxSize];
        size_t CondCtxSize = 3 * sizeof(size_t) + AE_CtxtSize + (_len *  PailCtxtSize);
        char HD_ctx_typo_Bytes[CondCtxSize];

        string msg_pad  = CryptoSymWrapperFunctions::Wrapper_pad(msg, _len);
        string pad_typo = CryptoSymWrapperFunctions::Wrapper_pad(typo, _len);

        /*  Running the traditional Encryption of chosen*/
        auto start_Enc_HD = high_resolution_clock::now();
        int tradEncRslt =0;
        tradEncRslt = HamDistTwo::Enc(pkobj._ppk, msg_pad, HD_Char_ORigCTx);
        auto stop_Enc_HD = high_resolution_clock::now();
        auto duration_Enc_HD = duration_cast<milliseconds>(stop_Enc_HD - start_Enc_HD);


        /*Running the Conditional Encryption*/
        auto start_CondEnc_HD = high_resolution_clock::now();
        auto ctx_final = HamDistTwo::CondEnc(pkobj._ppk, HD_Char_ORigCTx, typo, payload,_len, Threshold, HD_ctx_typo_Bytes);
        auto stop_CondEnc_HD = high_resolution_clock::now();
        auto duration_CondEnc_HD = duration_cast<milliseconds>(stop_CondEnc_HD - start_CondEnc_HD);
        cout <<"successfull Cond encryption\n";
        /*Running the Conditional Decryption */
        auto start_CondDec_HD = high_resolution_clock::now();
        string recovered_hdBytes;
        int CondDecOut  = 0;
        CondDecOut = HamDistTwo::CondDec(pkobj._ppk, HD_ctx_typo_Bytes, pkobj._psk, Threshold, recovered_hdBytes, _len, SizeShare);
        // CondDecOut = HamDistTwo::CondDec_Optimized(pkobj._ppk, HD_ctx_typo_Bytes, pkobj._psk, Threshold, recovered_hdBytes, _len, SizeShare, msg.size());
        // CondDecOut = HamDistTwo::CondDec_Optimized_UnknownMsgLength(pkobj._ppk, HD_ctx_typo_Bytes, pkobj._psk, Threshold, recovered_hdBytes, _len, SizeShare);
        // CondDecOut = HamDistTwo::CondDec_NewOPT(pkobj._ppk, HD_ctx_typo_Bytes, pkobj._psk, Threshold, recovered_hdBytes, _len, SizeShare);
        // CondDecOut = HamDistTwo::CondDec_NonSmallFieldCheck(pkobj._ppk, HD_ctx_typo_Bytes, pkobj._psk, Threshold, recovered_hdBytes, _len, SizeShare);
        // CondDecOut = HamDistTwo::CondDec_2dif(pkobj._ppk, HD_ctx_typo_Bytes, pkobj._psk, Threshold, recovered_hdBytes, _len, SizeShare);



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

    // string File1 = "HDdataL_T" + std::to_string(NumOfErrs -1) + ".dat";
    // string File2 = "HDdataL" + std::to_string(_len) + "_T.dat";

    // string File1 = "OPT_HoldingHDdataL_T" + std::to_string(NumOfErrs -1) + ".dat";
    // string File2 = "OPT_HoldingHDdataL" + std::to_string(_len) + "_T.dat";

    // string File1 = "HoldingHDdataL_T" + std::to_string(NumOfErrs -1) + ".dat";
    // string File2 = "HoldingHDdataL" + std::to_string(_len) + "_T.dat";
    // string File1 = "OPTJustHam2HoldingHDdataL_T" + std::to_string(NumOfErrs -1) + ".dat";
    // string File2 = "OPTJustHam2HoldingHDdataL" + std::to_string(_len) + "_T.dat";

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
            << CondCtxSize_HD_Sum /Num_tests  << "\n";

//    HDdataL << "The predicate is Hamming distance at most Threshold =" << _len - Threshold <<
//            "[# of errors as the worst case: "<< NumOfErrs << " _len = " << _len << "and KeySize = " << n_lambda <<
//            "****\n";

    HDdataL << MaxDist << "\t"<< _len << "\t" << duration_Enc_HD_Sum / Num_tests << "\t"
            << duration_CondEnc_HD_Sum / Num_tests << "\t"
            << duration_CondDec_HD_Sum / Num_tests << "\t"
            << TradCtxSize << "\t"
            << CondCtxSize_HD_Sum /Num_tests << "\n";

    CondEncHD.close();
    paillier_freepubkey(pkobj._ppk);
    paillier_freeprvkey(pkobj._psk);
    cout << "OPT_The predicate is Hamming distance at most Threshold =" << _len - Threshold <<
         "[# of errors as the worst case: "<< NumOfErrs << " _len = " << _len << "and KeySize = " << n_lambda <<
         "****\n";
    return 1;
}

int testCondEncOR(int n_lambda, int Num_tests, size_t _len, int Threshold, size_t AE_CtxtSize1, size_t SizeShare)
{
    PwPkCrypto pkobj;
    pkobj.Paill_pk_init(n_lambda);



    size_t PailCtxtSize =  PAILLIER_BITS_TO_BYTES(pkobj._ppk->bits)*2;

    size_t EDOneOrigCtxSize   = 2 * sizeof(size_t) + (_len + 1)  *  PailCtxtSize;
    size_t HDTwoOrigCtxSize   = 2 * sizeof(size_t) + _len *  PailCtxtSize;
    size_t CAPSLocOrigCtxSize = 2 * sizeof(size_t) +  PailCtxtSize;

    size_t ORPrdrigCtxSize = CAPSLocOrigCtxSize + EDOneOrigCtxSize + HDTwoOrigCtxSize;

    std::string filename = "PWDvsTyposDataSet/PWDvsTypoDataSetLessThan"+to_string(_len)+".txt";
    std::vector<std::pair<std::string, std::string>> data = LoadPWDvsTypoForTEST(filename);




    double duration_CondEnc_ED1_Sum = 0;
    double duration_Enc_ED1_Sum = 0;
    double duration_CondDec_ED1_Sum = 0;
    double CondEncOR_CtxSize_Sum = 0;

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




    // char* OrPred_Char_ORigCTx = (char*) malloc(ORPrdrigCtxSize);
    // char* OrPred_ctx_typo_Bytes = (char*) malloc(CondEncOR_CtxSize);


    for(int T = 0; T< Num_tests; T++)
    {

        int control = 1;
        msg= "Test";
        typo = "Test";
        payload = CryptoSymWrapperFunctions::Wrapper_pad(typo, _len);
        assert(payload.size()==_len);

        size_t AE_CtxtSize = 2 * KEYSIZE_BYTES + payload.size();
        size_t CondEncEDOneCtxSize = 3 * sizeof(size_t) + (sizeof(char) * AE_CtxtSize) + ((2 * _len) + 1) *  PailCtxtSize;
        size_t CondEncHDTwoCtxSize = 3 * sizeof(size_t) + (sizeof(char) * AE_CtxtSize) + (_len *  PailCtxtSize);
        size_t CondEncCPSLKCtxSize = 3 * sizeof(size_t) + (sizeof(char) * AE_CtxtSize) +  PailCtxtSize;

        size_t CondEncOR_CtxSize = CondEncCPSLKCtxSize + CondEncEDOneCtxSize + CondEncHDTwoCtxSize;
        // msg = data[1].first;
        // typo = data[1].second;



        char OrPred_Char_ORigCTx[ ORPrdrigCtxSize];
        char OrPred_ctx_typo_Bytes [CondEncOR_CtxSize];

        // while(control ==1)
        // {
        //     msg = SelectRandPwd();
        //     typo = ORMakeTypo(msg);
        //
        //     if(msg.size() >=  _len || typo.size() >= _len-1 )
        //     {
        //         control = 1;
        //     }else
        //     {control = 0; }
        //
        // }
        //
        // if (typo.size() >= _len)
        // {
        //     cout << "typo is greater than _len";
        //     break;
        // }



        // payload = typo;
        cout  <<msg << "\n" << typo << "\n";

        string msg_pad  = CryptoSymWrapperFunctions::Wrapper_pad(msg, _len);
        string pad_typo = CryptoSymWrapperFunctions::Wrapper_pad(typo, _len);

        // std::unique_ptr<OrPredicate> Class_OrPredicate(new OrPredicate());

        auto start_Enc_HD2 = high_resolution_clock::now();
        int OrigEncRst = 0;
        OrigEncRst = OrPredicate::Enc(pkobj._ppk, msg, OrPred_Char_ORigCTx, _len);
        auto stop_Enc_HD2 = high_resolution_clock::now();
        auto duration_Enc_HD2 = duration_cast<milliseconds>(stop_Enc_HD2 - start_Enc_HD2);


        string ctx_final;
//        OrPredicate*  Class_OrPredicate = new OrPredicate;
        auto start_CondEnc_HD2 = high_resolution_clock::now();
//        int ED1CondEncRstl =0;
        ctx_final = OrPredicate::CondEnc(pkobj._ppk, OrPred_Char_ORigCTx, typo, payload,_len, Threshold, OrPred_ctx_typo_Bytes);

        auto stop_CondEnc_HD2 = high_resolution_clock::now();
        auto duration_CondEnc_HD2 = duration_cast<milliseconds>(stop_CondEnc_HD2 - start_CondEnc_HD2);
        cout << "strat to decrypt OR\n";
        string recovered_hd2Bytes;
        int CondDecOut = 0;
        auto start_CondDec_HD2 = high_resolution_clock::now();
        // CondDecOut = Class_OrPredicate->CondDec_Optimized_for_HD2(pkobj._ppk, OrPred_ctx_typo_Bytes, pkobj._psk, Threshold, recovered_hd2Bytes, _len, SizeShare);
        // CondDecOut = Class_OrPredicate->CondDec_Optimized_for_HD2(pkobj._ppk, OrPred_ctx_typo_Bytes, pkobj._psk, Threshold, recovered_hd2Bytes, _len, SizeShare);
        // CondDecOut = OrPredicate::CondDec(pkobj._ppk, &ctx_final[0], pkobj._psk, 30, recovered_hd2Bytes, 32, 28);
        CondDecOut = OrPredicate::CondDec(pkobj._ppk, OrPred_ctx_typo_Bytes, pkobj._psk, _len-2, recovered_hd2Bytes, _len, 28);


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
        CondEncOR_CtxSize_Sum = CondEncOR_CtxSize_Sum + CondEncOR_CtxSize;
        // Class_OrPredicate.reset();
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
               << CondEncOR_CtxSize_Sum/Num_tests << "\n";

    CondEncORpred.close();
    paillier_freepubkey(pkobj._ppk);
//    paillier_freeprvkey(pkobj._psk);
    // free(OrPred_Char_ORigCTx);
    // free(OrPred_ctx_typo_Bytes);
    cout << "OR predicate is finished L =" <<_len << "\n";
    return 1;

}

int testCondEncCAPSLOCK(int n_lambda, int Num_tests, size_t _len, int Threshold, size_t AE_CtxtSize1, size_t SizeShare)
{

    std::string filename = "PWDvsTyposDataSet/PWDvsTypoDataSetLessThan"+to_string(_len)+".txt";
    std::vector<std::pair<std::string, std::string>> data = LoadPWDvsTypoForTEST(filename);


    PwPkCrypto pkobj;
    pkobj.Paill_pk_init(n_lambda);
    size_t PailCtxtSize =  PAILLIER_BITS_TO_BYTES(pkobj._ppk->bits)*2;

    size_t CAPSLocOrigCtxSize = 2 * sizeof(size_t) +  PailCtxtSize;

    // size_t ORPrdrigCtxSize = CAPSLocOrigCtxSize;


    // size_t CondEncOR_CtxSize = CondEncCPSLKCtxSize ;

    double duration_CondEnc_Sum = 0;
    double duration_Enc_Sum = 0;
    double duration_CondDec_Sum = 0;
    double CondEncCPSLKCtxSize_Sum = 0;

    string msg;
    string typo;
    string payload;

    // auto CAPSLOCK_Pred_Char_ORigCTx = static_cast<char*>(malloc(CAPSLocOrigCtxSize));
    // auto CAPSLOCK_Pred_ctx_typo_Bytes = static_cast<char*>(malloc(CondEncCPSLKCtxSize));

//    payload = typo;
    ofstream CondEnc;
    CondEnc.open("CondEncCAPSLOCOn.txt");

    CondEnc << "Performance evaluation of the conditional encryption for the CAPSLOCK Error on "
                 "for _len = " << _len << "and KeySize = " << n_lambda <<
              "****\n";




    for(int T = 0; T< Num_tests; T++)
    {


        msg = data[T].first;
        payload = typo = data[T].second;
        size_t AE_CtxtSize = 2* KEYSIZE_BYTES + payload.size();

        size_t CondEncCPSLKCtxSize = 3 * sizeof(size_t) + (sizeof(char) * AE_CtxtSize) +  PailCtxtSize;
        CondEncCPSLKCtxSize_Sum =CondEncCPSLKCtxSize_Sum + CondEncCPSLKCtxSize;

        char CAPSLOCK_Pred_Char_ORigCTx [CAPSLocOrigCtxSize];
        char CAPSLOCK_Pred_ctx_typo_Bytes [CondEncCPSLKCtxSize];


        // msg = "HassanHassanHassanHassanHassan";
        // payload = typo = "hASSANhASSANhASSANhASSANhASSAN";
        // msg = "Hassan";
        // payload = typo = "hASSAN";

        cout  <<msg << "\n" << typo << "\n";

        auto start_Enc = high_resolution_clock::now();
        int OrigEncRst = 0;
        OrigEncRst = CAPLOCKpredicate::Enc(pkobj._ppk, msg, CAPSLOCK_Pred_Char_ORigCTx);
        auto stop_Enc = high_resolution_clock::now();
        auto duration_Enc = duration_cast<milliseconds>(stop_Enc - start_Enc);
        // cout << OrigEncRst << "\n";
        // string regrecovered;
        // int s;
        // s = CAPLOCKpredicate::RegDec(pkobj._ppk,
        //                  CAPSLOCK_Pred_Char_ORigCTx,
        //                  pkobj._psk,
        //                  regrecovered, _len);

        // std::string ctx_final;
        auto start_CondEnc = high_resolution_clock::now();
        auto ctx_final = CAPLOCKpredicate::CondEnc(pkobj._ppk, CAPSLOCK_Pred_Char_ORigCTx, typo,
            payload,_len, Threshold, CAPSLOCK_Pred_ctx_typo_Bytes);
        auto stop_CondEnc = high_resolution_clock::now();
        auto duration_CondEnc = duration_cast<milliseconds>(stop_CondEnc - start_CondEnc);
        // cout << ctx_final << "\n";
        string recovered_hd2Bytes;
        int CondDecOut = 0;

        auto start_CondDec = high_resolution_clock::now();

        CondDecOut = CAPLOCKpredicate::CondDec(pkobj._ppk, CAPSLOCK_Pred_ctx_typo_Bytes, pkobj._psk, Threshold, recovered_hd2Bytes, _len, SizeShare);
        auto stop_CondDec = high_resolution_clock::now();
        auto duration_CondDec= duration_cast<milliseconds>(stop_CondDec- start_CondDec);
        // cout << "Hassan3\n";
        // cout << CondDecOut << "\n";
//        free(ED1_Char_ORigCTx);
//        free(ED1_ctx_typo_Bytes);

        CondEnc << "Enc.Time, CondEnc.Time, Cond.Dec.Time, Ctx.Size, CondCtx.Size, CondDecRslt: (" <<
                  duration_Enc.count()
                  << ", " << duration_CondEnc.count()
                  << ", " << duration_CondDec.count()
                  << ", " << CAPSLocOrigCtxSize
                  << ", " << CondEncCPSLKCtxSize
                  << ", " << CondDecOut << " )\n";



        duration_Enc_Sum =  duration_Enc_Sum + duration_Enc.count();
        duration_CondEnc_Sum =  duration_CondEnc_Sum + duration_CondEnc.count();
        duration_CondDec_Sum =  duration_CondDec_Sum + duration_CondDec.count();

//        Class_OrPredicate.reset();
//        delete Class_OrPredicate;
//        Class_OrPredicate = NULL;
//        Class_OrPredicate = nullptr;
        cout << T << "\n";
    }

    string File1 = "CAPSLKdataL.dat";
    std::ofstream CondEncORpred(File1, std::ios_base::app | std::ios_base::out);

    CondEncORpred << _len << "\t" << duration_Enc_Sum / Num_tests << "\t"
                  << duration_CondEnc_Sum / Num_tests << "\t"
                  << duration_CondDec_Sum / Num_tests << "\t"
                  << CAPSLocOrigCtxSize << "\t"
                  << CondEncCPSLKCtxSize_Sum /Num_tests << "\n";

    cout << "CAPSLOCK Error predicate is finished L =" <<_len << "\n";
    CondEncORpred.close();
    paillier_freepubkey(pkobj._ppk);
    paillier_freeprvkey(pkobj._psk);
    // free(CAPSLOCK_Pred_Char_ORigCTx);
    // free(CAPSLOCK_Pred_ctx_typo_Bytes);
    return 1;
}
