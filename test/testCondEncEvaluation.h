//
// Created by mameriek on 9/26/23.
//


/*
 * In this document we will provide and extensive performance evaluation
 * of our suggested conditional encryption schemes designed for different
 * binary predicates.
 *
 * */

#ifndef CONDENCCPP_TESTCONDENCEVALUATION_H
#define CONDENCCPP_TESTCONDENCEVALUATION_H


#include <iostream>
#include <string>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <netdb.h>
#include <sys/uio.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <fstream>
#include <random>

#include  "pkcspad.h"
#include "PK_crypto.h"


#define CATCH_CONFIG_MAIN // This should come **before** including the 'catch.hpp'.
#include "catch.hpp"


//#include "db.pb.h"
#include "PaillierWrapperFunctions.h"
#include "CryptoSymWrapperFunctions.h"

#include "ConditionalEncryptionHamDistTwo.h"
#include "ConditionalEncryptionOR.h"
#include "ConditionalEncryptionCAPSLOCK.h"
#include "ConditionalEncryptionEditDistOne.h"
#include <iostream>
#include <fstream>
#include <chrono>




using namespace std::chrono;
using std::vector;

string random_msg() {
    SecByteBlock s(32);
    PRNG.GenerateBlock(s.data(), s.size());
    return string(s.begin(), s.end());
}

TEST_CASE("Generating Raw data files for storing the extracted data after testing")
{

    std::ofstream HDdataL("HDdataL.dat", std::ios_base::app | std::ios_base::out);
    std::ofstream HDdataT("HDdataT.dat", std::ios_base::app | std::ios_base::out);
    std::ofstream EDOnedataL("EDOnedataL.dat", std::ios_base::app | std::ios_base::out);
    std::ofstream CAPSLKdataL("CAPSLKdataL.dat", std::ios_base::app | std::ios_base::out);
    std::ofstream ORdataL("ORdataL.dat", std::ios_base::app | std::ios_base::out);
    std::ofstream SSdataL("SecretSharing.dat", std::ios_base::app | std::ios_base::out);


    HDdataL << "L" << "\t" << "Enc" << "\t" << "CondEnc"<< "\t" << "CondDec" << "\t" << "CtxtSize" << "\t" << "CondCtxtSize\n";
    HDdataT << "T" << "\t" << "Enc" << "\t" << "CondEnc"<< "\t" << "CondDec" << "\t" << "CtxtSize" << "\t" << "CondCtxtSize\n";
    EDOnedataL << "L" << "\t" << "Enc" << "\t" << "CondEnc"<< "\t" << "CondDec" << "\t" << "CtxtSize" << "\t" << "CondCtxtSize\n";
    CAPSLKdataL << "L" << "\t" << "Enc" << "\t" << "CondEnc"<< "\t" << "CondDec" << "\t" << "CtxtSize" << "\t" << "CondCtxtSize\n";
    ORdataL << "L" << "\t" << "Enc" << "\t" << "CondEnc"<< "\t" << "CondDec" << "\t" << "CtxtSize" << "\t" << "CondCtxtSize\n";
    SSdataL << "T" << "\t" << "Recover\n";
}


string SelectRandPwd();

std::vector<std::pair<std::string, std::string>> LoadPWDvsTypoForTEST(const std::string& FileName);

//We note that the AE_CtxtSize =24 and the SizeShare = 28;
int testCondEncHamDist(int n_lambda, int Num_tests, size_t _len, int Threshold, size_t AE_CtxtSize1, size_t SizeShare);

int testCondEncEDist(int n_lambda,  int Num_tests, size_t _len, int Threshold, size_t AE_CtxtSize, int NumOfErrs);
int testCondEncOR(int n_lambda, int Num_tests, size_t _len, int Threshold, size_t AE_CtxtSize, size_t SizeShare);

int testCondEncCAPSLOCK(int n_lambda, int Num_tests, size_t _len, int Threshold, size_t AE_CtxtSize1, size_t SizeShare);


inline int main_test(string argv[] )
{


    if(argv[0] == "PlotFig1a")
    {

        auto r16_1 = testCondEncHamDist(1024, 300, 16, 15, 24, 28);
        auto r16_2 = testCondEncHamDist(1024, 300, 16, 14, 24, 28);
        auto r16_3 = testCondEncHamDist(1024, 100, 16, 13, 24, 28);
        auto r16_4 =testCondEncHamDist(1024, 50, 16, 12, 24, 28);

        auto r32_1 = testCondEncHamDist(1024, 300, 32, 31, 24, 28);
        auto r32_2 = testCondEncHamDist(1024, 300, 32, 30, 24, 28);
        auto r32_3 = testCondEncHamDist(1024, 100, 32, 29, 24, 28);
        auto r32_4 =testCondEncHamDist(1024, 50, 32, 28, 24, 28);

        auto r64_1 = testCondEncHamDist(2048, 100, 64, 63, 24, 28);
        auto r64_2 = testCondEncHamDist(2048, 100, 64, 62, 24, 28);
        auto r64_3 = testCondEncHamDist(2048, 25, 64, 61, 24, 28);
        auto r64_4 = testCondEncHamDist(2048, 5, 64, 60, 24, 28);

        auto r128_1 = testCondEncHamDist(3072, 3, 128, 127, 24, 28);
        auto r128_2 = testCondEncHamDist(3072, 1, 128, 126, 24, 28);
        auto r128_3 = testCondEncHamDist(3072, 1, 128, 125, 24, 28);
        auto r128_4 = testCondEncHamDist(3072, 10, 128, 124, 24, 28);

    }


    return 1;
}

TEST_CASE("CommandLine")
{
    std::string input[6];

    std::cout << "Please enter your input [PlotFig1a, PlotFig1b]: ";
    std::cin >> input[0];
    // std::cout << "Please enter n_lambda which indicates the public key size [1024, 2048, 3072]: ";
    // std::cin >> input[1];
    // std::cout << "Please enter Num_tests (for full text the value is 1000): ";
    // std::cin >> input[2];
    // std::cout << "Please enter maximum length of secret message (_len) [8, 16, 32, 64, 128]";
    auto r = main_test(input);

}


TEST_CASE("Loading test data")
{



    // std::string filename = "PWDvsTyposDataSet/PWDvsTypoDataSetLessThan8.txt";
    // std::vector<std::pair<std::string, std::string>> data = LoadPWDvsTypoForTEST(filename);
    //
    // // // Output the content of the vector
    // for (const auto& pair : data) {
    //     std::cout << "Column 1:" << pair.first << ", Column 2:" << pair.second << std::endl;
    // }

}

TEST_CASE("CAPSLOCK On Error")
{

    // auto TestRsl8 = testCondEncCAPSLOCK(1024, 1000, 8, 6, 24, 28);
    // auto TestRsl16 = testCondEncCAPSLOCK(1024, 1000, 16, 14, 24, 28);
    // auto TestRsl32 = testCondEncCAPSLOCK(1024, 1000, 32, 30, 24, 28);
    // auto TestRsl64 = testCondEncCAPSLOCK(2048, 1000, 64, 62, 24, 28);
    // auto TestRsl128 = testCondEncCAPSLOCK(3072, 1000, 128, 126, 24, 28);

}

TEST_CASE("Conditional Encryption: Hamming Distance: (n_lambda: 1024, 20, _len: 8, Threshold: 6, AE_CtxtSize 24, SizeShare: 28)  ")
{


    // testCondEncHamDist(1024, 1000, 16, 16, 24, 28);
    // testCondEncHamDist(1024, 300, 16, 15, 24, 28);
    // testCondEncHamDist(1024, 500, 16, 14, 24, 28);
    // testCondEncHamDist(1024, 300, 16, 13, 24, 28);
    // testCondEncHamDist(1024, 300, 16, 12, 24, 28);
    //
    //
    // auto r32_0 = testCondEncHamDist(1024, 10, 32, 32, 24, 28);
    // auto r32_1 = testCondEncHamDist(1024, 300, 32, 31, 24, 28);
    // auto r32_2 = testCondEncHamDist(1024, 300, 32, 30, 24, 28);
    // auto r32_3 = testCondEncHamDist(1024, 100, 32, 29, 24, 28);
    // auto r32_4 =testCondEncHamDist(1024, 50, 32, 28, 24, 28);
    //
    //
    //
    // auto r64_0 = testCondEncHamDist(2048, 500, 64, 64, 24, 28);
    // auto r64_1 = testCondEncHamDist(2048, 100, 64, 63, 24, 28);
    // auto r64_2 = testCondEncHamDist(2048, 100, 64, 62, 24, 28);
    // auto r64_3 = testCondEncHamDist(2048, 25, 64, 61, 24, 28);
    // auto r64_4 = testCondEncHamDist(2048, 5, 64, 60, 24, 28);
    //
    //
    // auto r128_0 = testCondEncHamDist(3072, 1000, 128, 128, 24, 28);
    // auto r128_1 = testCondEncHamDist(3072, 3, 128, 127, 24, 28);
    // auto r128_2 = testCondEncHamDist(3072, 1, 128, 126, 24, 28);
    // auto r128_3 = testCondEncHamDist(3072, 1, 128, 125, 24, 28);
    //auto r128_4 = testCondEncHamDist(3072, 10, 128, 124, 24, 28);



}

TEST_CASE("Conditional Encryption: Edit Distance at most one: (n_lambda: 1024, 20, _len: 8, AE_CtxtSize 24, SizeShare: 28)  ")
{

    std::ofstream EDOnedataL("EDOnedataL.dat", std::ios_base::app | std::ios_base::out);
    EDOnedataL << "L" << "\t" << "Enc" << "\t" << "CondEnc"<< "\t" << "CondDec" << "\t" << "CtxtSize" << "\t" << "CondCtxtSize\n";


    // auto TestRsl8 = testCondEncEDist(1024, 1000, 8, 1, 24, 28);
    // auto TestRsl16 = testCondEncEDist(1024, 1000, 16, 1, 24, 28);
    // auto TestRsl32 = testCondEncEDist(1024, 1000, 32, 1, 24, 28);
    // auto TestRsl64 = testCondEncEDist(2048, 800, 64, 1, 24, 28);
    // auto TestRsl128 = testCondEncEDist(3072, 400, 128, 1, 24, 28);
}

TEST_CASE("OR predicate" )
{
    std::ofstream ORdataL("ORdataL.dat", std::ios_base::app | std::ios_base::out);
    ORdataL << "L" << "\t" << "Enc" << "\t" << "CondEnc"<< "\t" << "CondDec" << "\t" << "CtxtSize" << "\t" << "CondCtxtSize\n";

    // auto rsltOr8 = testCondEncOR(1024, 200, 8, 6, 24, 28);
    // testCondEncOR(1024, 200, 16, 14, 24, 28);
    // auto rsltOr32 = testCondEncOR(1024, 100, 32, 30, 24, 28);
    // auto rsltOr = testCondEncOR(2048, 50, 64, 62, 24, 28);
    // auto rsltOr127 =testCondEncOR(3072, 50, 128, 126, 24, 28);
}

TEST_CASE("Tabke One Comparing All OPT vs No OPT when Predicate is holding" )
{
    // std::ofstream ORdataL("Table1.dat", std::ios_base::app | std::ios_base::out);
    // ORdataL << "L(SecondOPT)" << "\t" << "Enc" << "\t" << "CondEnc"<< "\t" << "CondDec" << "\t" << "CtxtSize" << "\t" << "CondCtxtSize\n";

    // auto r32_0 = testCondEncHamDist(1024, 500, 32, 32, 24, 28);
    // auto r32_1 = testCondEncHamDist(1024, 500, 32, 31, 24, 28);
    // auto r32_2 = testCondEncHamDist(1024, 150, 32, 30, 24, 28);
    // auto r32_3 = testCondEncHamDist(1024, 300, 32, 29, 24, 28);
    // auto r32_4 =testCondEncHamDist(1024, 100, 32, 28, 24, 28);
    // testCondEncOR(1024, 200, 32, 30, 24, 28);
    // auto TestRsl32 = testCondEncEDist(1024, 400, 32, 1, 24, 28);
    // auto TestRsl8 = testCondEncCAPSLOCK(1024, 400, 32, 30, 24, 28);
    // auto TestOR = testCondEncOR(1024, 200, 32, 30, 24, 28);


}

#endif //TYPTOP_TESTCONDENCEVALUATION_H
