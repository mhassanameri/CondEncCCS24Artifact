//
// Created by mameriek on 9/26/23.
//


/*
 * In this document we will provide and extensive performance evaluation
 * of our suggested conditional encryption schemes designed for different
 * binary predicates like: CAPSLOCK on, Edit distance at most one, Hamming Distance (at most 1, 2, 3 and 4) and OR of
 * (CAPSLOCK, Edit distance at most one, Hamming distance at most 2).
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

int GenerateBlankDataFilesToStorEvaluationResults(int l);
int GenerateDataForPlottingFig1a(int Num_tests);

string random_msg() {
    SecByteBlock s(32);
    PRNG.GenerateBlock(s.data(), s.size());
    return string(s.begin(), s.end());
}


/*
 * Executing this test case will generate and initilize the .dat files which store the performance evaluation
 * results like average time for regular encryption, Conditional Encryption and Condtiontional decryption as well as
 * the regular and conditional encryption ciphertext size.
 * */
TEST_CASE("GenerateBlankDatFiles")
{

    int Result =0;
    Result  = GenerateBlankDataFilesToStorEvaluationResults(0);

}


string SelectRandPwd();

/*
 * This function takes as input the FileName containing the set of passwords and their corresponding typos and load
 * them to an array which will be used as the inputs of the functions testing conditional encryption.
 *
 */
std::vector<std::pair<std::string, std::string>> LoadPWDvsTypoForTEST(const std::string& FileName);

/*
 * "testCondEncHamDist":
 * This function Evaluates Conditional Encryption performance which is associated to the Hamming distance.
 * Conditional Decryption applies the small Field Optimization.
 * It takes as input:
 *  n_lambda: the public key size  [e.g., 1024, 2048, 3072 bits modulus]
 *  Num_tests: Number of times that we performed Conditional encryption (Enc, CondEnc, CondDec)
 *  _len: The upper bound of the input secret message length (m_1) [e.g., 8, 16, 32, 64, 128 characters]
 *  MaxHam Distance: The maximum allowed Hamming distance of the control message: [0, 1, 2, 3, 4]
 *
 */
int testCondEncHamDist(int n_lambda, int Num_tests, size_t _len, int MaxHam);

/*
 * "testCondEncHamDist_NonOPT":
 * This function Evaluates Conditional Encryption performance which is associated to the Hamming distance.
 * Conditional Decryption is done without any optimization.
 * It takes as input:
 *  n_lambda: the public key size  [e.g., 1024, 2048, 3072 bits modulus]
 *  Num_tests: Number of times that we performed Conditional encryption (Enc, CondEnc, CondDec)
 *  _len: The upper bound of the input secret message length (m_1) [e.g., 8, 16, 32, 64, 128 characters]
 *  MaxHam Distance: The maximum allowed Hamming distance of the control message: [0, 1, 2, 3, 4]
 *
 */
int testCondEncHamDist_NonOPT(int n_lambda, int Num_tests, size_t _len, int MaxHam);


/*
 * "testCondEncEDist":
 * This function Evaluates Conditional Encryption performance designed for the Edit distance at most one predicate.
 * It takes as input:
 *  n_lambda: the public key size  [e.g., 1024, 2048, 3072 bits modulus]
 *  Num_tests: Number of times that we performed Conditional encryption (Enc, CondEnc, CondDec)
 *  _len: The upper bound of the input secret message length (m_1) [e.g., 8, 16, 32, 64, 128 characters]
 *  MaxHam Distance: The maximum allowed Hamming distance of the control message: [0, 1, 2, 3, 4]
 *
 */
int testCondEncEDist(int n_lambda,  int Num_tests, size_t _len);


/*
 * "testCondEncOR":
 * This function Evaluates Conditional Encryption performance designed for the OR (OR of CAPSLOCK,  Hamming Distance at
 * most two, Edit distance at most one) predicate.
 * It takes as input:
 *  n_lambda: the public key size  [e.g., 1024, 2048, 3072 bits modulus]
 *  Num_tests: Number of times that we performed Conditional encryption (Enc, CondEnc, CondDec)
 *  _len: The upper bound of the input secret message length (m_1) [e.g., 8, 16, 32, 64, 128 characters]
 *  MaxHam Distance: The maximum allowed Hamming distance of the control message: [MaxHam =2  for our OR predicate]
 *
 */
int testCondEncOR(int n_lambda, int Num_tests, size_t _len, int MaxHam);


/*
 * "testCondEncCAPSLOCK":
 * This function Evaluates Conditional Encryption preformance designed for the CAPSLOCK ON predicate.
 * It takes as input:
 *  n_lambda: the public key size  [e.g., 1024, 2048, 3072 bits modulus]
 *  Num_tests: Number of times that we performed Conditional encryption (Enc, CondEnc, CondDec)
 *  _len: The upper bound of the input secret message length (m_1) [e.g., 8, 16, 32, 64, 128 characters]
 *
 */
int testCondEncCAPSLOCK(int n_lambda, int Num_tests, size_t _len);




inline int DataForPlottingFigure1(string argv[] )
{


    if(argv[0] == "PlotFig1a")
    {
        // auto r16_1 = testCondEncHamDist(1024, 300, 16, 1);
        // auto OR_32 = testCondEncOR(1024, 100, 32, 30);
    }
    else if(argv[0] == "PlotFig1aNo128")
    {

    }

    return 1;
}

TEST_CASE("ArtifactCCS24")
{
    std::string input[4];
    std::ifstream inputFile("input.txt"); // Open the file "input.txt"
    inputFile >> input[0]; //put the first line as the first argument
    inputFile >> input[1]; //put the second line as the second argument and the same for 2 and 3
    inputFile >> input[2];
    inputFile >> input[3];


// std::cout << "Please enter your input [PlotFig1a, PlotFig1b]: ";
    // std::cin >> input[0];
    // std::cout << "Please enter n_lambda which indicates the public key size [1024, 2048, 3072]: ";
    // std::cin >> input[1];
    // std::cout << "Please enter Num_tests (for full text the value is 1000): ";
    // std::cin >> input[2];
    // std::cout << "Please enter maximum length of secret message (_len) [8, 16, 32, 64, 128]";


    // auto r = DataForPlottingFigure1a(input);

}


TEST_CASE("DataPlotFig1a")
{


    // auto r_test =  GenerateDataForPlottingFig1a(1);
    auto OR_32 = testCondEncOR(1024, 100, 32, 30);


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

TEST_CASE("Table One Comparing All OPT vs No OPT when Predicate is holding" )
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
