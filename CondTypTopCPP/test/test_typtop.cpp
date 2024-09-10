//
// Created by rahul on 3/30/17.
//

#include "typtop.h"
#include "catch.hpp"

#include <iostream>
#include <fstream>
#include <chrono>
using namespace std::chrono;

#define DEBUG 1
#define times(n, code_block) {for(int _ti=0; _ti<n; _ti++) code_block;}

const string _db_fname = "./test_typtop_db";
//const vector<string> pws = {
//        "hello_pass", // 0, ed=0
//        "Hello_pass",  // 1, ed=1
//        "hello_pass1", // 2, ed=1
//        "HELLO_PASS",  // 3, ed=1
////        "hlelo_pass", // 4, ed=1
//        "hello_pash", // 4, ed=1
////        "hello_Pass",  // 5, ed=2
//        "hello_pas",  // 5, ed=1
//};


const vector<string> pws = {
        "ABC123RockYou", // 0, ed=0
        "ABC123ockYou",  // 1, ed=1, One char deletion
        "ABC123RockYouh", // 2, ed=1, One char addition
//        "ABC123ROCKYOU",  // 3, Capslock on (all the lower case letter will be transfer to th upper letter case.This typo is happen for mac OS.
        "ABC123gockYou",  // 3, hd = 1, Hammind dsitance equal 1.
        "abc123rOCKyOU", // 4, Cahnge the lower case chars to upper case and vice versa.
        "ABC123focktou",  // 5, hd =2; replacing two characters with other chars.
};

/*
 * pwd_wrong is the vector of wrong password which has
 * high distance from the original password, i.e., pwd[0].
 * */
const vector<string> pws_wrong = {
        "ABB12345",
        "ABB12345@#$",
        "8983ersyEDG21@",
        "FGH5647#$%pSms123",
        "LSKDs 65%%^^d",
        "7u7shbfgegbs!@##$45e45%^%",
};

string install_id; // get_install_id();
const int32_t infinity = INT_MAX;

class TypTopTest : public TypTop {
public:
    TypTopTest() : TypTop(_db_fname) {};
    using TypTop::add_to_waitlist;
    using TypTop::get_db;
    using TypTop::get_ench;
    using TypTop::get_pkobj;
    using TypTop::permute_typo_cache;
    using TypTop::initialize;
    using TypTop::reinitialize;
};

TEST_CASE("Generating Raw data files for storing the extracted data after testing")
{

    std::ofstream TyptopCondOPT("TypTopCondOPT.dat", std::ios_base::app | std::ios_base::out);

    TyptopCondOPT << "TypTopType" <<"\t" << "Init" << "\t" << "usrLoginNotif(Correct)" << "\t" << "usrLoginNotif(Incorrect)" <<"\t" << "TotalProcessingTimeCorrectLogin"<< "\t" << "TotalProcessingTimeIncorrectLogin" << "\t" << "ProcessWaitListContainsValidTypo" << "\t" << "WaitListSize" <<"\n";

}



TEST_CASE("Symmetric Authenticated Encryption"){
    SECTION("EncDecSymAuth")
    {
        string b(AES::DEFAULT_KEYLENGTH, 0);
        string test  = "TESTTEST";
        string EncrypteKey;
        PRNG.GenerateBlock((byte *) b.data(), b.size());
        CryptoSymWrapperFunctions::Wrapper_AuthEncrypt(b, test, EncrypteKey);

        string plain_text, plain_text2;
        CryptoSymWrapperFunctions::Wrapper_AuthDecrypt(b, EncrypteKey, plain_text);

        assert (plain_text == test);
        SecByteBlock salt, key;
//        salt.resize(SALTSIZE_BYTES_HASH);
//        PRNG.GenerateBlock(salt, SALTSIZE_BYTES_HASH);
        auto start = std::chrono::high_resolution_clock::now();

        CryptoSymWrapperFunctions::Wrapper_AuthEncrypt_Hardened(b, test, EncrypteKey);
//
//        CryptoSymWrapperFunctions::Wrapper_slow_hash(b, salt, key);

        auto stop = std::chrono::high_resolution_clock::now();

        auto duration = duration_cast< std::chrono::milliseconds>(stop - start);
        double time  = duration.count();
        cout << "The time for one slow hash function: " << time << "\n";


        CryptoSymWrapperFunctions::Wrapper_AuthDecrypt_Hardened(b, EncrypteKey, plain_text2);

        assert (plain_text2 == test);


    }
}

TEST_CASE("typtop_util") {
    install_id = get_install_id();
    SECTION("edit_distance") {
        byte b[] = {0x32, 0xf4, 0x32, 0x65, 0xff};
        string b_str((char *) b, 5);
        REQUIRE(edit_distance(pws[0], pws[0]) == 0);
        CHECK(edit_distance(b_str, b_str) == 0);
        CHECK(edit_distance(pws[0], pws[1]) == 1);
        CHECK(edit_distance(pws[0], pws[2]) == 1);
        CHECK(edit_distance(pws[0], pws[3]) == 1);
        CHECK(edit_distance(pws[0], pws[4]) == 1);
        CHECK(edit_distance(pws[0], pws[5]) == 2);
    }
    SECTION("get_typos") {
        vector<string> typos(10);
        // hello_pass
//        vector<string> should_be = {
//                "Hello_pass", "HELLO_PASS", "hello_pass1", "ello_pass", "hello_pas",
//                "hello_pass`"
//        };

        vector<string> should_be = {
                "ABC123RockYou", "abc123rOCKyOU", "aBC123RockYou", "ABC123RockYo", "BC123RockYou",
                "ABC123RockYou1", "ABC123RockYou`", "ABC123ROCKYOU", "abc123rockyou"
        };


        get_typos(pws[0], typos);
        REQUIRE(typos.size() == 10);//TODO: Probably I need to make sure that he size of the typo should be lower thatn 32 chars of bytes.
        CHECK(std::find(typos.begin(), typos.end(), pws[0]) == typos.end());
        for (auto ti: should_be) {
            CHECK(std::find(typos.begin(), typos.end(), ti) != typos.end());
        }
    }
    SECTION("win(f_o, f_n)") {
        REQUIRE(win(0, INT_MAX));
        REQUIRE_FALSE(win(-1, 0));
        REQUIRE(win(-1, 1));
        REQUIRE(win(-1, INT_MAX));
        REQUIRE_FALSE(win(INT_MAX, 0));
        REQUIRE_FALSE(win(INT_MAX, INT_MAX));
        REQUIRE_FALSE(win(INT_MAX - 4, 5));
        CHECK_FALSE(win(1, 0));
        //CHECK_THROWS(win(0, 0));
    }
    SECTION("typo_policy_abs_entropy_cutoff") {
        typtop::TypoPolicy tp;
        string pw[2] = {"Password1!", "Password1"};
        tp.set_rel_entcutoff(10);
        REQUIRE(entropy(pw[1]) < 6); // weak password
        CHECK_FALSE(meets_typo_policy(pw[0], pw[1], tp)); // fails abs_cutoff
        tp.set_abs_entcutoff(5);
        CHECK(meets_typo_policy(pw[0], pw[1], tp)); // passes abs_cutoff of 5

        tp.set_rel_entcutoff(2);
        REQUIRE((entropy(pw[0]) - entropy(pw[1])) > 2);
        CHECK_FALSE(meets_typo_policy(pw[0], pw[1], tp)); // fails rel_ent_cutoff
    }
    SECTION("meets_typo_policy") {
        const typtop::TypoPolicy tp;
        CHECK(meets_typo_policy(pws[0], pws[0], tp));
        CHECK(meets_typo_policy(pws[0], pws[4], tp));
//        CHECK(meets_typo_policy(pws[0], pws[5], tp));
        CHECK(meets_typo_policy(pws[3], swapcase(pws[3]), tp));
        CHECK(meets_typo_policy(pws[0], pws[3], tp)); // edit distance >1
//        CHECK_FALSE(meets_typo_policy(pws[0], pws[5], tp)); // edit distance >1
        CHECK_FALSE(meets_typo_policy(pws[0].substr(6), pws[0].substr(0, 6), tp)); // pw length too small
        CHECK_FALSE(meets_typo_policy(pws[0].substr(0, 6), pws[1].substr(0, 6), tp)); // pw length too small
    }
}

TEST_CASE("Test TypTop DB") {
    install_id = get_install_id();
    remove(_db_fname.c_str()); // fresh initialization
    TypTopTest tp;
    const typoDB &db = tp.get_db();
    REQUIRE(db.h().sys_state() == SystemStatus::UNINITIALIZED);

    auto start = high_resolution_clock::now();
    tp.initialize(pws[0]);
    auto stop = high_resolution_clock::now();

    auto time_init = duration_cast<milliseconds>(stop - start);/* Computes the execution time of initialization phase*/

    tp.check(pws[0], SECOND_TIME, false);
    REQUIRE(db.h().sys_state() == SystemStatus::ALL_GOOD);
    const PkCrypto &pkobj = tp.get_pkobj();
    REQUIRE(db.w_size() == W_size);
    REQUIRE(db.t_size() == T_size);

    SECTION("Install id") {
        CHECK(tp.this_install_id() == install_id);
        CHECK(db.ch().install_id() == install_id);
    }

    SECTION("post install checks") {
        EncHeaderData ench;
        string ench_str, ctx, rdata, sk_str;

        PkCrypto mut_pkobj(pkobj);
        PwPkCrypto t;
        REQUIRE(CryptoSymWrapperFunctions::Wrapper_AuthDecrypt_Hardened(pws[0], db.t(0), sk_str));
//        mut_pkobj.set_sk(sk_str);
        mut_pkobj.set_sk_Pail(sk_str);
        string ctx_h_test = db.h().enc_header();

        PaillerWrapperFunctions::Pail_Classic_Dec(pkobj._ppk,&ctx_h_test[0],pkobj._psk,ench_str,112 );//TODO: check what is the size _len?
        REQUIRE(ench.ParseFromString(ench_str));
        REQUIRE(ench.freq_size() == T_size);
        REQUIRE(ench.last_used_size() == T_size);

//        SECTION("check permutation") {
//            vector<string> T(db.t().begin(), db.t().end());
//            tp.permute_typo_cache(sk_str);
//            const EncHeaderData &new_ench = tp.get_ench();
//            /* Check if the first entry matches */
//            CHECK(db.t(0) == T[0]); // Fist index should always match
//            CHECK(new_ench.last_used(0) == ench.last_used(0));
//            CHECK(new_ench.freq(0) == ench.freq(0));
//            /* check if all other entry matches */
//            int j = 0;
//            bool at_least_permuted = false;
//            for (int i = 0; i < T_size; i++) {
//                for (j = 0; j < T_size; j++) {
//                    if (db.t(j) == T[i]) {
//                        CHECK(new_ench.freq(j) == ench.freq(i));
//                        CHECK(new_ench.last_used(j) == ench.last_used(i));
//                        at_least_permuted |= (i != j);
//                        // cerr << i << " <<-->> " << j << endl;
//                        // break;
//                    }
//                }
//            }
//            REQUIRE(at_least_permuted);
        }

//        SECTION("Verify inserted typos") {
//            vector<string> typos(T_size);
//            get_typos(pws[0], typos);
//            string sK_str;
//            typos.insert(typos.begin(), pws[0]);
//            REQUIRE(CryptoSymWrapperFunctions::Wrapper_AuthDecrypt_Hardened(pws[0], db.t(0), sK_str));
//            for(int j=1; j<T_size; j++) {
//                size_t i=0;
//                for(i=0; i<typos.size(); i++){
//                    // cerr << "<<-- checking >> " << typos[i] << endl;
//                    if (CryptoSymWrapperFunctions::Wrapper_AuthDecrypt_Hardened(typos[i], db.t(j), sK_str))
//                        break;
//                }
//                CHECK(i < typos.size());
//            }
//        }

//        SECTION("Check(pw)") {
//            CHECK(db.h().sys_state() == SystemStatus::ALL_GOOD);
//            string ctx_db_h_enc_header = db.h().enc_header();
//            int RecRslt = 0;
//            RecRslt = PaillerWrapperFunctions::Pail_Classic_Dec(pkobj._ppk, &ctx_db_h_enc_header[0], pkobj._psk, ench_str, 109);
//            CHECK(tp.check(pws[0], FIRST_TIME, false));
//            ench.Clear();
//            ench.ParseFromString(ench_str);
//            CHECK(ench.pw() == pws[0]);
//            CHECK(tp.check(pws[0], FIRST_TIME, false));
//        }

//        SECTION("step-by-step 'check' function") {
//            ench.Clear();
//            string enc_header_str;
//            /* Standard book-keeping */
//            CHECK(CryptoSymWrapperFunctions::Wrapper_AuthDecrypt_Hardened(pws[0], db.t(0), sk_str));
//            mut_pkobj.set_sk_Pail(sk_str);
//            int RecRslt;
//            string enc_heder_non_const = db.h().enc_header();
//            RecRslt = PaillerWrapperFunctions::Pail_Classic_Dec(pkobj._ppk, &enc_heder_non_const[0], pkobj._psk, enc_header_str, 109);
//            ench.ParseFromString(enc_header_str);
//            CHECK(ench.pw() == pws[0]);
//
//            CHECK(ench.IsInitialized());
//            string ench_ctx,ench_plaintxt,  _t_ench_str;
////            pkobj.pk_encrypt(ench.SerializeAsString(), ench_ctx);
////            pkobj.Paill_pk_encrypt(ench.SerializeAsString(), ench_ctx);
//            ench_plaintxt =  ench.SerializeAsString();
//            char*  ench_ctx_byte = (char*) malloc (mut_pkobj.Return_pk_size(mut_pkobj._ppk)) ;
//            PaillerWrapperFunctions::Pail_Classic_Enc(ench_plaintxt, mut_pkobj._ppk, ench_ctx_byte);
////            pkobj.pk_decrypt(ench_ctx, _t_ench_str);
//            PaillerWrapperFunctions::Pail_Classic_Dec(mut_pkobj._ppk, ench_ctx_byte, mut_pkobj._psk, _t_ench_str, 109);
////            pkobj.Paill_pk_decrypt(ench_ctx, _t_ench_str, 0);
//            // db.mutable_h()->set_enc_header(ench_ctx);
//            free(ench_ctx_byte);
//            CHECK(_t_ench_str == ench.SerializeAsString());
//            ench.Clear();
//        }
//
//        SECTION("Reinitializing tests") {
//            string old_salt = db.ch().global_salt();
//            tp.reinitialize(pws[0]);
//            CHECK(old_salt == db.ch().global_salt());
//        }
//    }

//    SECTION("add_to_waitlist") {
//        SECTION("one typo add") { // Please make sure added typo is not in the typo cache
//            int indexj = db.h().indexj();
//            tp.add_to_waitlist("Blahblah", now());
//            CHECK((indexj + 1) % W_size == db.h().indexj());
//            CHECK(db.w_size() == W_size);
//        }
//        SECTION("add 20 typos") {
//            int indexj = db.h().indexj();
//            for (int i = 0; i < W_size; i++)
//                tp.add_to_waitlist("Blahblah", now());
//            REQUIRE(indexj == db.h().indexj());
//            REQUIRE(db.w_size() == W_size);
//        }
//        size_t t = 0;
//        for(int i=0; i<db.w_size(); i++) {
//            if (t<=0) t = db.w(i).size();
//            else
//            {
////                CHECK(t == db.w(i).size());
////                CHECK(t == strlen( db.w(i)));
//            }
//
//        }
//    }

//    SECTION("persistence of the db on re-reading") {
//        TypTopTest tp1;
//        REQUIRE(tp1.check(pws[0], PAM_RETURN::SECOND_TIME, false));
//        tp1.save();
//        TypTopTest tp2;
//
//        const typoDB db1 = tp1.get_db(), db2 = tp2.get_db();
//        // test CH
//        REQUIRE(db1.ch().DebugString() == db2.ch().DebugString());
//        // test H
//        REQUIRE(db1.h().SerializeAsString() == db2.h().SerializeAsString());
//
//        // test W
//        for (int i = 0; i < W_size; i++)
//            REQUIRE(db1.w(i) == db2.w(i));
//        // test T
//        for (int i = 0; i < T_size; i++)
//            REQUIRE(db1.t(i) == db2.t(i));
//
//        // test L
//        REQUIRE(db1.logs().l_size() == db2.logs().l_size());
//        for (int i = 0; i < db1.logs().l_size(); i++)
//            REQUIRE(db1.logs().l(i).SerializeAsString() == db2.logs().l(i).SerializeAsString());
//
//        string s1 = CryptoSymWrapperFunctions::Wrapper_b64encode(tp1.get_db().SerializeAsString());
//        string s2 = CryptoSymWrapperFunctions::Wrapper_b64encode(tp2.get_db().SerializeAsString());
//        REQUIRE(s1.length() == s2.length());
//        REQUIRE(s1.substr(0, 100) == s2.substr(0, 100));
//        CHECK(s1 == s2);
//    }

    SECTION("Test check function") {
        remove(_db_fname.c_str());

        tp.check(pws[0], SECOND_TIME, false); // set the password
        REQUIRE(db.ch().install_id() == install_id);

//        SECTION("check") {
//            REQUIRE(tp.check(pws[0], FIRST_TIME, false));
//            REQUIRE(tp.check(pws[0], FIRST_TIME, false));
//            CHECK(tp.check(pws[1], FIRST_TIME, false));
//            CHECK(tp.check(pws[2], FIRST_TIME, false));
//            CHECK(tp.check(pws[3], FIRST_TIME, false));
//            CHECK_FALSE(tp.check(pws[4], FIRST_TIME, false));
//            CHECK_FALSE(tp.check(pws[5], FIRST_TIME, false));
//        }

        SECTION("try inserting a typo with real pw") {

            REQUIRE(tp.check(pws[0], FIRST_TIME, false));

            auto start_LginOrigPWD = high_resolution_clock::now();
            times(2, CHECK_FALSE(tp.check(pws[0], FIRST_TIME, false)));
            auto stop_LginOrigPWD = high_resolution_clock::now();
            auto time_TotalProcessing_OrignPWD = duration_cast<milliseconds>(stop_LginOrigPWD - start_LginOrigPWD);

            double time_AveTotalProcessing_OrignPWD = time_TotalProcessing_OrignPWD.count()/2;

            string sk_str;


            auto start_Correct_login = high_resolution_clock::now();
            int i =0;
            for(int t=0; t< 5; t++)
            {
                i = tp.is_typo_present(pws[0], sk_str);
//                assert(i==0);
            }
            auto stop_Correct_login = high_resolution_clock::now();
            auto time_UsrNotif_Correct_Lgin = duration_cast<milliseconds>(stop_Correct_login - start_Correct_login); //When we use MHF, sec is the orde of  computations.
            double time_AveUsrNotif_Correct_Lgin = time_UsrNotif_Correct_Lgin.count()/5;

            auto start_Incorrect_login = high_resolution_clock::now();
//            int i =0;
            for(int t=0; t< 1; t++)
            {
                i = tp.is_typo_present(pws[2], sk_str);
//                assert(i == T_size);
                i = tp.is_typo_present(pws[1], sk_str);
//                assert(i == T_size);
                i = tp.is_typo_present(pws[3], sk_str);
//                assert(i == T_size);
//                i = tp.is_typo_present(pws[0], sk_str);
//                assert(i == T_size);
            }
            auto stop_Incorrect_login = high_resolution_clock::now();

//            auto time_UsrNotif = duration_cast<microseconds>(stop - start);
            auto time_UsrNotif_incorrect_Lgin = duration_cast<seconds>(stop_Incorrect_login - start_Incorrect_login); //When we use MHF, sec is the orde of  computations.
            double time_AveUsrNotif_incorrect_Lgin = time_UsrNotif_incorrect_Lgin.count()/3;

            auto start_LginIncrctTypo = high_resolution_clock::now();

//            times(3, CHECK_FALSE(tp.check(pws[2], FIRST_TIME, false)));
//            times(2, CHECK_FALSE(tp.check(pws[1], FIRST_TIME, false)));
//            times(3, CHECK_FALSE(tp.check(pws[3], FIRST_TIME, false)));
//            times(2, CHECK_FALSE(tp.check(pws[5], FIRST_TIME, false)));
//            times(2, CHECK_FALSE(tp.check(pws[4], FIRST_TIME, false)));

            times(1, CHECK_FALSE(tp.check(pws[2], FIRST_TIME, false)));
            times(1, CHECK_FALSE(tp.check(pws[1], FIRST_TIME, false)));
            times(1, CHECK_FALSE(tp.check(pws[3], FIRST_TIME, false)));
            times(1, CHECK_FALSE(tp.check(pws[5], FIRST_TIME, false)));
            times(1, CHECK_FALSE(tp.check(pws[4], FIRST_TIME, false)));


            auto stop_LginIncrctTypo = high_resolution_clock::now();
            auto time_TotalProcessing_IncrctTypo = duration_cast<milliseconds>(stop_LginIncrctTypo - start_LginIncrctTypo);
            double time_AveTotalProcessing_IncrctTypo = time_TotalProcessing_IncrctTypo.count()/5;


            double SizeOfWaitingList = ((db.w(1).size()) * W_size)/1024;






//            times(5, CHECK_FALSE(tp.check(pws[5], FIRST_TIME, false)));

            auto start_Login_WaitListIncludeValidTypo = high_resolution_clock::now();
            REQUIRE(tp.check(pws[0], FIRST_TIME, false));
            auto stop_Login_WaitListIncludeValidTypo = high_resolution_clock::now();
            auto time_Login_WaitListIncludeValidTypo = duration_cast<milliseconds>(stop_Login_WaitListIncludeValidTypo - start_Login_WaitListIncludeValidTypo);


            std::ofstream TyptopCondOPT("TypTopCondOPT.dat", std::ios_base::app | std::ios_base::out);

            TyptopCondOPT << "TypTopCondEnc(mhf/opt)" <<"\t" << time_init.count() << "\t" << time_AveUsrNotif_Correct_Lgin  << "(micro)"<< "\t" << time_AveUsrNotif_incorrect_Lgin <<"\t" << time_AveTotalProcessing_OrignPWD<< "\t" << time_AveTotalProcessing_IncrctTypo << "\t" << time_Login_WaitListIncludeValidTypo.count() << "\t" << SizeOfWaitingList <<"\n";

//            TyptopCondOPT << "TypTopCondEncOptimized" << "\t" << time_init.count() << "\t" << time_AveUsrNotif << "\t" << time_AveTotalProcessing_OrignPWD << "\t" << time_AveTotalProcessing_IncrctTypo << "\t" << time_Login_WaitListIncludeValidTypo.count() << "\t" << SizeOfWaitingList <<"\n";


            CHECK(tp.check(pws[1], FIRST_TIME, false));
            CHECK(tp.check(pws[2], FIRST_TIME, false));
            CHECK(tp.check(pws[3], FIRST_TIME, false));
            CHECK(tp.check(pws[5], FIRST_TIME, false));
//            CHECK_FALSE(tp.check(pws[5], FIRST_TIME, false));
        }

        SECTION("try inserting a typo with typo") {
            REQUIRE(tp.check(pws[1], FIRST_TIME, false));
            times(8, CHECK_FALSE(tp.check(pws[4], FIRST_TIME, false)));
            times(8, CHECK_FALSE(tp.check(pws[5], FIRST_TIME, false)));
            REQUIRE(tp.check(pws[1], FIRST_TIME, false));
            CHECK(tp.check(pws[4], FIRST_TIME, false));
            CHECK_FALSE(tp.check(pws[5], FIRST_TIME, false));
        }
    }



    SECTION("Long term use of typtop.") {

    }

    SECTION("Test log entries and upload") {
        tp.allow_upload(false);
        tp.check(pws[0], PAM_RETURN::SECOND_TIME, false);

        SECTION("send_w/o_autoupload") {
            tp.send_log(1); // truncate  // test=1
            CHECK(db.logs().l_size() == 0);  // log had the typos

            CHECK(tp.check(pws[1], PAM_RETURN::FIRST_TIME, false));
            CHECK(db.logs().l_size() == 1);
            for (int i = 0; i < 6; ++i) {
                tp.check(pws[2], PAM_RETURN::FIRST_TIME, false);
                CHECK(db.logs().l_size() == i + 2);
            }
            tp.send_log(1);
            CHECK(db.logs().l_size() == 0);  // log had the typos
        }
    }
}

TEST_CASE("Upload"){
    SECTION("Simple upload") {
        REQUIRE(send_log_to_server("test-uid", "test-log-loerm-ipsum", 1));
    }
}

TEST_CASE("Timing") {

    remove(_db_fname.c_str());
    TypTopTest tp;


    tp.check(pws[0], SECOND_TIME, false); // set the password //Initializes the system using this pwd.
//    tp.check(pws[0], FIRST_TIME, false);
    SECTION("Wrong password - 100 times") {
        times(10, CHECK_FALSE(tp.check(pws[4], FIRST_TIME, false)))
    }

    SECTION("Correct password - 100 times") {
        times(10, CHECK(tp.check(pws[0], FIRST_TIME, false)))
    }

    SECTION("Intiation") {
    }
}

TEST_CASE("Typtop extra utilities") {
    string hpws[] = {
            "Password1#",
            "password1#",
            "Password1",
            "password1"
    };
    remove(_db_fname.c_str());
    TypTopTest tp;
    tp.check(hpws[0], SECOND_TIME, false); // set the password
    tp.set_typo_policy(1, 0, 30);
    tp.check(hpws[0], SECOND_TIME, false); // reset the password
    REQUIRE(tp.check(hpws[0], FIRST_TIME, false));
//    vector<string> typos(10);
//    get_typos(hpws[0], typos);
//    for(string it: typos){
//        cerr << it << endl;
//    }
    SECTION("set_typo_policy") {
        const TypoPolicy& tpoly = tp.get_typo_policy();
        CHECK(tpoly.edit_cutoff() == 1);
        CHECK(tpoly.abs_entcutoff() == 0);
        CHECK(tpoly.rel_entcutoff() == 30);
    }


    SECTION("Allow Typo login") {
        CHECK(tp.check(hpws[1], FIRST_TIME, false));
        tp.allow_typo_login(false);
        CHECK_FALSE(tp.get_db().ch().allowed_typo_login());
        CHECK(tp.check(hpws[0], FIRST_TIME, false));
        CHECK_FALSE(tp.check(hpws[1], FIRST_TIME, false));
        tp.allow_typo_login(true);
        CHECK(tp.check(hpws[0], FIRST_TIME, false));
        CHECK(tp.check(hpws[1], FIRST_TIME, false));
    }

    SECTION("Typo Policy.EditCutoff") {
        tp.set_typo_policy(2, -1, -1);
        tp.check(hpws[1], FIRST_TIME, false);
        for(int i=1; i<=3 && !tp.check(hpws[3], FIRST_TIME, false); i++) {
            times(5*i, tp.check(hpws[3], FIRST_TIME, false));
            tp.check(hpws[1], FIRST_TIME, false);
        }
        CHECK(tp.check(hpws[3], FIRST_TIME, false));
        tp.set_typo_policy(1, -1, -1);
    }

    SECTION("Typo Policy.AbsEntCutoff") {
        CHECK(tp.check(hpws[1], FIRST_TIME, false));
        tp.set_typo_policy(-1, 30, -1);
        CHECK_FALSE(tp.check(hpws[1], FIRST_TIME, false));
    }

    SECTION("Typo Policy.RelEntCutoff") {

    }
}