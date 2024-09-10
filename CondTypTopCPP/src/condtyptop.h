/**
 *
 * Created by Rahul Chatterjee on 3/28/17.
 * Main TyptopDB related functions are given here.
 * First, do the initialization
 */


#ifndef CONDTYPTOP_C_TYPTOP_H
#define CONDTYPTOP_C_TYPTOP_H

#include "condtyptopconfig.h"
#include "plog/Log.h"
#include "db.pb.h"
#include "typo_util.hpp"
#include "pw_crypto.h"
#include "ConditionalEncryptionHamDistAtmostT.h"
#include "ConditionalEncryptionOR.h"
#include "ConditionalEncryptionCAPSLOCK.h"
#include "ConditionalEncryptionEditDistOne.h"



#ifndef CONDTYPTOP_LOG_FILE
#define CONDTYPTOP_LOG_FILE "/tmp/condtyptop.log"
#endif

using namespace condtyptop;

//#include "conditionalcrypto.h"
//#include "ConditionalEncryptionOR.h"

const int W_size = 10;
const int T_size = 5 + 1; // 1 for the real password

inline void setup_logger(plog::Severity severity) {
    const size_t MAX_LOG_FILE_SIZE = size_t(1e6); // 1 MB
    if(plog::get() != nullptr) {
        LOGD << "Logger already exists.";
        return;
    }
#ifdef DEBUG
    std::srand(254);
    plog::init(plog::debug, CONDTYPTOP_LOG_FILE"_test", MAX_LOG_FILE_SIZE, 1);
#else
    std::srand( (unsigned)std::time(0) );
    plog::init(severity, CONDTYPTOP_LOG_FILE, MAX_LOG_FILE_SIZE, 1);
#endif
}

enum PAM_RETURN {
    FIRST_TIME = 1, // the pam_unix return is not known
    SECOND_TIME = 2 // pam_unix is true for sure
};

//class Dummy {
//private:
//    static void DumFunv (const string& pw, time_t ts);
//};

class TypTop {
private:
    typoDB db;
    EncHeaderData ench;
    string db_fname;
    PwPkCrypto pkobj;
    string real_pw;   // secure object; carefully delete it once done
//    PwdCtx real_pw_ctx;
//    PwdCtxEDOne real_pw_ctx_edone;
//    PwdCtxORPredicate real_pw_ctx_or;
//    EditDistOne A;
//    HamDistTwo B;
//    OrPredicate ConEncOR;


//    CAPLOCKpredicate D;


//    ConditionalEncryption *A;
//    HamDistTwo *A =  new HamDistTwo();
//    HamDistTwo A;

//    ConditionalEncryptionEditDistOne CondEncEditDistOne;
//    ConditionalEncryptionHamDistTwo CondEncHammDistTwo;

    void _insert_into_typo_cache(const int index, const string &sk_ctx, const int freq);

public:
//    OrPredicate A;
//    const string &db_fname1;
    TypTop(const string& _db_fname);
    ~TypTop();
    bool check(const string &pw, PAM_RETURN pret, bool isfork = false);
    const string& this_install_id() const { return db.ch().install_id();}
    void save() const;
    int is_typo_present(const string& pw, string& sk_str) const;
    bool is_correct(const string& pw) const;
    inline bool is_initialized() const { return db.IsInitialized(); }
    void print_log();
    int send_log(int test);
    void allow_upload(bool b);
    void allow_typo_login(bool b);
    void status() const;
    void set_typo_policy(int edit_cutoff = -1, int abs_entcutoff = -1, int rel_entcutoff = -1);
    const TypoPolicy &get_typo_policy();
protected:

    void fill_waitlist_w_garbage();
    void initialize(const string& pw);
    void reinitialize(const string& pw);
    void insert_into_log(const string& pw, bool in_cache, time_t ts);
    void add_to_waitlist(const string& pw, time_t ts);
    void process_waitlist(const string& sk_str);
    void permute_typo_cache(const string& sk_str);
    void expire_typos(const string& sk_str);

    // For testing
    inline const typoDB& get_db(){ return db; }
    inline const PkCrypto& get_pkobj(){return pkobj;}
    inline const EncHeaderData& get_ench(){return ench;}

};

int send_log_to_server(const string uid, const string log, int test=1);

#endif //CONDTYPTOP_C_TYPTOP_H
