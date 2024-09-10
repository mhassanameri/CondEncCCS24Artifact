//
// Created by Rahul Chatterjee on 3/28/17.
//

#include <assert.h>
#include <random>
#include <dirent.h>
#include <libgen.h>
#include "condtyptop.h"

using CryptoPP::FileSource;

// Password length for random entries
//previous value 16.
#define DEFAULT_PW_LENGTH 32

#undef GOOGLE_LOG
pthread_mutex_t db_lock = PTHREAD_MUTEX_INITIALIZER;
const mode_t typtop_file_mask = 0177;   // because 0666 & 0600 = 0600

// inline void Dummy::DumFunv( const string& pw, time_t ts)
//{
//    paillier_pubkey_t* ppk;
//    string Pull_RlPwd_ctx_ForEditDisOne;
//    size_t len;
//    EditDistOne::CondEnc(ppk,Pull_RlPwd_ctx_ForEditDisOne, Pull_RlPwd_ctx_ForEditDisOne,Pull_RlPwd_ctx_ForEditDisOne, Pull_RlPwd_ctx_ForEditDisOne, len);
//
//}



TypTop::TypTop(const string &_db_fname) : db_fname(_db_fname) {
#ifdef DEBUG
    setup_logger(plog::debug);
#else
    setup_logger(plog::info);
#endif
    LOG_INFO << " -- TypTop Begin -- ";
    google::protobuf::SetLogHandler(NULL);  // stop annoying protobuf error messages
    mode_t o_mask = umask(typtop_file_mask);  // 0777 & ~typtop_file_mask = 0600
    fstream idbf(db_fname, ios::in | ios::binary);
    if(!idbf.good()) {
        LOG_WARNING << "TypTop db is not initialized: " << db.h().sys_state();
        db.mutable_ch()->set_install_id(get_install_id());
        return;
    }
    try {
        if(db.ParseFromIstream(&idbf)) {
            LOG_INFO << "TypTop initialized: " << bool(db.h().sys_state() == SystemStatus::ALL_GOOD);
//            pkobj.set_pk(db.ch().public_key());
            /*Added nby hassan*/
            pkobj.set_pk_Pail(db.ch().public_key());
//            pkobj.Paill_pk_init(pkobj.n_lambda);
        } else {
            db.mutable_ch()->set_install_id(get_install_id());
            LOG_ERROR << "Could not parse the DB file.";
            // Delete the file, that it cannot parse. 
            LOG_DEBUG << "Deleted offending file: " << remove(db_fname.c_str());
        }
    } catch (google::protobuf::FatalException ex) {
        db.mutable_h()->set_sys_state(SystemStatus::UNINITIALIZED);
        db.mutable_ch()->set_install_id(get_install_id());
        LOG_ERROR << "DB file is corrupted, will (re)initialize next time.";
    }
    umask(o_mask);
}




void TypTop::save() const {
    if (!is_initialized()) return; // no need to do anything
    // check if the directory exists
#ifdef WIN32
    throw("No idea what to do.")
#else
    const char* db_dirname = dirname(strdup(db_fname.c_str()));
    DIR* dir;
    if(!(dir = opendir(db_dirname))) {
        LOGD << "Trying to create directory " << db_dirname << ".\n";
        if(mkdir(db_dirname, 0775) != 0) // (S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH)))
            LOG_ERROR << strerror(errno) << " " << getuid() << endl;
    } else {
        LOG_DEBUG << "Directory '" << db_dirname << "' exists.";
    }
    closedir(dir);
    /* Each time this function gets called, the counter is incremented by the calling thread.*/
    string db_bak = db_fname + ".bak";
    auto o_mask = umask(typtop_file_mask);
    int fd = open("/tmp/typtop.lock", O_WRONLY);
    struct flock* lock = (struct flock*)malloc(sizeof(struct flock));
    lock_file(fd, lock);
#endif
    std::fstream of(db_bak, ios::out | ios::binary);

    if(of.good()) {
        LOG_DEBUG << "db_bak: ownership: " << endl;
        db.SerializeToOstream(&of);
    }
    else {
        LOG_ERROR << "Could not open backup file for writing " << db_bak;
        // cerr << "Could not open backup file for writing\n" << strerror(errno) << endl;
    }
    of.close();
    if(rename(db_bak.c_str(), db_fname.c_str()) != 0) {
        LOG_ERROR << "Could not replace original db file " << db_fname;
    }
    umask(o_mask);
#ifdef WIN32
    throw("No idea what to do!")
#else
    unlock_file(fd, lock);
    close(fd);
#endif
    LOG_INFO << "db is saved";
    /* -- Does not work. Making the file only readable by the owner (root).
    //  Change DB permission
    if (chown(db_fname.c_str(), 0, 0) != 0) {
        LOG_ERROR << "Could not set the ownership of the db_file. ErrorNo.: "  << errno;
    } else {
        LOG_DEBUG << "db ownership set to root:root";
    }*/
}

TypTop::~TypTop() {
    if(db.IsInitialized())
        save();
    LOG_INFO << " -- TypTop END -- " << endl;
}




void TypTop::add_to_waitlist(const string &typo, time_t ts) {
//    cout << "adding to the waiting list";
//    if (ts > 0) cerr << "adding a typo to the waiting list\n";

    LOG_DEBUG_IF(db.w_size() < W_size) << "Increasing Waitlist size from "
                                       << db.w_size() << " to " << W_size;
    for (int i = db.w_size(); i < W_size; i++)
        db.add_w();
    string ctx;
//    vector<paillier_ciphertext_t*> vctx;
    WaitlistEntry wlent;

    wlent.set_pw(typo);
    wlent.set_ts((int64_t)ts);

    string TypoInput;
    if (ts>0)
        TypoInput = typo;
    else
    {
        TypoInput = "Garbage";
    }

    /*
     * The following code reterive the original ctxt of the using
     * Enc algorithm of OR predicate for the conditional encryption.
     * The output will be used as the input of the CEnc of the conditional
     * encryption of the mentioned predicate.
     * */

    /*
     * According to the API of CondEnc, wlent.SerializeAsString(), will be encrypted, iff
     * OR_Predi(typo, pwd)=1, in which, pwd is the original user pwd in time of initialization.
     * */

/*
 * For handling edit distance we can also pull real_PwdCtxt_ForEdit_Dist and then use it and the conditionEnc for
 * predicate EditDistance One for adding thoese typoed to the waiting list.
 * */

//*-*-*-*-*-*-*--**-*-*-*-*-*-*-

/*
 * when ts = -1, we are adding garbage, so instead of secret sharing, just concatinate
 * elements from the ctxt space.
 * */
//    pkobj.SecretShare_MHammDis(Pull_RlPwd_ctx, wlent.SerializeAsString(), ctx);

    size_t len = pkobj.len_limit();

    size_t threshold = len-2;
    size_t PailCtxtSize =  PAILLIER_BITS_TO_BYTES(pkobj._ppk->bits)*2;
    size_t AE_CtxtSize = 2 * KEYSIZE_BYTES + len;
    size_t ORPrdrigCtxSize = OrPredicate::Trad_Ctxt_Size_Calculator(len, PailCtxtSize);
    size_t CondEncOR_CtxSize = OrPredicate::CondEnc_Ctxt_Size_Calculator(len,PailCtxtSize, AE_CtxtSize);
    // char* byte_OrigCtx = (char*) malloc (ORPrdrigCtxSize) ;
    // char* byte_condCtx = (char*) malloc(CondEncOR_CtxSize) ;
    char byte_OrigCtx [ORPrdrigCtxSize];
    char byte_condCtx [CondEncOR_CtxSize];
//    std::string Pull_OR_CTX_Orig = db.rlpwdctxorenc();
//    std::string typo_OR_CEncIn_Payload = wlent.SerializeAsString();  //Plays the role of our payload in CEnc. In th ecase OR_Predi(typo, payload) =1, we can extract in after CDec(.).
    // cout <<"adding to cache2\n";
    string typo_OR_CEncIn_Payload;

    CryptoPP::StringSink ss_typo_OR_CEncIn_Payload(typo_OR_CEncIn_Payload);
    ss_typo_OR_CEncIn_Payload.Put((const CryptoPP::byte*)wlent.SerializeAsString().data(),
                                  wlent.SerializeAsString().size(), false);

    // cout << typo <<endl;
    // std::string typo_OR_CEncIn;
    // CryptoPP::StringSink ss_typo_OR_CEncIn(typo_OR_CEncIn);
    // ss_typo_OR_CEncIn.Put((const CryptoPP::byte*)typo.data(),  typo.size(), false);
    // cout <<"adding to cache3\n";


//    memcpy(&typo_OR_CEncIn[0], &typo[0], typo.size());

//    memcpy(CryptoPP::byte_OrigCtx, &Pull_OR_CTX_Orig[0], ORPrdrigCtxSize);
    memcpy(byte_OrigCtx, &db.rlpwdctxorenc()[0], ORPrdrigCtxSize);



//    OrPredicate::CondEnc(pkobj._ppk, byte_OrigCtx, typo_OR_CEncIn, typo_OR_CEncIn_Payload , pkobj.len_limit(),  pkobj.len_limit()-2, byte_condCtx);//TODO: make sure that if this way of generating the ctx is ok or not?
    // OrPredicate::CondEnc(pkobj._ppk, byte_OrigCtx, typo_OR_CEncIn,
    //                      typo_OR_CEncIn_Payload , pkobj.len_limit(),
    //                      pkobj.len_limit()-2, byte_condCtx);

    OrPredicate::CondEnc(pkobj._ppk, byte_OrigCtx, TypoInput,
                         typo_OR_CEncIn_Payload , pkobj.len_limit(),
                         pkobj.len_limit()-2, byte_condCtx);

    int32_t curr_index = db.h().indexj();
    db.set_w(curr_index, byte_condCtx, CondEncOR_CtxSize);
    curr_index = (curr_index + 1) % W_size;
    db.mutable_h()->set_indexj(curr_index);
    // free(byte_OrigCtx);
    // free(byte_condCtx);
}

void TypTop::fill_waitlist_w_garbage() {
    for (int i = 0; i < W_size; i++) {
        string b(DEFAULT_PW_LENGTH, 0);
        PRNG.GenerateBlock((CryptoPP::byte*) b.data(), b.size());
        add_to_waitlist(b, -1); // ts = -1 for garbage strings

    }
}

void TypTop::reinitialize(const string &pw) {
    LOG_INFO << "Reinitializing the db.";
    initialize(pw);
}

void TypTop::initialize(const string &real_pw) {
    ConfigHeader *ch = db.mutable_ch();
    this->real_pw = real_pw;
    // - Set config header
    ch->set_install_id(get_install_id());
    ch->set_allow_upload(is_participating());


    pkobj.initialize();

    int _len = pkobj.len_limit();
    size_t PailCtxtSize =  PAILLIER_BITS_TO_BYTES(pkobj._ppk->bits)*2;
    size_t EDOneOrigCtxSize   = 2 * sizeof(size_t) + (_len + 1)  *  PailCtxtSize;
    size_t HDTwoOrigCtxSize   = 2 * sizeof(size_t) + _len *  PailCtxtSize;
    size_t CAPSLocOrigCtxSize = 2 * sizeof(size_t) +  PailCtxtSize;

    size_t ORPrdrigCtxSize = CAPSLocOrigCtxSize + EDOneOrigCtxSize + HDTwoOrigCtxSize;

//    char OrPred_Char_ORigCTx[ORPrdrigCtxSize];
    char* OrPred_Char_ORigCTx = (char*) malloc(ORPrdrigCtxSize);
    // char OrPred_Char_ORigCTx [ORPrdrigCtxSize];
//    string RlPwd_ctx_pull = real_pw_ctx.rlpwdctx(); // for debug!!

    /*
     * Here we are defining real_PwdCtxt_ForEdit_Dist as the encryption of the reali password which will be used for
     * the aim of handling edit distance one which incluede the insertion and deletion cases.
     * This ciphertext includes the Enc_PK(ToInt(pwd)), ..., Enc_PK (ToInt(pwd_{-1})), Enc_PK (ToInt(pwd_{-i})), ...,
     * Enc_PK (ToInt(pwd_{-n})).
     * */

    //*=*=*======**=*=*=*=**=*=*=


    /*
     * Added by Hassan*/
//    string RlPwd_ctx;
    string RlPwd_ctx_ORPRediacte;

    /*The following command will encrypt the original
     * pwd for the aim of cheking the authorization.
     * */
//    pkobj.pw_pk_encrypt(real_pw, RlPwd_ctx, pkobj._ppk); /*This should be added to the original APP*/
//    real_pw_ctx.set_rlpwdctx(RlPwd_ctx);

//    real_PwdCtxt_ForEdit_Dist.set_rlpwdctxedone(RlPwd_ctx_EditDistOne);
//    pkobj.pw_pk_encrypt(real_pw, RlPwd_ctx,pkobj._ppk );//
    int OrigEncRst = 0;

    string origianl_pwd_plaintext = real_pw;
    OrigEncRst = OrPredicate::Enc(pkobj._ppk, origianl_pwd_plaintext, OrPred_Char_ORigCTx, _len); //ctxt of the original password will be used as the input of the CondEnc when we want to add the typo to the waiting list.
    db.set_rlpwdctxorenc(OrPred_Char_ORigCTx, ORPrdrigCtxSize); //Probably will deeply copy the generated ciphertext to our defined data base.
    free(OrPred_Char_ORigCTx);

    /*------*/

    LOG_INFO << "Initializing the db ";
//    ch->set_public_key(pkobj.serialize_pk()); //The original one
    ch->set_public_key(pkobj.pk_Pail_Serialize(pkobj._ppk));

    if (ch->global_salt().empty()) { // only change the salt if it is empty
        SecByteBlock global_salt((ulong)AES::BLOCKSIZE);
        PRNG.GenerateBlock(global_salt, global_salt.size());  // random element
        ch->set_global_salt((const char *) global_salt.data(), global_salt.size());
    } else {
        LOG_INFO << "Keeping the salt unchanged";
    }


    string sk_str = pkobj.serialize_sk(); //(Hassan: from the original code)
    /*Added by Hassan */
//    paillier_prvkey_t* psk =  pkobj.sk_Pail_Extract();
//    cerr << "Loading the secret key.\n";
//    char* sk_str_Pail_hex = paillier_prvkey_to_hex(psk);
    string sk_str_Pail =  paillier_prvkey_to_hex(pkobj._psk);
//    sk_str[0] =  paillier_prvkey_to_hex(psk);
    /* ###### */
    // cerr << __FUNCTION__ << " :: " << b64encode(sk_str) << endl;

    // --- Set the encryption header
    ench.set_pw(real_pw);
    ench.set_pw_ent(entropy(real_pw));
    std::vector<string> T_cache(T_size - 1);
    get_typos(real_pw, T_cache);
    T_cache.insert(T_cache.begin(), real_pw);  // the real password is always at the 0-th location
    assert(T_cache.size() == T_size);
    string _t, sk_ctx;



    for (int i = 0; i < T_size; i++) {
        if ((T_cache[i].empty() || !meets_typo_policy(real_pw, T_cache[i], db.ch().tp())) && i!= 0) { // generate random
            T_cache[i].resize(DEFAULT_PW_LENGTH, 0);
            if(i==0)
            {
                cout << "T_chace random with the original pwd[0]";
            }
            PRNG.GenerateBlock((CryptoPP::byte*) T_cache[i].data(), T_cache[i].size());
            if (!T_cache[i].empty()) LOGD << "Skipping: " << T_cache[i];
        } else {
            insert_into_log(T_cache[i], true, -1); // sets L
            LOGD << "Inserting: " << T_cache[i];
        }

        auto AuthEncRst = CryptoSymWrapperFunctions::Wrapper_AuthEncrypt_Hardened(T_cache[i], sk_str_Pail, sk_ctx); //Encrypting the generated secret key under the symmerteric key extracted from pw
        // LOG_DEBUG << "Inserting " << T_cache[i] << " at " << i;
        _insert_into_typo_cache(i, sk_ctx, (i == 0 ? INT_MAX : T_size - i));
#ifdef DEBUG
        // cerr << "Inserting -->" << T_cache[i] << endl;
        if(i>0) {

            assert(db.t(i) == sk_ctx);
            assert(CryptoSymWrapperFunctions::Wrapper_AuthDecrypt_Hardened(T_cache[i], db.t(i), _t));
            assert(ench.freq(i) == T_size-i);
        }
#endif

    }

    permute_typo_cache(sk_str);

    Header *h = db.mutable_h();
    h->set_indexj(PRNG.GenerateWord32(0, W_size - 1)); // initialize the indexj to a random value

    assert(ench.freq_size() == T_size);

    string ench_ctx;
//    vector<paillier_ciphertext_t*> vctx;

//    pkobj.pk_encrypt(ench.SerializeAsString(), *(h->mutable_enc_header()));
//    pkobj.Paill_pk_encrypt( ench.SerializeAsString(), *(h->mutable_enc_header())); /* Added by Hassan */


    size_t ctxt_size =  PAILLIER_BITS_TO_BYTES(pkobj._ppk->bits)*2;
    char* ctx_mutable_from_h = (char*) malloc (ctxt_size);
    std::string msg_ench;
//    msg_ench = ench.SerializeAsString();
    if(!ench.SerializeToString(&msg_ench))
    {
        cerr << "serialization error";
    }

    PaillerWrapperFunctions::Pail_Classic_Enc(msg_ench, pkobj._ppk, ctx_mutable_from_h);
    h->set_enc_header(ctx_mutable_from_h,ctxt_size);//This line stores the poitner to the memory which stores the resulted ctxt and serialize via the protobuf for future usage.
    free(ctx_mutable_from_h);

// For debugging
#ifdef DEBUG
    string ench_str;

    pkobj.set_sk_Pail(sk_str_Pail, false);
    pkobj._can_decrypt_Pail = true;
//    PaillerWrapperFunctions::Pail_Classic_Dec(pkobj._ppk, ctx_mutable_from_h, pkobj._psk, ench_str, 109);
    char* h_string_ptr = (char*) malloc(ctxt_size);
    std::string h_enc_str = h->enc_header(); //For the debuging purposes, here we just extract the string of the ctxt from the pointer to the memory and then using memcopy transfer the vector to the byte array of char* which is suitable as the imput of the ciphertext.
    memcpy(h_string_ptr, &h_enc_str[0], ctxt_size);
    PaillerWrapperFunctions::Pail_Classic_Dec(pkobj._ppk, h_string_ptr, pkobj._psk, ench_str, msg_ench.size());
    string enchSerial = ench.SerializeAsString();
    ench.SerializePartialToString(&enchSerial);
    free(h_string_ptr);
    assert (ench_str == ench.SerializeAsString()); // For debugging
#endif
    fill_waitlist_w_garbage();   // sets W

    db.mutable_h()->set_sys_state(SystemStatus::ALL_GOOD);
    assert(is_initialized());


    LOG_INFO << "DB is initialized.";
#ifdef DEBUG
    if (db.t_size() != ench.freq_size() ||
        db.t_size() != ench.last_used_size() ||
        ench.last_used_size() != T_size) {
        cerr << __FILE__ << __LINE__ << " : "
             << " ---> db.t=" << db.t_size() << ", freq=" << ench.freq_size()
             << " last_used=" << ench.last_used_size() << " T-size=" << T_size << endl;
        throw ("I am dying");
    }
    LOGD << "TypTop data-structure is initialized!" << endl;
#endif
}


void TypTop::insert_into_log(const string &pw, bool in_cache, time_t ts) {
    assert(!real_pw.empty());
    float _this_pw_ent = entropy(pw);
    size_t len = pw.size();
    // Why 10, that's the 3-quartile of RockYou dataset with passwords>6.
    int pass_complexity = (len>10 || _this_pw_ent>32)?2:
                          (len>8 || _this_pw_ent>16)?1:
                          0;
    int edist = edit_distance(pw, real_pw);

    /** For small stats **/
    if (ts>0 && edist>0 && edist<5) {
        db.mutable_logs()->set_typos(db.logs().typos() + 1);
        if (in_cache)
            db.mutable_logs()->set_typos_saved(db.logs().typos_saved() + 1);
    }

    if (!db.ch().allow_upload() && db.logs().l_size() > 30) {
        LOG_INFO << "Not participating in the study, and Log size is too large, so ignoring further logs.";
        return;
    }

    SecByteBlock g_salt((const CryptoPP::byte*) db.ch().global_salt().data(), db.ch().global_salt().size());
    Log *l = db.mutable_logs()->add_l();
    l->set_in_cache(in_cache);
    l->set_istop5fixable(top5fixable(real_pw, pw));
    l->set_edit_dist(min(edist, 5));
    l->set_rel_entropy(_this_pw_ent - ench.pw_ent());
    l->set_pass_complexity(pass_complexity);
    l->set_tid(CryptoSymWrapperFunctions::compute_id(g_salt, pw));
    l->set_ts((int64_t)ts);
    l->set_localtime(localtime());
}

int TypTop::is_typo_present(const string &pw, string &sk_str) const {
    int i = 0;
    for (i = 0; i < T_size; i++) {
        sk_str.clear();
        if (CryptoSymWrapperFunctions::Wrapper_AuthDecrypt_Hardened(pw, db.t(i), sk_str)) { //looks like that all the ctxs in the dp.t are the encryption of the set of pdws that have small edit distance from the original pwd. Encryption scheme is simply the the classic encryption algorithm.
            break;
        }
    }
    return i;
}

bool TypTop::is_correct(const string &pw) const {
    string sk_str;
    bool ret = CryptoSymWrapperFunctions::Wrapper_AuthDecrypt_Hardened(pw, db.t(0), sk_str);
    sk_str.clear();
    return ret;
}

/**
 * Checks the password in the TypTop cache.
 * 01. if pret == FIRST_TIME, then only reply if IsInitialized
 * 0b. if pret == SECOND_TIME, then only Initialize and return true.
 * 1. Check the pw against db.t()
 * 2. If match found, process waitlist.
 * 2a.
 * 3. If no match found add to waitlist
 * 3a.
 * @param pw: typed password (could be wrong)
 * @param were_right: The return from previous authentication mechanism, such as pam_unix.
 * @return Whether or not the entered password is allowable.
 */
bool TypTop::check(const string &pw, PAM_RETURN pret, bool isfork) {
    LOG_INFO << "Checking with typtop for FIRST/SECOND: " << pret;

    if(!is_initialized()) {
        if (pret == SECOND_TIME) {
            this -> initialize(pw);
            return true;
        } else {
            LOG_DEBUG << "DB is not initialized.";
            return false;
        }
    }
    if (pret == SECOND_TIME) {
        // Should have handled this pw submission in first time
        // Probably cause: password changed, so have to reinitialize the db.
        // TODO: How to detect old typo?
        this->reinitialize(pw);
        return true;
    }

    ench.Clear();
    string sk_str, enc_header_str;
    /* Standard book-keeping */
    db.mutable_h()->set_login_count(db.h().login_count() + 1);

    // check the password
    int i = is_typo_present(pw, sk_str); //Here, if the pw is correct we can extract the secret key derived from pw.

//    cerr << "the index of checked pwds: " << i << "\n";


    if (i == T_size) { // not found in the typo cache, so add to waitlist
        add_to_waitlist(pw, now());
//        cerr << "added to the waiting list \n";
        LOG_INFO << "Failed to find match in typocache: " << i;
        return false;
    } else { // found in typo-cache
        // cerr << __FUNCTION__ << " :: " << b64encode(sk_str) << endl;

        //
        pkobj.set_sk_Pail(sk_str); //In the case of correct login we can extract the the secret key of our PK encryption scheme.

        //
        try {
//            pkobj.pk_decrypt(db.h().enc_header(), enc_header_str);
//            pkobj.Paill_pk_decrypt(db.h().enc_header(), enc_header_str);
            int RecRslt = 0;
            std::string typo_pw;

//            pkobj.HE_Pk_Dec(db.h().enc_header(), enc_header_str, indx, typo_c, is_typo_found);
//            RecRslt = pkobj.RecoverShares(db.h().enc_header(), pkobj._ppk, pkobj._psk, 25, enc_header_str); // enc_header_str is the recovered typo.
//            pkobj.Paill_pk_decrypt(db.h().enc_header(), enc_header_str, 0);/
            string ctx_db_h_enc_header = db.h().enc_header();
            RecRslt = PaillerWrapperFunctions::Pail_Classic_Dec(pkobj._ppk, &ctx_db_h_enc_header[0], pkobj._psk, enc_header_str, 109);


            ench.ParseFromString(enc_header_str);
            this->real_pw = ench.pw();
//            cerr << "the real password is extracted\n";
            if (i > 0) {
                ench.set_freq(i, ench.freq(i) + 1);
                ench.set_last_used(i, now());
            }
            if (i == 0)
            {
                process_waitlist(sk_str); //We just need to process the waiting list when we loging with the original pwd,  So we run the rocess_waitlist only i == 0. TODO: Double check with Jeremiah to make sure if it is the case.
            }
//            cerr << "the waiting list is successfully preocessed\n";
            permute_typo_cache(sk_str);

            insert_into_log(pw, true, now());
            string ench_plaintxt, ench_ctx, _t_ench_str;
            string mssage = ench.SerializePartialAsString();
            ench_plaintxt = ench.SerializeAsString();

            char* ench_ctx_byte = (char*) malloc (pkobj.Return_pk_size(pkobj._ppk));

//            pkobj.pk_encrypt(ench.SerializeAsString(), ench_ctx);
//            pkobj.(ench.SerializeAsString(), ench_ctx); /* Added by Hassan */

            PaillerWrapperFunctions::Pail_Classic_Enc(ench_plaintxt, pkobj._ppk, ench_ctx_byte);

//            pkobj.pk_decrypt(ench_ctx, _t_ench_str);
//            pkobj.Paill_pk_decrypt(ench_ctx, _t_ench_str); /* Added by Hassan */
//            pkobj.HE_Pk_Dec(ench_ctx, _t_ench_str);
//            pkobj.Paill_pk_decrypt(ench_ctx, _t_ench_str, 0);//

            /*For Debug
             * added by Hassan
             *
             * */
            string enchString = ench.SerializeAsString();
            /*---*/
//            assert(_t_ench_str == ench.SerializeAsString());
//            db.mutable_h()->set_enc_header(ench_ctx);
            db.mutable_h()->set_enc_header(ench_ctx_byte,pkobj.Return_pk_size(pkobj._ppk) );
            free(ench_ctx_byte);

            ench.Clear();
            if(i == 0)
                LOG_INFO << "Accepting the real password!";
            else {
                if(db.ch().allowed_typo_login() && meets_typo_policy(this->real_pw, pw, db.ch().tp()))
                    LOG_INFO << "Accepting a typo!";
                else {
                    LOG_INFO << "Typo is rejected because of the allow_typo_log is "
                             << db.ch().allowed_typo_login();
                    LOG_INFO << " or does not meet the typo-policy"
                             << db.ch().tp().SerializePartialAsString();
                    return false;
                }
            }
            if(db.ch().allow_upload()){
#ifdef DEBUG
                send_log(1);
#else
                if (isfork) {
                    if (fork() == 0)
                        send_log(0);
                } else {
                    send_log(1);
                }
#endif
            }
            return true;
        } catch (exception &ex) {
            LOG_FATAL << "Exception: " << ex.what() << endl;
            LOG_ERROR << CryptoSymWrapperFunctions::Wrapper_b64encode(enc_header_str) << endl;
            PkCrypto pkobj1; pkobj1.set_sk(sk_str);
//            pkobj1.set_sk_Pail(sk_str);
//            pkobj1.pk_decrypt(db.h().enc_header(), enc_header_str);
//            pkobj1.Paill_pk_decrypt(db.h().enc_header(), enc_header_str, 0);//TODO: need to double check if this part is important.
            return false;
        }
    }
}

void TypTop::_insert_into_typo_cache(const int index, const string &sk_ctx,
                                     const int freq) {
    LOG_DEBUG_IF(ench.freq_size()<T_size)<< "Increasing the Typocache size from "
                                         << db.t_size() << " to " << T_size;
    for(int i=db.t_size(); i<T_size; i++) // db.T can deviate, hence separately dealing with it.
        db.add_t();
    for (int i = ench.freq_size(); i < T_size; i++) { // assume two arrays (freq, last_used) are in sync
        ench.add_freq(-1);
        ench.add_last_used(-1);
    }
    assert(db.t_size() == T_size);

    db.set_t(index, sk_ctx);
    int64_t now_t = now();
    ench.set_freq(index, freq);
    ench.set_last_used(index, now_t);

}

/**
 * For security reason we should keep the typo cache permuted after
 * every time the cache is altered.
 */
void TypTop::permute_typo_cache(const string &sk_str) {
    std::random_device rd;
    uint32_t permutation_seed = rd();
    std::mt19937 g(permutation_seed);
    shuffle(db.mutable_t()->begin() + 1, db.mutable_t()->end(), g);
    g.seed(permutation_seed); // reseed the permutaion
    shuffle(ench.mutable_freq()->begin() + 1, ench.mutable_freq()->end(), g);
    g.seed(permutation_seed);
    shuffle(ench.mutable_last_used()->begin() + 1, ench.mutable_last_used()->end(), g);

    if (db.ch().expire_typos())
        expire_typos(sk_str);
}

void TypTop::expire_typos(const string &sk_str) {
    // remove very old typos from the cache
    int64_t t_now = now();
    string sk_ctx;
    for (int i = 1; i < T_size; i++) { // don't remove real password
        if ((t_now - ench.last_used(i)) > db.ch().typo_expiry_time()) {
            string fake_pw(DEFAULT_PW_LENGTH, 0);
            PRNG.GenerateBlock((CryptoPP::byte *) fake_pw.data(), fake_pw.size());
            CryptoSymWrapperFunctions::Wrapper_AuthEncrypt_Hardened(fake_pw, sk_str, sk_ctx);
            LOG_INFO << "Expiring typo at " << i
                      << " time_now:" << t_now
                      << " Last used:" << ench.last_used(i);
            _insert_into_typo_cache(i, sk_ctx, -1);
        }
    }
}

/**
 * 1. Decrypt the wait-list, add to log, and consolidate
 * 2. for each consolidated and validated entries
 *     try to insert in the typo cache
 */
void TypTop::process_waitlist(const string &sk_str) {
    LOG_DEBUG << "Processing waitlist" ;
    assert (!this->real_pw.empty());
    map<string, int> wl_typo;
    WaitlistEntry wlent;

    int _len = pkobj.len_limit();
    size_t PailCtxtSize =  PAILLIER_BITS_TO_BYTES(pkobj._ppk->bits)*2;
    size_t AE_CtxtSize = 2 * KEYSIZE_BYTES + _len; // Computing the sized of AE for padded payload (padded size=_len)
    size_t CondEncEDOneCtxSize = 3 * sizeof(size_t) + (sizeof(char) * AE_CtxtSize) + ((2 * _len) + 1) *  PailCtxtSize;
    size_t CondEncHDTwoCtxSize = 3 * sizeof(size_t) + (sizeof(char) * AE_CtxtSize) + (_len *  PailCtxtSize);
    size_t CondEncCPSLKCtxSize = 3 * sizeof(size_t) + (sizeof(char) * AE_CtxtSize) +  PailCtxtSize;

    int threshold = 30;
    size_t CondEncOR_CtxSize = CondEncCPSLKCtxSize + CondEncEDOneCtxSize + CondEncHDTwoCtxSize;
//    char* OrPred_ctx_typo_Bytes =  (char*) malloc(CondEncOR_CtxSize);

//    cout <<  "starting to decrypt all of the ctxts added to the waiting  list \n";
    for (int i = 0; i < W_size; i++) {
        string wlent_str;
//        string _wlent_str;


//        pkobj.pw_pk_decrypt(db.w(i), wlent_str); //from the orig. code commented by hassan.

        /* Added by hassab */
        string CondTypoCtx;
//        = db.w(i);
        CryptoPP::StringSink ss(CondTypoCtx);
        ss.Put((const CryptoPP::byte*)db.w(i).data(),  db.w(i).size(), false);


//        memcpy(OrPred_ctx_typo_Bytes, &CondTypoCtx[0], CondEncOR_CtxSize );

        std::string recovered_OR_Bytes;
        size_t l_m = real_pw.size();

        int RsltRcvr =0;
//        RsltRcvr = pkobj.RecoverShares(db.w(i), pkobj._ppk, pkobj._psk, 29, _wlent_str); // enc_header_str is the recovered typo. \TODO (IMPTN) make this function executable for debugging
//        RsltRcvr = pkobj.RecoverTypoEdiDisOne (db.w(i), pkobj._ppk, pkobj._psk, 0,_wlent_str); // this should be commented out
//        RsltRcvr = CondEncEditDistOneProt.CondDec(pkobj._ppk, db.w(i), pkobj._psk,1, _wlent_str, 32, 32);
        RsltRcvr = OrPredicate::CondDec(pkobj._ppk, &CondTypoCtx[0], pkobj._psk, threshold, wlent_str, _len);
//        cout << "...CodDec...\n";
//        RsltRcvr = OrPredicate::CondDec_Optimized_for_HD2(pkobj._ppk, &CondTypoCtx[0], pkobj._psk, threshold, wlent_str, _len, 28, l_m);//TODO: Note that here the decrypted value should be the payaload if the OR_Predi(pwd,typo) =1. So, in the case of 1 as the result of conditional decryption.
        if (RsltRcvr >= 0)  {
            cout << "A valid typo is detected\n";
            wlent.ParseFromString(wlent_str);
            if (wlent.ts() > 0) // no points logging the garbage of the Wait-list
                insert_into_log(wlent.pw(), false, wlent.ts());
//            if (meets_typo_policy(real_pw, wlent.pw(), db.ch().tp()))
            if (meets_typo_policy(real_pw,wlent.pw(), db.ch().tp())) {
                wl_typo[wlent.pw()] = wl_typo[wlent.pw()] + 1; // stl map initialized to 0 by default!!
//                wl_typo.insert(pair<string, int>(wlent_str, wl_typo[wlent_str] + 1));
            }
        }

    }

    vector<int> freq_vec(ench.freq().begin(), ench.freq().end());
    auto freq_vec_sorted_idx = sort_indexes(freq_vec);
    for (auto e: wl_typo) {
        // cerr<< e.first << " :: " << e.second << endl;
        string pw = e.first;
        int freq = e.second;
        string sk_ctx;
        LOG_DEBUG << "Got typo: " << pw;
        for (auto i: freq_vec_sorted_idx) {
            // try to insert at i-th location
            if (win(ench.freq((int) i), freq)) {
//                cout  << "A typo is inserted to the chache of valid typos \n";
                CryptoSymWrapperFunctions::Wrapper_AuthEncrypt_Hardened(pw, sk_str, sk_ctx);
                LOG_DEBUG << "Inserting " << pw << " at " << i;
                _insert_into_typo_cache((int) i, sk_ctx, max(freq, freq_vec[i] + 1));
#ifdef DEBUG
            string _t;
            assert(CryptoSymWrapperFunctions::Wrapper_AuthDecrypt_Hardened(pw, db.t(i), _t));
#endif
                break;
            }
        }
        // add_to_typo_cache(e.first, e.second, sk_str, ench);
    }
    fill_waitlist_w_garbage();
//    free(OrPred_ctx_typo_Bytes);
}

void TypTop::print_log() {
    if(is_initialized()) {
        for(auto it: db.logs().l())
            cerr << it.DebugString() << endl;
    } else {
        cerr << "Db is not initialized. " << db.IsInitialized();
    }
}

void TypTop::allow_upload(bool b) {
    if(db.IsInitialized()) {
        db.mutable_ch()->set_allow_upload(b);
    }
}

void TypTop::allow_typo_login(bool b) {
    if(db.IsInitialized()) {
        db.mutable_ch()->set_allowed_typo_login(b);
    }
}

const TypoPolicy& TypTop::get_typo_policy() {
    return db.ch().tp();
}

void TypTop::set_typo_policy(int edit_cutoff, int abs_entcutoff, int rel_entcutoff) {
    TypoPolicy *tp = db.mutable_ch()->mutable_tp();
    if (edit_cutoff >= 0) tp->set_edit_cutoff(edit_cutoff);
    if (abs_entcutoff >= 0) tp->set_abs_entcutoff(abs_entcutoff);
    if (rel_entcutoff >= 0) tp->set_rel_entcutoff(rel_entcutoff);
}

int TypTop::send_log(int test) {
    if (!is_initialized()) {
        LOG_INFO << "DB is not initialized. Will send logs later.";
    } else if (db.logs().l_size() < 5) {
        LOG_INFO << "Not many logs (" << db.logs().l_size() << "). Will send logs later.";
    } else {
        LOG_INFO << "Sending logs.";
        int ret = send_log_to_server(db.ch().install_id(),
                                     CryptoSymWrapperFunctions::Wrapper_b64encode(db.logs().SerializeAsString()),
                                     test);
        if (ret == 1) {
            LOG_INFO << "Sending logs succeeded.";
            db.mutable_logs()->clear_l();
            return 1;
        } else {
            LOG_INFO << "Sending logs failed.";
        }

    }
    return 0;
}

int typo_stats(const Logs& L, int* saved) {
    int t=0, s=0;
    *saved = L.typos_saved();
    return L.typos();
    for (Log l: L.l()) {
        if(l.edit_dist()>0 && l.edit_dist() < 4) {
            t++;
            if (l.in_cache())
                s++;
        }
    }
    *saved = s;
    return t;
}

void TypTop::status() const {
    int saved;
    int typo_count = typo_stats(db.logs(), &saved);
    cout << "\nTypTop: A smart password checker" << endl
         << "  Version: " << condtyptop_VERSION_MAJOR
         << "." << condtyptop_VERSION_MINOR
         << "." << condtyptop_VERSION_PATCH << endl
         << "  Install-id: " << db.ch().install_id() << endl
         << "  Login attempts: " << db.h().login_count() << endl
         << "  Typos made: " << typo_count << endl
         << "  Logins saved by TypTop: " << saved << endl
         << "  Volunteer for the study: " << db.ch().allow_upload() << endl
         << "  Allow login with typos: " << db.ch().allowed_typo_login() << endl;
    const condtyptop::TypoPolicy& tp = db.ch().tp();
    cout << "  TypoPolicy: \n"
         << "\t EditDistance Cutoff: " << tp.edit_cutoff() << endl
         << "\t Absolute Entropy Cutoff: " << tp.abs_entcutoff() << endl
         << "\t Relative Entropy Cutoff: " << tp.rel_entcutoff() << endl << endl;
#ifdef DEBUG
    cout << "(Debug is on)\n";
#endif
}

