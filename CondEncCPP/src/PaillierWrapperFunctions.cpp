//
// Created by mameriek on 9/7/21.
//

#include "PaillierWrapperFunctions.h"
#include "filters.h"


vector<paillier_ciphertext_t*> PaillerWrapperFunctions::Pail_Parse_Ctx_size(paillier_pubkey_t* ppk,
                                                          char* ctx)
{

    size_t size;
    memcpy(&size, ctx , sizeof(size_t));
    size_t Ctxt_Elemnt_Size;
    memcpy(&Ctxt_Elemnt_Size, ctx + sizeof(size_t) , sizeof(size_t));

//    size_t* msg_size =(size_t*) malloc(sizeof(size_t));
//    free((size_t*)msg_size);
//    size_t* Elements_Size =(size_t*) malloc(sizeof(size_t));
//    free((size_t*)Elements_Size);
    size_t Accum_ptr = 0;
//    memcpy(&msg_size, ctx , sizeof(size_t));
//    const size_t size = (size_t) msg_size;

//    cout << "after decoding the size from the void vector: " << size << "\n";

    vector<paillier_ciphertext_t*> Vect_Ctx(size);
//    char byteCtxt1[PAILLIER_BITS_TO_BYTES(ppk->bits)*2];
//    char* byteCtxt1 = (char*)malloc(PAILLIER_BITS_TO_BYTES(ppk->bits)*2);
    void* byteCtxt1 = malloc(PAILLIER_BITS_TO_BYTES(ppk->bits)*2);
    for(int i = 0; i< size; i++ )
    {
//        memcpy(&Ctxt_Elemnt_Size, ctx + (i+1) * sizeof(size_t) , sizeof(size_t));
//        size_t Ctxt_Elemnt_Size = (size_t) Elements_Size;
//        memcpy(byteCtxt1,  (ctx +  sizeof(size_t) + i * PAILLIER_BITS_TO_BYTES(ppk->bits)*2 ), PAILLIER_BITS_TO_BYTES(ppk->bits)*2);
        memcpy(byteCtxt1,  ctx + (2 * sizeof(size_t)) + Accum_ptr , Ctxt_Elemnt_Size);
        Accum_ptr = Accum_ptr + Ctxt_Elemnt_Size;

        Vect_Ctx[i] = paillier_ciphertext_from_bytes(byteCtxt1, PAILLIER_BITS_TO_BYTES(ppk->bits)*2);

//        Vect_Ctx[i]  = ctxt1;
    }

    free(byteCtxt1);
//    free(Elements_Size);
//    free(msg_size);
    return Vect_Ctx;
}


int PaillerWrapperFunctions::Pail_Classic_Enc(string& msg, paillier_pubkey_t* ppk, char ctx_final[])
{
    size_t msg_size;
    size_t ctxt_size =  PAILLIER_BITS_TO_BYTES(ppk->bits)*2;

    auto& str = msg;
    string s(begin(str), end(str));
    msg_size = s.size();
    paillier_plaintext_t* m;

    paillier_ciphertext_t* ctxt_i;
//    ctxt_i = (paillier_ciphertext_t*) malloc(ctxt_size);
//    char* byteCtxt1;
    void* byteCtxt1;
    m = paillier_plaintext_from_bytes(&msg[0], msg_size );//&str[0] we conside the whole array in one shot. TODO: So I need to make sure in the byte by byte encryption algorithm the idea of &msg[i]  is corret. I guess it is correct as we just conside jsut one char afteer the targer cahr and we reed just one char .
    ctxt_i = paillier_enc(NULL, ppk, m, paillier_get_rand_devrandom);
    byteCtxt1 = paillier_ciphertext_to_bytes(ctxt_size, ctxt_i);
//        ctx_final = (char*) malloc(ctxt_size);
    memcpy(ctx_final, byteCtxt1,  ctxt_size);
    paillier_freeciphertext(ctxt_i);
    paillier_freeplaintext(m);
    free(byteCtxt1);

    return  1;
}


int PaillerWrapperFunctions::Pail_Classic_Dec( paillier_pubkey_t* ppk,
                             char pail_ctx[],
                             paillier_prvkey_t* psk,
                             string &plaintext,int _len)

{
    int ret = -1;
    vector<paillier_ciphertext_t*> V_ctx_typo(1);
//    void* ByteDec;
    string StrDec;
    int pars_rslt =0;
//    pars_rslt = PaillerWrapperFunctions::Pail_Parse_Ctx_Classic(ppk, pail_ctx, V_ctx_typo);
    V_ctx_typo[0] = paillier_ciphertext_from_bytes((void*)pail_ctx, PAILLIER_BITS_TO_BYTES(ppk->bits)*2);
    paillier_plaintext_t* dec;
    dec = paillier_dec(NULL, ppk, psk, V_ctx_typo[0]);


    char* buf;
    size_t len;

    buf = (char*) mpz_export(0, &len, 1, 1, 0, 0, dec->m);
    buf = (char*) realloc(buf, len + 1);
    buf[len] = 0;


//    plaintext = paillier_plaintext_to_str(dec);





    CryptoPP::StringSink ss(plaintext);
    ss.Put((const CryptoPP::byte*)paillier_plaintext_to_str(dec),  len, false);


//    ByteDec = paillier_plaintext_to_bytes(_len, dec);
//    vector<byte> ab(_len);
//    memcpy(&ab[0],ByteDec, _len);
//    std::string s(ab.begin(), ab.end());

    paillier_freeplaintext(dec);
//    free(ByteDec);

//    plaintext = s;
//    assert(StrDec == s);
    ret = 1;
    paillier_freeciphertext(V_ctx_typo[0]);
    return ret;


}

int PaillerWrapperFunctions::Pail_Parse_Ctx_Classic(paillier_pubkey_t* ppk,
                                                         char* ctx,
                                                         vector<paillier_ciphertext_t*> &Vect_Ctx)
{
//    size_t Ctxt_Byte_size =  PAILLIER_BITS_TO_BYTES(ppk->bits)*2;

//    char* byteCtxt1 = (char*)malloc(PAILLIER_BITS_TO_BYTES(ppk->bits)*2);
//    memcpy(byteCtxt1,  ctx, Ctxt_Byte_size);
    Vect_Ctx[0] = paillier_ciphertext_from_bytes((void*)ctx, PAILLIER_BITS_TO_BYTES(ppk->bits)*2);

//    free(byteCtxt1);

    return 1;

}



int PaillerWrapperFunctions::Enc_Byte_By_Byte(string& msg, paillier_pubkey_t* ppk, char ctx_final[])
{
    size_t msg_size;
    size_t ctxt_size =  PAILLIER_BITS_TO_BYTES(ppk->bits)*2;

    auto& str = msg;
    string s(begin(str), end(str));
    msg_size = s.size();
//    char* ctx_final =(char*) malloc (2 * sizeof(size_t) + msg_size * PAILLIER_BITS_TO_BYTES(ppk->bits)*2);
    memcpy(ctx_final, &msg_size, sizeof(size_t));
//    void* a = (char*) malloc (sizeof(char));
//    void* a = malloc (sizeof(char));

//    char* as = (char*) malloc (sizeof(char));
    paillier_plaintext_t* m;
//    paillier_plaintext_t* m = (paillier_plaintext_t*) malloc (sizeof(paillier_plaintext_t));
    memcpy(ctx_final + sizeof(size_t), &ctxt_size, sizeof(size_t));
//    for(int k = 0; k < msg_size; k++)
//    {
//        memcpy(aux + (k+1) * sizeof(size_t), &ctxt_size,sizeof(size_t));
//    }

    paillier_ciphertext_t* ctxt_i;
//    ctxt_i = (paillier_ciphertext_t*) malloc(ctxt_size);
//    char* byteCtxt1;
    void* byteCtxt1;
    for (int j = 0; j < msg_size ; ++j) {

//        memcpy(a  ,  &msg[0] + j, sizeof(char));
//        memcpy(as , a, sizeof(char));
//        cout << "this is:" <<  (char*) as << "\n";
        m = paillier_plaintext_from_bytes(&msg[j], sizeof(char));

        ctxt_i = paillier_enc(NULL, ppk, m, paillier_get_rand_devrandom);
//        byteCtxt1 = (char*)paillier_ciphertext_to_bytes(ctxt_size, ctxt_i);
        byteCtxt1 = paillier_ciphertext_to_bytes(ctxt_size, ctxt_i);
        memcpy(ctx_final  + 2 * sizeof(size_t) + j * ctxt_size, byteCtxt1,  ctxt_size);
        paillier_freeciphertext(ctxt_i);
        paillier_freeplaintext(m);
        free(byteCtxt1);
    }

//    size_t c =(size_t) malloc(sizeof(size_t));
//
//    memcpy(&c, aux  , sizeof(size_t));
//    cout << "after decoding the size from the void vector: " << c << "\n";
//    paillier_freeplaintext(m);

//    free(a);
//    free(as);

//    free(aux);
    return  1;
}


  vector<paillier_ciphertext_t*>
          PaillerWrapperFunctions::Pail_Parse_Real_Pass_Ctx
          (paillier_pubkey_t* ppk,
           string& ctx,
           int& VecSize,
           string &CtxAE,
           int b) {

    vector<paillier_ciphertext_t*> vctx;
//    = (char*)malloc(PAILLIER_BITS_TO_BYTES(ppk->bits)*2 );
    string delimiter = "%VVV";
    string s =  ctx;
    int counter = 0;
    int AECtxContr = 0;
    size_t pos = 0;
    string token;
    while ((pos = s.find(delimiter)) !=  string::npos) {
        token = s.substr(0, pos);
        if (AECtxContr == 0 && b == 1)
        {
            CtxAE = token;
            s.erase(0, pos + delimiter.length());
            AECtxContr++;
        }else {
            vctx.push_back (paillier_create_enc_zero());
            mpz_set_str(vctx[counter]->c,token.c_str(),10);
            s.erase(0, pos + delimiter.length());
            counter++;
        }
    }
    VecSize = counter;
    return  vctx;

}


  paillier_ciphertext_t*
  PaillerWrapperFunctions::Pail_Add(
          paillier_pubkey_t* ppk,
          paillier_ciphertext_t* ctx_1,
          paillier_ciphertext_t* ctx_2)
  {
      paillier_ciphertext_t* res;
      res = paillier_create_enc_zero();
      mpz_mul(res->c, ctx_1->c, ctx_2->c);
      mpz_mod(res->c, res->c, ppk->n_squared);
//      paillier_mul(ppk, res, ctx_1, ctx_2);
      return res;
  }
  paillier_ciphertext_t*
 PaillerWrapperFunctions::Pail_Mult_PtxCtx(
         paillier_pubkey_t* pub,
         paillier_ciphertext_t* ct,
         paillier_plaintext_t* pt)
 {
     paillier_ciphertext_t* res;
     res = paillier_create_enc_zero();
     mpz_powm(res->c, ct->c, pt->m, pub->n_squared);
//     paillier_exp(pub, r, ct, pt);
     return res;
 }


/*Subtract function: subtracts ctx_1 - ctx_2*/
  paillier_ciphertext_t*
  PaillerWrapperFunctions::Pail_Subtct(
          paillier_pubkey_t* ppk,
          paillier_ciphertext_t* ctx_1,
          paillier_ciphertext_t* ctx_2)
{
    paillier_ciphertext_t* Aux;
    Aux =paillier_create_enc_zero();
    paillier_ciphertext_t*  res;
//    res = (paillier_ciphertext_t*) malloc(256);
//    mpz_init_set_ui(res->c, 1);
    res =  paillier_create_enc_zero();
    mpz_t MinusOneModPK_n;
    mpz_init(MinusOneModPK_n);
    mpz_sub_ui (MinusOneModPK_n, ppk->n, 1);

    mpz_powm(Aux->c, ctx_2->c, MinusOneModPK_n, ppk->n_squared);
//    paillier_plaintext_t* minus_one = paillier_plaintext_from_ui( -1 );
//    paillier_ciphertext_t* Aux_2;
//    Aux_2 =paillier_create_enc_zero();
//    mpz_invert(ctx_2->c, ctx_2->c, ppk->n_squared);
//    mpz_mod(Aux_2->c, Aux_2->c, ppk->n_squared);
//        assert(mpz_invert(Aux_2->c, ctx_2->c, ppk->n_squared)>=0);
    paillier_mul(ppk, res, ctx_1, Aux);
//    paillier_mul(ppk, ctx_2, ctx_1, ctx_2);


    paillier_freeciphertext(Aux);
    mpz_clear(MinusOneModPK_n);
    return res;
}

/*Old Version*/
//  void
//  PaillerWrapperFunctions::init_rand(
//          gmp_randstate_t rand,
//          paillier_get_rand_t get_rand,
//          int bytes)
// {
//     void* buf;
//     mpz_t s;
//
//     buf = malloc(bytes);
//     get_rand(buf, bytes);
//
//     gmp_randinit_default(rand);
//     mpz_init(s);
//     mpz_import(s, bytes, 1, 1, 0, 0, buf);
//     gmp_randseed(rand, s);
//     mpz_clear(s);
//     free(buf);
// }

void
PaillerWrapperFunctions::init_rand( gmp_randstate_t rand, const int bytes )
{
    gmp_randinit_default(rand);
    // auto *rr = new gmp_randclass(gmp_randinit_default);
    gmp_randclass rr(gmp_randinit_default);
    rr.seed(time(nullptr));
    const mpz_class ran = rr.get_z_bits(bytes * 8);
    const unsigned long int random=ran.get_ui();
    gmp_randseed_ui(rand, random);
    // delete rr;
}


/*Old Version*/
 // paillier_plaintext_t*
//  PaillerWrapperFunctions::Rand_Plain_Pail(const paillier_pubkey_t* ppk)
//  {
//
// //        gmp_randstate_t rand;
//      paillier_get_rand_t get_rand = paillier_get_rand_devurandom;
// //        init_rand(rand, get_rand, num_bits / 8 + 1);
//      paillier_plaintext_t* R;
// //     paillier_plaintext_t* R;
//      R = (paillier_plaintext_t*) malloc(sizeof(paillier_plaintext_t));
//      mpz_init(R->m);
//      mpz_t r;
//      gmp_randstate_t rand;
//
//      /* pick random blinding factor */
//
//      mpz_init(r);
//      PaillerWrapperFunctions::init_rand(rand, get_rand, ppk->bits / 8 + 1);
//      do
//          mpz_urandomb(r, rand, ppk->bits);
//      while( mpz_cmp(r, ppk->n) >= 0 );
//
//      mpz_mod(R->m, r, ppk->n);
//      mpz_clear(r);
//      gmp_randclear(rand);
//      return R;
//  }

paillier_plaintext_t*
PaillerWrapperFunctions::Rand_Plain_Pail(const paillier_pubkey_t* ppk)
{

    auto R = static_cast<paillier_plaintext_t*>(malloc(sizeof(paillier_plaintext_t)));
    // paillier_plaintext_t* R;
    mpz_init(R->m);
    mpz_t r;
    gmp_randstate_t rand;

    mpz_init(r);
    // PaillerWrapperFunctions::init_rand(rand, get_rand, ppk->bits / 8 + 1);
    const int Rand_size_Byte = ppk->bits / 8 + 1;
    PaillerWrapperFunctions::init_rand(rand,Rand_size_Byte );

    do
        mpz_urandomb(r, rand, ppk->bits);
    while( mpz_cmp(r, ppk->n) >= 0 );

    mpz_mod(R->m, r, ppk->n);
    mpz_clear(r);
    gmp_randclear(rand);
    return R;
}



 vector<paillier_ciphertext_t*>
         PaillerWrapperFunctions::Enc_Vec_Typo(
                 string& msg,
                 paillier_pubkey_t* ppk)
 {

     auto& str = msg;
     string s(begin(str), end(str));
     size_t msg_size = s.size();
     vector<paillier_ciphertext_t*> vctx(msg_size);
     for (int j = 0; j < msg_size ; ++j) {
         paillier_plaintext_t* m;
//         unsigned muint;
//         muint = s[j];
//         m = paillier_plaintext_from_ui(muint);
         m = paillier_plaintext_from_bytes(&msg[j], sizeof(char));

         vctx[j] = paillier_enc(NULL, ppk, m, paillier_get_rand_devrandom);
         paillier_freeplaintext(m);
     }

//     paillier_freeplaintext(m);
     return vctx;
 }



 void
 PaillerWrapperFunctions::makeCombiUtil(
         vector<vector<int> >& ans,
         vector<int>& tmp,
         int n,
         int left,
         int k)
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


// Prints all combinations of size k of numbers
// from 1 to n.
 vector<vector<int> >
         PaillerWrapperFunctions::makeCombi(int n, int k)
{
    vector<vector<int> > ans;
    vector<int> tmp;
    makeCombiUtil(ans, tmp, n, 1, k);
    return ans;
}


vector<byte>
          PaillerWrapperFunctions::mpz_to_vector(
                  mpz_t x,
                  size_t _FinalVecSize)
  {
      size_t size =_FinalVecSize; //(mpz_sizeinbase (x, 2) + CHAR_BIT-1) / CHAR_BIT;
      vector<byte> v(size);
//      if(!&v[0])
//      {
//          cout <<  "the vaule v is a pointer to null\n";
//      }
//       vector<byte> cv(_FinalVecSize);
//      char* cvchar;
      void* cv;
      cv = malloc(_FinalVecSize * sizeof(unsigned char)); //
      //= (char*)malloc (_FinalVecSize * sizeof(char));
      mpz_export(cv, NULL, -1, 1, 0, 0, x);
      memcpy(&v[0], cv, _FinalVecSize );
//      mpz_export(&v[0], &size, -1, 1, 0, 0, x);
//      mpz_export(&v[0], NULL, -1, 1, 0, 0, x);
//      for(int i=0; i < _FinalVecSize; i++)
//      {
//          v[i] = cv[i];
//      }

//      v.resize(_FinalVecSize);
      free(cv);
      return v;
  }

vector<char>
PaillerWrapperFunctions::mpz_to_vector_char(
        mpz_t x,
        size_t _FinalVecSize)
{
    size_t size =_FinalVecSize; //(mpz_sizeinbase (x, 2) + CHAR_BIT-1) / CHAR_BIT;
    vector<char> v(size);
    mpz_export(&v[0], NULL, -1, 1, 0, 0, x);
    v.resize(_FinalVecSize);
    return v;
}
