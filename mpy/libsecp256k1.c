#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include "libsecp256k1-config.h"
#include "include/secp256k1.h"
#include "include/secp256k1_preallocated.h"
#include "include/secp256k1_extrakeys.h"
#include "include/secp256k1_schnorrsig.h"
#include "include/secp256k1_recovery.h"
#include "include/secp256k1_generator.h"
#include "include/secp256k1_rangeproof.h"
#include "include/secp256k1_surjectionproof.h"
#include "py/obj.h"
#include "py/objint.h"
#include "py/binary.h"
#include "py/runtime.h"
#include "py/builtin.h"
#include "py/gc.h"
#include "py/stream.h"
#include "rangeproof_preallocated/rangeproof_preallocated.h"


#define malloc(b) gc_alloc((b), false)
#define free gc_free

// global context
#define PREALLOCATED_CTX_SIZE 880 // 440 for 32-bit. FIXME: autodetect

STATIC unsigned char preallocated_ctx[PREALLOCATED_CTX_SIZE];
STATIC secp256k1_context * ctx = NULL;

void maybe_init_ctx(){
    if(ctx != NULL){
        return;
    }
    // ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY | SECP256K1_CONTEXT_SIGN);
    ctx = secp256k1_context_preallocated_create((void *)preallocated_ctx, SECP256K1_CONTEXT_VERIFY | SECP256K1_CONTEXT_SIGN);
}


STATIC mp_obj_t usecp256k1_context_preallocated_size(){
    size_t size = secp256k1_context_preallocated_size(SECP256K1_CONTEXT_VERIFY | SECP256K1_CONTEXT_SIGN);
    return mp_obj_new_int_from_ull(size);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_0(usecp256k1_context_preallocated_size_obj, usecp256k1_context_preallocated_size);


// randomize context using 32-byte seed
STATIC mp_obj_t usecp256k1_context_randomize(const mp_obj_t seed){
    maybe_init_ctx();
    mp_buffer_info_t seedbuf;
    mp_get_buffer_raise(seed, &seedbuf, MP_BUFFER_READ);
    if(seedbuf.len != 32){
        mp_raise_ValueError("Seed should be 32 bytes long");
        return mp_const_none;
    }
    int res = secp256k1_context_randomize(ctx, seedbuf.buf);
    if(!res){
        mp_raise_ValueError("Failed to randomize context");
        return mp_const_none;
    }
    return mp_const_none;
}
STATIC MP_DEFINE_CONST_FUN_OBJ_1(usecp256k1_context_randomize_obj, usecp256k1_context_randomize);

// create public key from private key
STATIC mp_obj_t usecp256k1_ec_pubkey_create(const mp_obj_t arg){
    maybe_init_ctx();
    mp_buffer_info_t secretbuf;
    mp_get_buffer_raise(arg, &secretbuf, MP_BUFFER_READ);
    if(secretbuf.len != 32){
        mp_raise_ValueError("Private key should be 32 bytes long");
        return mp_const_none;
    }
    secp256k1_pubkey pubkey;
    int res = secp256k1_ec_pubkey_create(ctx, &pubkey, secretbuf.buf);
    if(!res){
        mp_raise_ValueError("Invalid private key");
        return mp_const_none;
    }
    vstr_t vstr;
    vstr_init_len(&vstr, 64);
    memcpy((byte*)vstr.buf, pubkey.data, 64);

    return mp_obj_new_str_from_vstr(&mp_type_bytes, &vstr);
}

STATIC MP_DEFINE_CONST_FUN_OBJ_1(usecp256k1_ec_pubkey_create_obj, usecp256k1_ec_pubkey_create);

// parse sec-encoded public key
STATIC mp_obj_t usecp256k1_ec_pubkey_parse(const mp_obj_t arg){
    maybe_init_ctx();
    mp_buffer_info_t secbuf;
    mp_get_buffer_raise(arg, &secbuf, MP_BUFFER_READ);
    if(secbuf.len != 33 && secbuf.len != 65){
        mp_raise_ValueError("Serialized pubkey should be 33 or 65 bytes long");
        return mp_const_none;
    }
    byte * buf = (byte*)secbuf.buf;
    switch(secbuf.len){
        case 33:
            if(buf[0] != 0x02 && buf[0] != 0x03){
                mp_raise_ValueError("Compressed pubkey should start with 0x02 or 0x03");
                return mp_const_none;
            }
            break;
        case 65:
            if(buf[0] != 0x04){
                mp_raise_ValueError("Uncompressed pubkey should start with 0x04");
                return mp_const_none;
            }
            break;
    }
    secp256k1_pubkey pubkey;
    int res = secp256k1_ec_pubkey_parse(ctx, &pubkey, secbuf.buf, secbuf.len);
    if(!res){
        mp_raise_ValueError("Failed parsing public key");
        return mp_const_none;
    }
    vstr_t vstr;
    vstr_init_len(&vstr, 64);
    memcpy((byte*)vstr.buf, pubkey.data, 64);

    return mp_obj_new_str_from_vstr(&mp_type_bytes, &vstr);
}

STATIC MP_DEFINE_CONST_FUN_OBJ_1(usecp256k1_ec_pubkey_parse_obj, usecp256k1_ec_pubkey_parse);

// serialize public key
STATIC mp_obj_t usecp256k1_ec_pubkey_serialize(mp_uint_t n_args, const mp_obj_t *args){
    maybe_init_ctx();
    mp_buffer_info_t pubbuf;
    mp_get_buffer_raise(args[0], &pubbuf, MP_BUFFER_READ);
    if(pubbuf.len != 64){
        mp_raise_ValueError("Pubkey should be 64 bytes long");
        return mp_const_none;
    }
    secp256k1_pubkey pubkey;
    memcpy(pubkey.data, pubbuf.buf, 64);
    mp_int_t flag = SECP256K1_EC_COMPRESSED;
    if(n_args > 1){
        flag = mp_obj_get_int(args[1]);
    }
    byte out[65];
    size_t len = 65;
    int res = secp256k1_ec_pubkey_serialize(ctx, out, &len, &pubkey, flag);
    if(!res){
        mp_raise_ValueError("Failed serializing public key");
        return mp_const_none;
    }
    vstr_t vstr;
    vstr_init_len(&vstr, len);
    memcpy((byte*)vstr.buf, out, len);
    return mp_obj_new_str_from_vstr(&mp_type_bytes, &vstr);
}

STATIC MP_DEFINE_CONST_FUN_OBJ_VAR(usecp256k1_ec_pubkey_serialize_obj, 1, usecp256k1_ec_pubkey_serialize);

// parse compact ecdsa signature
STATIC mp_obj_t usecp256k1_ecdsa_signature_parse_compact(const mp_obj_t arg){
    maybe_init_ctx();
    mp_buffer_info_t buf;
    mp_get_buffer_raise(arg, &buf, MP_BUFFER_READ);
    if(buf.len != 64){
        mp_raise_ValueError("Compact signature should be 64 bytes long");
        return mp_const_none;
    }
    secp256k1_ecdsa_signature sig;
    int res = secp256k1_ecdsa_signature_parse_compact(ctx, &sig, buf.buf);
    if(!res){
        mp_raise_ValueError("Failed parsing compact signature");
        return mp_const_none;
    }
    vstr_t vstr;
    vstr_init_len(&vstr, 64);
    memcpy((byte*)vstr.buf, sig.data, 64);

    return mp_obj_new_str_from_vstr(&mp_type_bytes, &vstr);
}

STATIC MP_DEFINE_CONST_FUN_OBJ_1(usecp256k1_ecdsa_signature_parse_compact_obj, usecp256k1_ecdsa_signature_parse_compact);

// parse der ecdsa signature
STATIC mp_obj_t usecp256k1_ecdsa_signature_parse_der(const mp_obj_t arg){
    maybe_init_ctx();
    mp_buffer_info_t buf;
    mp_get_buffer_raise(arg, &buf, MP_BUFFER_READ);
    secp256k1_ecdsa_signature sig;
    int res = secp256k1_ecdsa_signature_parse_der(ctx, &sig, buf.buf, buf.len);
    if(!res){
        mp_raise_ValueError("Failed parsing der signature");
        return mp_const_none;
    }
    vstr_t vstr;
    vstr_init_len(&vstr, 64);
    memcpy((byte*)vstr.buf, sig.data, 64);

    return mp_obj_new_str_from_vstr(&mp_type_bytes, &vstr);
}

STATIC MP_DEFINE_CONST_FUN_OBJ_1(usecp256k1_ecdsa_signature_parse_der_obj, usecp256k1_ecdsa_signature_parse_der);

// serialize der ecdsa signature
STATIC mp_obj_t usecp256k1_ecdsa_signature_serialize_der(const mp_obj_t arg){
    maybe_init_ctx();
    mp_buffer_info_t buf;
    mp_get_buffer_raise(arg, &buf, MP_BUFFER_READ);
    if(buf.len != 64){
        mp_raise_ValueError("Signature should be 64 bytes long");
        return mp_const_none;
    }
    secp256k1_ecdsa_signature sig;
    memcpy(sig.data, buf.buf, 64);
    byte out[78];
    size_t len = 78;
    int res = secp256k1_ecdsa_signature_serialize_der(ctx, out, &len, &sig);
    if(!res){
        mp_raise_ValueError("Failed serializing der signature");
        return mp_const_none;
    }
    vstr_t vstr;
    vstr_init_len(&vstr, len);
    memcpy((byte*)vstr.buf, out, len);

    return mp_obj_new_str_from_vstr(&mp_type_bytes, &vstr);
}

STATIC MP_DEFINE_CONST_FUN_OBJ_1(usecp256k1_ecdsa_signature_serialize_der_obj, usecp256k1_ecdsa_signature_serialize_der);

// serialize compact ecdsa signature
STATIC mp_obj_t usecp256k1_ecdsa_signature_serialize_compact(const mp_obj_t arg){
    maybe_init_ctx();
    mp_buffer_info_t buf;
    mp_get_buffer_raise(arg, &buf, MP_BUFFER_READ);
    if(buf.len != 64){
        mp_raise_ValueError("Signature should be 64 bytes long");
        return mp_const_none;
    }
    secp256k1_ecdsa_signature sig;
    memcpy(sig.data, buf.buf, 64);
    vstr_t vstr;
    vstr_init_len(&vstr, 64);
    secp256k1_ecdsa_signature_serialize_compact(ctx, (byte*)vstr.buf, &sig);
    return mp_obj_new_str_from_vstr(&mp_type_bytes, &vstr);
}

STATIC MP_DEFINE_CONST_FUN_OBJ_1(usecp256k1_ecdsa_signature_serialize_compact_obj, usecp256k1_ecdsa_signature_serialize_compact);

// verify ecdsa signature
STATIC mp_obj_t usecp256k1_ecdsa_verify(const mp_obj_t sigarg, const mp_obj_t msgarg, const mp_obj_t pubkeyarg){
    maybe_init_ctx();
    mp_buffer_info_t buf;
    mp_get_buffer_raise(sigarg, &buf, MP_BUFFER_READ);
    if(buf.len != 64){
        mp_raise_ValueError("Signature should be 64 bytes long");
        return mp_const_none;
    }
    secp256k1_ecdsa_signature sig;
    memcpy(sig.data, buf.buf, 64);

    mp_get_buffer_raise(msgarg, &buf, MP_BUFFER_READ);
    if(buf.len != 32){
        mp_raise_ValueError("Message should be 32 bytes long");
        return mp_const_none;
    }
    byte msg[32];
    memcpy(msg, buf.buf, 32);

    mp_get_buffer_raise(pubkeyarg, &buf, MP_BUFFER_READ);
    if(buf.len != 64){
        mp_raise_ValueError("Public key should be 64 bytes long");
        return mp_const_none;
    }
    secp256k1_pubkey pub;
    memcpy(pub.data, buf.buf, 64);

    int res = secp256k1_ecdsa_verify(ctx, &sig, msg, &pub);
    if(res){
        return mp_const_true;
    }
    return mp_const_false;
}

STATIC MP_DEFINE_CONST_FUN_OBJ_3(usecp256k1_ecdsa_verify_obj, usecp256k1_ecdsa_verify);

// normalize ecdsa signature
STATIC mp_obj_t usecp256k1_ecdsa_signature_normalize(const mp_obj_t arg){
    maybe_init_ctx();
    mp_buffer_info_t buf;
    mp_get_buffer_raise(arg, &buf, MP_BUFFER_READ);
    if(buf.len != 64){
        mp_raise_ValueError("Signature should be 64 bytes long");
        return mp_const_none;
    }
    secp256k1_ecdsa_signature sig;
    secp256k1_ecdsa_signature sig2;
    memcpy(sig.data, buf.buf, 64);
    vstr_t vstr;
    vstr_init_len(&vstr, 64);
    secp256k1_ecdsa_signature_normalize(ctx, &sig2, &sig);
    memcpy(vstr.buf, sig2.data, 64);
    return mp_obj_new_str_from_vstr(&mp_type_bytes, &vstr);
}

STATIC MP_DEFINE_CONST_FUN_OBJ_1(usecp256k1_ecdsa_signature_normalize_obj, usecp256k1_ecdsa_signature_normalize);

// same as secp256k1_nonce_function_rfc6979
STATIC mp_obj_t usecp256k1_nonce_function_default(mp_uint_t n_args, const mp_obj_t *args){
    mp_buffer_info_t msgbuf;
    mp_get_buffer_raise(args[0], &msgbuf, MP_BUFFER_READ);
    if(msgbuf.len != 32){
        mp_raise_ValueError("Message should be 32 bytes long");
        return mp_const_none;
    }
    mp_buffer_info_t secbuf;
    mp_get_buffer_raise(args[1], &secbuf, MP_BUFFER_READ);
    if(secbuf.len != 32){
        mp_raise_ValueError("Secret should be 32 bytes long");
        return mp_const_none;
    }
    unsigned char *algo16 = NULL;
    void *data = NULL;
    int attempt = 0;
    // result
    vstr_t nonce;
    vstr_init_len(&nonce, 32);
    if(n_args > 2){
        if(args[2] != mp_const_none){
            mp_buffer_info_t algbuf;
            mp_get_buffer_raise(args[0], &algbuf, MP_BUFFER_READ);
            algo16 = algbuf.buf;
        }
        if(n_args > 3 && args[3]!=mp_const_none){
            mp_buffer_info_t databuf;
            if (!mp_get_buffer(args[3], &databuf, MP_BUFFER_READ)) {
                data = (void*) args[3];
            }else{
                data = (void*) databuf.buf;
            }
        }
        if(n_args > 4){
            attempt = mp_obj_get_int(args[4]);
        }
    }
    int res = secp256k1_nonce_function_default((unsigned char*)nonce.buf, msgbuf.buf, secbuf.buf, algo16, data, attempt);
    if(!res){
        mp_raise_ValueError("Failed to calculate nonce");
        return mp_const_none;
    }
    return mp_obj_new_str_from_vstr(&mp_type_bytes, &nonce);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_VAR(usecp256k1_nonce_function_default_obj, 2, usecp256k1_nonce_function_default);

STATIC mp_obj_t mp_nonce_callback = NULL;
STATIC mp_obj_t mp_nonce_data = NULL;

STATIC int usecp256k1_nonce_function(
    unsigned char *nonce32,
    const unsigned char *msg32,
    const unsigned char *key32,
    const unsigned char *algo16,
    void *data,
    unsigned int attempt
    ){

    return secp256k1_nonce_function_default(nonce32, msg32, key32, algo16, data, attempt);
    // TODO: make nonce function compatible with ctypes
    // if(!mp_obj_is_callable(mp_nonce_callback)){
    //     mp_raise_ValueError("Nonce callback should be callable...");
    //     return mp_const_none;
    // }

    // if(attempt > 100){
    //     mp_raise_ValueError("Too many attempts... Invalid function?");
    //     // not sure it will ever get here, but just in case
    //     return secp256k1_nonce_function_default(nonce32, msg32, key32, algo16, data, attempt);
    // }
    // mp_obj_t mp_args[5];
    // mp_args[0] = mp_obj_new_bytes(msg32, 32);
    // mp_args[1] = mp_obj_new_bytes(key32, 32);
    // if(algo16!=NULL){
    //     mp_args[2] = mp_obj_new_bytes(key32, 16);
    // }else{
    //     mp_args[2] = mp_const_none;
    // }
    // if(mp_nonce_data!=NULL){
    //     mp_args[3] = mp_nonce_data;
    // }else{
    //     mp_args[3] = mp_const_none;
    // }
    // mp_args[4] = mp_obj_new_int_from_uint(attempt);

    // mp_obj_t mp_res = mp_call_function_n_kw(mp_nonce_callback , 5, 0, mp_args);
    // if(mp_res == mp_const_none){
    //     return 0;
    // }
    // mp_buffer_info_t buffer_info;
    // if (!mp_get_buffer(mp_res, &buffer_info, MP_BUFFER_READ)) {
    //     return 0;
    // }
    // if(buffer_info.len < 32){
    //     mp_raise_ValueError("Returned nonce is less than 32 bytes");
    //     return 0;
    // }
    // memcpy(nonce32, (byte*)buffer_info.buf, 32);
    // return 1;
}

// msg, secret, [callback, data]
STATIC mp_obj_t usecp256k1_ecdsa_sign(mp_uint_t n_args, const mp_obj_t *args){
    maybe_init_ctx();
    mp_nonce_data = NULL;
    if(n_args < 2){
        mp_raise_ValueError("Function requires at least two arguments: message and private key");
        return mp_const_none;
    }
    mp_buffer_info_t msgbuf;
    mp_get_buffer_raise(args[0], &msgbuf, MP_BUFFER_READ);
    if(msgbuf.len != 32){
        mp_raise_ValueError("Message should be 32 bytes long");
        return mp_const_none;
    }

    mp_buffer_info_t secbuf;
    mp_get_buffer_raise(args[1], &secbuf, MP_BUFFER_READ);
    if(secbuf.len != 32){
        mp_raise_ValueError("Secret key should be 32 bytes long");
        return mp_const_none;
    }
    secp256k1_ecdsa_signature sig;

    mp_buffer_info_t databuf;
    void * data = NULL;

    int res=0;
    if(n_args == 2){
        res = secp256k1_ecdsa_sign(ctx, &sig, msgbuf.buf, secbuf.buf, NULL, NULL);
    }else if(n_args >= 3){
        mp_nonce_callback = args[2];
        if(n_args > 3){
            mp_get_buffer_raise(args[3], &databuf, MP_BUFFER_READ);
            if(databuf.len != 32){
                mp_raise_ValueError("Data should be 32 bytes long");
                return mp_const_none;
            }
            data = databuf.buf;
        }
        res = secp256k1_ecdsa_sign(ctx, &sig, msgbuf.buf, secbuf.buf, usecp256k1_nonce_function, data);
    }
    if(!res){
        mp_raise_ValueError("Failed to sign");
        return mp_const_none;
    }

    vstr_t vstr;
    vstr_init_len(&vstr, 64);
    memcpy((byte*)vstr.buf, sig.data, 64);

    return mp_obj_new_str_from_vstr(&mp_type_bytes, &vstr);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_VAR(usecp256k1_ecdsa_sign_obj, 2, usecp256k1_ecdsa_sign);

// verify secret key
STATIC mp_obj_t usecp256k1_ec_seckey_verify(const mp_obj_t arg){
    maybe_init_ctx();
    mp_buffer_info_t buf;
    mp_get_buffer_raise(arg, &buf, MP_BUFFER_READ);
    if(buf.len != 32){
        mp_raise_ValueError("Private key should be 32 bytes long");
        return mp_const_none;
    }

    int res = secp256k1_ec_seckey_verify(ctx, buf.buf);
    if(res){
        return mp_const_true;
    }
    return mp_const_false;
}

STATIC MP_DEFINE_CONST_FUN_OBJ_1(usecp256k1_ec_seckey_verify_obj, usecp256k1_ec_seckey_verify);

// return N - secret key
STATIC mp_obj_t usecp256k1_ec_privkey_negate(mp_obj_t arg){
    maybe_init_ctx();
    mp_buffer_info_t buf;
    mp_get_buffer_raise(arg, &buf, MP_BUFFER_READ);
    if(buf.len != 32){
        mp_raise_ValueError("Private key should be 32 bytes long");
        return mp_const_none;
    }

    vstr_t vstr;
    vstr_init_len(&vstr, 32);
    memcpy((byte*)vstr.buf, buf.buf, 32);

    int res = secp256k1_ec_privkey_negate(ctx, vstr.buf);
    if(!res){ // never happens according to the API
        mp_raise_ValueError("Failed to negate the private key");
        return mp_const_none;
    }
    return mp_obj_new_str_from_vstr(&mp_type_bytes, &vstr);
}

STATIC MP_DEFINE_CONST_FUN_OBJ_1(usecp256k1_ec_privkey_negate_obj, usecp256k1_ec_privkey_negate);

// return neg of pubkey
STATIC mp_obj_t usecp256k1_ec_pubkey_negate(mp_obj_t arg){
    maybe_init_ctx();
    mp_buffer_info_t buf;
    mp_get_buffer_raise(arg, &buf, MP_BUFFER_READ);
    if(buf.len != 64){
        mp_raise_ValueError("Publick key should be 64 bytes long");
        return mp_const_none;
    }

    vstr_t vstr;
    vstr_init_len(&vstr, 64);
    memcpy((byte*)vstr.buf, buf.buf, 64);

    int res = secp256k1_ec_pubkey_negate(ctx, (secp256k1_pubkey *)vstr.buf);
    if(!res){ // never happens according to the API
        mp_raise_ValueError("Failed to negate the public key");
        return mp_const_none;
    }
    return mp_obj_new_str_from_vstr(&mp_type_bytes, &vstr);
}

STATIC MP_DEFINE_CONST_FUN_OBJ_1(usecp256k1_ec_pubkey_negate_obj, usecp256k1_ec_pubkey_negate);

// tweak private key in place
STATIC mp_obj_t usecp256k1_ec_privkey_tweak_add(mp_obj_t privarg, const mp_obj_t tweakarg){
    maybe_init_ctx();
    mp_buffer_info_t privbuf;
    mp_get_buffer_raise(privarg, &privbuf, MP_BUFFER_READ);
    if(privbuf.len != 32){
        mp_raise_ValueError("Private key should be 32 bytes long");
        return mp_const_none;
    }

    mp_buffer_info_t tweakbuf;
    mp_get_buffer_raise(tweakarg, &tweakbuf, MP_BUFFER_READ);
    if(tweakbuf.len != 32){
        mp_raise_ValueError("Tweak should be 32 bytes long");
        return mp_const_none;
    }

    int res = secp256k1_ec_privkey_tweak_add(ctx, privbuf.buf, tweakbuf.buf);
    if(!res){ // never happens according to the API
        mp_raise_ValueError("Failed to tweak the private key");
        return mp_const_none;
    }
    return mp_const_none;
}

STATIC MP_DEFINE_CONST_FUN_OBJ_2(usecp256k1_ec_privkey_tweak_add_obj, usecp256k1_ec_privkey_tweak_add);

// add private key
STATIC mp_obj_t usecp256k1_ec_privkey_add(mp_obj_t privarg, const mp_obj_t tweakarg){
    maybe_init_ctx();
    mp_buffer_info_t privbuf;
    mp_get_buffer_raise(privarg, &privbuf, MP_BUFFER_READ);
    if(privbuf.len != 32){
        mp_raise_ValueError("Private key should be 32 bytes long");
        return mp_const_none;
    }

    mp_buffer_info_t tweakbuf;
    mp_get_buffer_raise(tweakarg, &tweakbuf, MP_BUFFER_READ);
    if(tweakbuf.len != 32){
        mp_raise_ValueError("Tweak should be 32 bytes long");
        return mp_const_none;
    }

    vstr_t priv2;
    vstr_init_len(&priv2, 32);
    memcpy((byte*)priv2.buf, privbuf.buf, 32);

    int res = secp256k1_ec_privkey_tweak_add(ctx, priv2.buf, tweakbuf.buf);
    if(!res){ // never happens according to the API
        mp_raise_ValueError("Failed to tweak the private key");
        return mp_const_none;
    }
    return mp_obj_new_str_from_vstr(&mp_type_bytes, &priv2);
}

STATIC MP_DEFINE_CONST_FUN_OBJ_2(usecp256k1_ec_privkey_add_obj, usecp256k1_ec_privkey_add);

// tweak public key in place (add tweak * Generator)
STATIC mp_obj_t usecp256k1_ec_pubkey_tweak_add(mp_obj_t pubarg, const mp_obj_t tweakarg){
    maybe_init_ctx();
    mp_buffer_info_t pubbuf;
    mp_get_buffer_raise(pubarg, &pubbuf, MP_BUFFER_READ);
    if(pubbuf.len != 64){
        mp_raise_ValueError("Public key should be 64 bytes long");
        return mp_const_none;
    }
    secp256k1_pubkey pub;
    memcpy(pub.data, pubbuf.buf, 64);

    mp_buffer_info_t tweakbuf;
    mp_get_buffer_raise(tweakarg, &tweakbuf, MP_BUFFER_READ);
    if(tweakbuf.len != 32){
        mp_raise_ValueError("Tweak should be 32 bytes long");
        return mp_const_none;
    }

    int res = secp256k1_ec_pubkey_tweak_add(ctx, &pub, tweakbuf.buf);
    if(!res){ // never happens according to the API
        mp_raise_ValueError("Failed to tweak the public key");
        return mp_const_none;
    }
    memcpy(pubbuf.buf, pub.data, 64);
    return mp_const_none;
}

STATIC MP_DEFINE_CONST_FUN_OBJ_2(usecp256k1_ec_pubkey_tweak_add_obj, usecp256k1_ec_pubkey_tweak_add);

// add tweak * Generator
STATIC mp_obj_t usecp256k1_ec_pubkey_add(mp_obj_t pubarg, const mp_obj_t tweakarg){
    maybe_init_ctx();
    mp_buffer_info_t pubbuf;
    mp_get_buffer_raise(pubarg, &pubbuf, MP_BUFFER_READ);
    if(pubbuf.len != 64){
        mp_raise_ValueError("Public key should be 64 bytes long");
        return mp_const_none;
    }
    secp256k1_pubkey pub;
    memcpy(pub.data, pubbuf.buf, 64);

    mp_buffer_info_t tweakbuf;
    mp_get_buffer_raise(tweakarg, &tweakbuf, MP_BUFFER_READ);
    if(tweakbuf.len != 32){
        mp_raise_ValueError("Tweak should be 32 bytes long");
        return mp_const_none;
    }

    int res = secp256k1_ec_pubkey_tweak_add(ctx, &pub, tweakbuf.buf);
    if(!res){ // never happens according to the API
        mp_raise_ValueError("Failed to tweak the public key");
        return mp_const_none;
    }

    vstr_t pubbuf2;
    vstr_init_len(&pubbuf2, 64);
    memcpy((byte*)pubbuf2.buf, pub.data, 64);
    return mp_obj_new_str_from_vstr(&mp_type_bytes, &pubbuf2);
}

STATIC MP_DEFINE_CONST_FUN_OBJ_2(usecp256k1_ec_pubkey_add_obj, usecp256k1_ec_pubkey_add);

// tweak private key in place (multiply by tweak)
STATIC mp_obj_t usecp256k1_ec_privkey_tweak_mul(mp_obj_t privarg, const mp_obj_t tweakarg){
    maybe_init_ctx();
    mp_buffer_info_t privbuf;
    mp_get_buffer_raise(privarg, &privbuf, MP_BUFFER_READ);
    if(privbuf.len != 32){
        mp_raise_ValueError("Private key should be 32 bytes long");
        return mp_const_none;
    }

    mp_buffer_info_t tweakbuf;
    mp_get_buffer_raise(tweakarg, &tweakbuf, MP_BUFFER_READ);
    if(tweakbuf.len != 32){
        mp_raise_ValueError("Tweak should be 32 bytes long");
        return mp_const_none;
    }

    int res = secp256k1_ec_privkey_tweak_mul(ctx, privbuf.buf, tweakbuf.buf);
    if(!res){ // never happens according to the API
        mp_raise_ValueError("Failed to tweak the public key");
        return mp_const_none;
    }
    return mp_const_none;
}

STATIC MP_DEFINE_CONST_FUN_OBJ_2(usecp256k1_ec_privkey_tweak_mul_obj, usecp256k1_ec_privkey_tweak_mul);

// tweak public key in place (multiply by tweak)
STATIC mp_obj_t usecp256k1_ec_pubkey_tweak_mul(mp_obj_t pubarg, const mp_obj_t tweakarg){
    maybe_init_ctx();
    mp_buffer_info_t pubbuf;
    mp_get_buffer_raise(pubarg, &pubbuf, MP_BUFFER_READ);
    if(pubbuf.len != 64){
        mp_raise_ValueError("Public key should be 64 bytes long");
        return mp_const_none;
    }
    secp256k1_pubkey pub;
    memcpy(pub.data, pubbuf.buf, 64);

    mp_buffer_info_t tweakbuf;
    mp_get_buffer_raise(tweakarg, &tweakbuf, MP_BUFFER_READ);
    if(tweakbuf.len != 32){
        mp_raise_ValueError("Tweak should be 32 bytes long");
        return mp_const_none;
    }

    int res = secp256k1_ec_pubkey_tweak_mul(ctx, &pub, tweakbuf.buf);
    if(!res){ // never happens according to the API
        mp_raise_ValueError("Failed to tweak the public key");
        return mp_const_none;
    }
    memcpy(pubbuf.buf, pub.data, 64);
    return mp_const_none;
}

STATIC MP_DEFINE_CONST_FUN_OBJ_2(usecp256k1_ec_pubkey_tweak_mul_obj, usecp256k1_ec_pubkey_tweak_mul);

// adds public keys
STATIC mp_obj_t usecp256k1_ec_pubkey_combine(mp_uint_t n_args, const mp_obj_t *args){
    maybe_init_ctx();
    secp256k1_pubkey pubkey;
    secp256k1_pubkey ** pubkeys;
    pubkeys = (secp256k1_pubkey **)malloc(sizeof(secp256k1_pubkey*)*n_args);
    mp_buffer_info_t pubbuf;
    for(unsigned int i=0; i<n_args; i++){ // TODO: can be refactored to avoid allocation
        mp_get_buffer_raise(args[i], &pubbuf, MP_BUFFER_READ);
        if(pubbuf.len != 64){
            for(unsigned int j=0; j<i; j++){
                free(pubkeys[j]);
            }
            free(pubkeys);
            mp_raise_ValueError("All pubkeys should be 64 bytes long");
            return mp_const_none;
        }
        pubkeys[i] = (secp256k1_pubkey *)malloc(64);
        memcpy(pubkeys[i]->data, pubbuf.buf, 64);
    }
    int res = secp256k1_ec_pubkey_combine(ctx, &pubkey, (const secp256k1_pubkey *const *)pubkeys, n_args);
    if(!res){
        mp_raise_ValueError("Failed combining public keys");
        return mp_const_none;
    }
    vstr_t vstr;
    vstr_init_len(&vstr, 64);
    memcpy((byte*)vstr.buf, pubkey.data, 64);
    for(unsigned int i=0; i<n_args; i++){
        free(pubkeys[i]);
    }
    free(pubkeys);
    return mp_obj_new_str_from_vstr(&mp_type_bytes, &vstr);
}

STATIC MP_DEFINE_CONST_FUN_OBJ_VAR(usecp256k1_ec_pubkey_combine_obj, 2, usecp256k1_ec_pubkey_combine);

/**************************** schnorrsig ****************************/

STATIC mp_obj_t usecp256k1_xonly_pubkey_from_pubkey(mp_obj_t arg){
    maybe_init_ctx();
    mp_buffer_info_t buf;
    mp_get_buffer_raise(arg, &buf, MP_BUFFER_READ);
    if(buf.len != 64){
        mp_raise_ValueError("Public key should be 64 bytes long");
        return mp_const_none;
    }

    vstr_t vstr;
    vstr_init_len(&vstr, 64);
    int parity = 0;

    int res = secp256k1_xonly_pubkey_from_pubkey(ctx, (secp256k1_xonly_pubkey *)vstr.buf, &parity, buf.buf);
    if(!res){
        mp_raise_ValueError("Failed to convert the public key");
        return mp_const_none;
    }

    mp_obj_t items[2];
    items[0] = mp_obj_new_str_from_vstr(&mp_type_bytes, &vstr);
    items[1] = mp_obj_new_int(parity);
    return mp_obj_new_tuple(2, items);
}

STATIC MP_DEFINE_CONST_FUN_OBJ_1(usecp256k1_xonly_pubkey_from_pubkey_obj, usecp256k1_xonly_pubkey_from_pubkey);


STATIC mp_obj_t usecp256k1_schnorrsig_verify(const mp_obj_t sigarg, const mp_obj_t msgarg, const mp_obj_t pubkeyarg){
    maybe_init_ctx();
    mp_buffer_info_t buf;
    mp_get_buffer_raise(sigarg, &buf, MP_BUFFER_READ);
    if(buf.len != 64){
        mp_raise_ValueError("Signature should be 64 bytes long");
        return mp_const_none;
    }
    byte sig[64];
    memcpy(sig, buf.buf, 64);

    mp_get_buffer_raise(msgarg, &buf, MP_BUFFER_READ);
    if(buf.len != 32){
        mp_raise_ValueError("Message should be 32 bytes long");
        return mp_const_none;
    }
    byte msg[32];
    memcpy(msg, buf.buf, 32);

    mp_get_buffer_raise(pubkeyarg, &buf, MP_BUFFER_READ);
    if(buf.len != 64){
        mp_raise_ValueError("Public key should be 64 bytes long");
        return mp_const_none;
    }
    secp256k1_xonly_pubkey pub;
    memcpy(pub.data, buf.buf, 64);

    int res = secp256k1_schnorrsig_verify(ctx, sig, msg, &pub);
    if(res){
        return mp_const_true;
    }
    return mp_const_false;
}

STATIC MP_DEFINE_CONST_FUN_OBJ_3(usecp256k1_schnorrsig_verify_obj, usecp256k1_schnorrsig_verify);


STATIC mp_obj_t usecp256k1_keypair_create(mp_obj_t arg){
    maybe_init_ctx();
    mp_buffer_info_t buf;
    mp_get_buffer_raise(arg, &buf, MP_BUFFER_READ);
    if(buf.len != 32){
        mp_raise_ValueError("Secret should be 32 bytes long");
        return mp_const_none;
    }

    vstr_t vstr;
    vstr_init_len(&vstr, 96);
    int parity = 0;

    int res = secp256k1_keypair_create(ctx, (secp256k1_keypair *)vstr.buf, buf.buf);
    if(!res){
        mp_raise_ValueError("Failed to create keypair");
        return mp_const_none;
    }

    return mp_obj_new_str_from_vstr(&mp_type_bytes, &vstr);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_1(usecp256k1_keypair_create_obj, usecp256k1_keypair_create);


// msg, secret, [callback, data]
STATIC mp_obj_t usecp256k1_schnorrsig_sign(mp_uint_t n_args, const mp_obj_t *args){
    maybe_init_ctx();
    mp_nonce_data = NULL;
    if(n_args < 2){
        mp_raise_ValueError("Function requires at least two arguments: message and private key");
        return mp_const_none;
    }
    mp_buffer_info_t msgbuf;
    mp_get_buffer_raise(args[0], &msgbuf, MP_BUFFER_READ);
    if(msgbuf.len != 32){
        mp_raise_ValueError("Message should be 32 bytes long");
        return mp_const_none;
    }

    mp_buffer_info_t secbuf;
    mp_get_buffer_raise(args[1], &secbuf, MP_BUFFER_READ);
    if(secbuf.len != 32 && secbuf.len != 96){
        mp_raise_ValueError("Secret key should be 32 bytes long or 96 bytes long (keypair)");
        return mp_const_none;
    }
    byte keypair[96];
    if(secbuf.len == 32){
        int res = secp256k1_keypair_create(ctx, (secp256k1_keypair *)keypair, secbuf.buf);
        if(!res){
            mp_raise_ValueError("Failed to create keypair");
            return mp_const_none;
        }
    }else{
        memcpy(keypair, secbuf.buf, 96);
    }
    byte sig[64];

    mp_buffer_info_t databuf;
    void * data = NULL;

    int res=0;
    if(n_args == 2){
        res = secp256k1_schnorrsig_sign(ctx, sig, msgbuf.buf, (secp256k1_keypair *)keypair, NULL, NULL);
    }else if(n_args >= 3){
        mp_nonce_callback = args[2];
        if(n_args > 3){
            mp_get_buffer_raise(args[3], &databuf, MP_BUFFER_READ);
            if(databuf.len != 32){
                mp_raise_ValueError("Data should be 32 bytes long");
                return mp_const_none;
            }
            data = databuf.buf;
        }
        res = secp256k1_schnorrsig_sign(ctx, sig, msgbuf.buf, (secp256k1_keypair *)keypair, NULL, data);
    }
    if(!res){
        mp_raise_ValueError("Failed to sign");
        return mp_const_none;
    }

    vstr_t vstr;
    vstr_init_len(&vstr, 64);
    memcpy((byte*)vstr.buf, sig, 64);

    return mp_obj_new_str_from_vstr(&mp_type_bytes, &vstr);
}

STATIC MP_DEFINE_CONST_FUN_OBJ_VAR(usecp256k1_schnorrsig_sign_obj, 2, usecp256k1_schnorrsig_sign);

/**************************** recoverable ***************************/

// msg, secret, [callback, data]
STATIC mp_obj_t usecp256k1_ecdsa_sign_recoverable(mp_uint_t n_args, const mp_obj_t *args){
    maybe_init_ctx();
    mp_nonce_data = NULL;
    if(n_args < 2){
        mp_raise_ValueError("Function requires at least two arguments: message and private key");
        return mp_const_none;
    }
    mp_buffer_info_t msgbuf;
    mp_get_buffer_raise(args[0], &msgbuf, MP_BUFFER_READ);
    if(msgbuf.len != 32){
        mp_raise_ValueError("Message should be 32 bytes long");
        return mp_const_none;
    }

    mp_buffer_info_t secbuf;
    mp_get_buffer_raise(args[1], &secbuf, MP_BUFFER_READ);
    if(secbuf.len != 32){
        mp_raise_ValueError("Secret key should be 32 bytes long");
        return mp_const_none;
    }
    secp256k1_ecdsa_recoverable_signature sig;
    int res=0;

    mp_buffer_info_t databuf;
    void * data = NULL;

    if(n_args == 2){
        res = secp256k1_ecdsa_sign_recoverable(ctx, &sig, msgbuf.buf, secbuf.buf, NULL, NULL);
    }else if(n_args >= 3){
        mp_nonce_callback = args[2];
        if(n_args > 3){
            mp_get_buffer_raise(args[3], &databuf, MP_BUFFER_READ);
            if(databuf.len != 32){
                mp_raise_ValueError("Data should be 32 bytes long");
                return mp_const_none;
            }
            data = databuf.buf;
        }
        res = secp256k1_ecdsa_sign_recoverable(ctx, &sig, msgbuf.buf, secbuf.buf, usecp256k1_nonce_function, data);
    }
    if(!res){
        mp_raise_ValueError("Failed to sign");
        return mp_const_none;
    }

    vstr_t vstr;
    vstr_init_len(&vstr, 65);
    memcpy((byte*)vstr.buf, sig.data, 65);

    return mp_obj_new_str_from_vstr(&mp_type_bytes, &vstr);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_VAR(usecp256k1_ecdsa_sign_recoverable_obj, 2, usecp256k1_ecdsa_sign_recoverable);

/******************************* zkp ********************************/

STATIC mp_obj_t usecp256k1_generator_generate_blinded(const mp_obj_t assetarg, const mp_obj_t abfarg){
    maybe_init_ctx();
    mp_buffer_info_t assetbuf;
    mp_get_buffer_raise(assetarg, &assetbuf, MP_BUFFER_READ);
    if(assetbuf.len != 32){
        mp_raise_ValueError("Asset should be 32 bytes long");
        return mp_const_none;
    }

    mp_buffer_info_t abfbuf;
    mp_get_buffer_raise(abfarg, &abfbuf, MP_BUFFER_READ);
    if(abfbuf.len != 32){
        mp_raise_ValueError("Blinding factor should be 32 bytes long");
        return mp_const_none;
    }

    secp256k1_generator gen;

    int res = secp256k1_generator_generate_blinded(ctx, &gen, assetbuf.buf, abfbuf.buf);
    if(!res){ // never happens according to the API
        mp_raise_ValueError("Failed to generate generator");
        return mp_const_none;
    }
    vstr_t vstr;
    vstr_init_len(&vstr, 64);
    memcpy(vstr.buf, gen.data, 64);
    return mp_obj_new_str_from_vstr(&mp_type_bytes, &vstr);
}

STATIC MP_DEFINE_CONST_FUN_OBJ_2(usecp256k1_generator_generate_blinded_obj, usecp256k1_generator_generate_blinded);

// serialize generator
STATIC mp_obj_t usecp256k1_generator_serialize(const mp_obj_t arg){
    maybe_init_ctx();
    mp_buffer_info_t buf;
    mp_get_buffer_raise(arg, &buf, MP_BUFFER_READ);
    if(buf.len != 64){
        mp_raise_ValueError("Generator should be 64 bytes long");
        return mp_const_none;
    }
    secp256k1_generator gen;
    memcpy(gen.data, buf.buf, 64);
    vstr_t vstr;
    vstr_init_len(&vstr, 33);
    secp256k1_generator_serialize(ctx, (byte*)vstr.buf, &gen);
    return mp_obj_new_str_from_vstr(&mp_type_bytes, &vstr);
}

STATIC MP_DEFINE_CONST_FUN_OBJ_1(usecp256k1_generator_serialize_obj, usecp256k1_generator_serialize);

STATIC mp_obj_t usecp256k1_generator_parse(const mp_obj_t arg){
    maybe_init_ctx();
    mp_buffer_info_t buf;
    mp_get_buffer_raise(arg, &buf, MP_BUFFER_READ);
    if(buf.len != 33){
        mp_raise_ValueError("Serialized generator should be 33 bytes long");
        return mp_const_none;
    }
    secp256k1_generator gen;
    int res = secp256k1_generator_parse(ctx, &gen, buf.buf);
    if(!res){
        mp_raise_ValueError("Failed to parse commitment");
        return mp_const_none;
    }
    vstr_t vstr;
    vstr_init_len(&vstr, 64);
    memcpy(vstr.buf, gen.data, 64);
    return mp_obj_new_str_from_vstr(&mp_type_bytes, &vstr);
}

STATIC MP_DEFINE_CONST_FUN_OBJ_1(usecp256k1_generator_parse_obj, usecp256k1_generator_parse);

// pedersen_commit(value_blinding_factor, value, gen)
STATIC mp_obj_t usecp256k1_pedersen_commit(const mp_obj_t blindarg, mp_obj_t valuearg, const mp_obj_t genarg){
    maybe_init_ctx();
    mp_buffer_info_t blindbuf;
    mp_get_buffer_raise(blindarg, &blindbuf, MP_BUFFER_READ);
    if(blindbuf.len != 32){
        mp_raise_ValueError("Blinding factor should be 32 bytes long");
        return mp_const_none;
    }

    mp_buffer_info_t genbuf;
    mp_get_buffer_raise(genarg, &genbuf, MP_BUFFER_READ);
    if(genbuf.len != 64){
        mp_raise_ValueError("Generator should be 64 bytes long");
        return mp_const_none;
    }

    assert(mp_obj_is_type(valuearg, &mp_type_int));
    uint64_t value = 0;
    // int to big endian
    byte buf[8] = {0};
    #if MICROPY_LONGINT_IMPL != MICROPY_LONGINT_IMPL_NONE
    if (!mp_obj_is_small_int(valuearg)) {
        mp_obj_int_to_bytes_impl(valuearg, true, 8, buf);
    } else
    #endif
    {
        mp_int_t val = MP_OBJ_SMALL_INT_VALUE(valuearg);
        size_t l = MIN(8, sizeof(val));
        mp_binary_set_int(l, true, buf + 8 - l, val);
    }
    for (int i = 0; i < 8; ++i)
    {
        value = (value << 8);
        value += buf[i];
    }


    secp256k1_generator gen;
    memcpy(gen.data, genbuf.buf, 64);

    secp256k1_pedersen_commitment commit;

    int res = secp256k1_pedersen_commit(ctx, &commit, blindbuf.buf, value, genbuf.buf);
    if(!res){
        mp_raise_ValueError("Failed to create commitment");
        return mp_const_none;
    }
    vstr_t vstr;
    vstr_init_len(&vstr, 64);
    memcpy(vstr.buf, commit.data, 64);
    return mp_obj_new_str_from_vstr(&mp_type_bytes, &vstr);
}

STATIC MP_DEFINE_CONST_FUN_OBJ_3(usecp256k1_pedersen_commit_obj, usecp256k1_pedersen_commit);

STATIC mp_obj_t usecp256k1_pedersen_commitment_serialize(const mp_obj_t arg){
    maybe_init_ctx();
    mp_buffer_info_t buf;
    mp_get_buffer_raise(arg, &buf, MP_BUFFER_READ);
    if(buf.len != 64){
        mp_raise_ValueError("Pedersen commitment should be 64 bytes long");
        return mp_const_none;
    }
    secp256k1_pedersen_commitment gen;
    memcpy(gen.data, buf.buf, 64);
    vstr_t vstr;
    vstr_init_len(&vstr, 33);
    secp256k1_pedersen_commitment_serialize(ctx, (byte*)vstr.buf, &gen);
    return mp_obj_new_str_from_vstr(&mp_type_bytes, &vstr);
}

STATIC MP_DEFINE_CONST_FUN_OBJ_1(usecp256k1_pedersen_commitment_serialize_obj, usecp256k1_pedersen_commitment_serialize);


STATIC mp_obj_t usecp256k1_pedersen_commitment_parse(const mp_obj_t arg){
    maybe_init_ctx();
    mp_buffer_info_t buf;
    mp_get_buffer_raise(arg, &buf, MP_BUFFER_READ);
    if(buf.len != 33){
        mp_raise_ValueError("Serialized pedersen commitment should be 33 bytes long");
        return mp_const_none;
    }
    secp256k1_pedersen_commitment gen;
    int res = secp256k1_pedersen_commitment_parse(ctx, &gen, buf.buf);
    if(!res){
        mp_raise_ValueError("Failed to parse commitment");
        return mp_const_none;
    }
    vstr_t vstr;
    vstr_init_len(&vstr, 64);
    memcpy(vstr.buf, gen.data, 64);
    return mp_obj_new_str_from_vstr(&mp_type_bytes, &vstr);
}

STATIC MP_DEFINE_CONST_FUN_OBJ_1(usecp256k1_pedersen_commitment_parse_obj, usecp256k1_pedersen_commitment_parse);

uint64_t get_uint64(mp_obj_t arg){
    assert(mp_obj_is_type(arg, &mp_type_int));
    uint64_t value = 0;
    // int to big endian
    byte buf[8] = {0};
    #if MICROPY_LONGINT_IMPL != MICROPY_LONGINT_IMPL_NONE
    if (!mp_obj_is_small_int(arg)) {
        mp_obj_int_to_bytes_impl(arg, true, 8, buf);
    } else
    #endif
    {
        mp_int_t val = MP_OBJ_SMALL_INT_VALUE(arg);
        size_t l = MIN(8, sizeof(val));
        mp_binary_set_int(l, true, buf + 8 - l, val);
    }
    for (int i = 0; i < 8; ++i)
    {
        value = (value << 8);
        value += buf[i];
    }
    return value;
}

// vals, abfs, vbfs, psbtv.num_inputs
STATIC mp_obj_t usecp256k1_pedersen_blind_generator_blind_sum(mp_uint_t n_args, const mp_obj_t *args){
    maybe_init_ctx();
    mp_obj_list_t *vals = MP_OBJ_TO_PTR(args[0]);
    mp_obj_list_t *abfs = MP_OBJ_TO_PTR(args[1]);
    mp_obj_list_t *vbfs = MP_OBJ_TO_PTR(args[2]);
    size_t n_total = (size_t)vals->len;
    // TODO: check all lists have the same length
    size_t n_inputs = (size_t)get_uint64(args[3]);

    uint64_t * value = (uint64_t *)malloc(n_total*sizeof(uint64_t));
    const unsigned char **gens = (const unsigned char **)malloc(n_total*sizeof(unsigned char *));
    unsigned char **bfactors = (unsigned char **)malloc(n_total*sizeof(unsigned char *));
    mp_buffer_info_t buf;

    vstr_t vstr;
    vstr_init_len(&vstr, 32);

    // TODO: test length of buffers
    for(int i = 0; i < n_total; i++){
        value[i] = get_uint64(vals->items[i]);
        mp_get_buffer(abfs->items[i], &buf, MP_BUFFER_READ);
        gens[i] = buf.buf;
        mp_get_buffer(vbfs->items[i], &buf, MP_BUFFER_READ);
        if(i == n_total-1){
            memcpy(vstr.buf, buf.buf, 32);
            bfactors[i] = vstr.buf;
        }else{
            bfactors[i] = buf.buf;
        }
    }
    int res = secp256k1_pedersen_blind_generator_blind_sum(ctx, value, gens, bfactors, n_total, n_inputs);
    free(value);
    free(gens);
    free(bfactors);
    if(!res){
        mp_raise_ValueError("Failed to calculate sum");
    }
    return mp_obj_new_str_from_vstr(&mp_type_bytes, &vstr);
}

STATIC MP_DEFINE_CONST_FUN_OBJ_VAR(usecp256k1_pedersen_blind_generator_blind_sum_obj, 4, usecp256k1_pedersen_blind_generator_blind_sum);

// surjection proofs

// surjectionproof_initialize(in_assets, asset, seed, tags_to_use=None, iterations=100)
STATIC mp_obj_t usecp256k1_surjectionproof_initialize(mp_uint_t n_args, const mp_obj_t *args){
    maybe_init_ctx();
    mp_obj_list_t *in_assets = MP_OBJ_TO_PTR(args[0]);
    mp_buffer_info_t asset;
    mp_get_buffer_raise(args[1], &asset, MP_BUFFER_READ);
    mp_buffer_info_t seed;
    mp_get_buffer_raise(args[2], &seed, MP_BUFFER_READ);
    if(asset.len != sizeof(secp256k1_fixed_asset_tag) || seed.len != 32){
        mp_raise_ValueError("Invalid argument length");
    }

    size_t iterations = 100;
    size_t n_inputs = in_assets->len;
    // min(3, len(in_assets))
    size_t n_tags_to_use = 3;
    if(n_inputs < n_tags_to_use){
        n_tags_to_use = n_inputs;
    }

    vstr_t proof;
    vstr_init_len(&proof, sizeof(secp256k1_surjectionproof));
    size_t input_index = 0;

    mp_buffer_info_t buf;
    for(int i=0; i<n_inputs; i++){
        mp_get_buffer_raise(in_assets->items[i], &buf, MP_BUFFER_READ);
        if(buf.len != 32){
            mp_raise_ValueError("Invalid argument length");
        }
    }
    secp256k1_fixed_asset_tag * in_assets_buf = (secp256k1_fixed_asset_tag *)malloc(sizeof(secp256k1_fixed_asset_tag)*n_inputs);
    for(int i=0; i<n_inputs; i++){
        mp_get_buffer(in_assets->items[i], &buf, MP_BUFFER_READ);
        memcpy(in_assets_buf+(i*sizeof(secp256k1_fixed_asset_tag)), buf.buf, sizeof(secp256k1_fixed_asset_tag));
    }
    int res = secp256k1_surjectionproof_initialize(ctx, (secp256k1_surjectionproof*)proof.buf, &input_index, in_assets_buf, n_inputs, n_tags_to_use, (secp256k1_fixed_asset_tag *)asset.buf, iterations, seed.buf);
    free(in_assets_buf);
    if(!res){
        mp_raise_ValueError("Failed to initialize surj proof");
    }
    mp_obj_t items[2];
    items[0] = mp_obj_new_str_from_vstr(&mp_type_bytes, &proof);
    items[1] = mp_obj_new_int_from_ull(input_index);
    return mp_obj_new_tuple(2, items);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_VAR(usecp256k1_surjectionproof_initialize_obj, 3, usecp256k1_surjectionproof_initialize);

// surjectionproof_initialize_preallocated(proofptr, prooflen, in_assets, asset, seed, tags_to_use=None, iterations=100)
// proofptr is a pointer to preallocated memory and prooflen is the length of availble memory
// returns a tuple: (used prooflen, in_index)
STATIC mp_obj_t usecp256k1_surjectionproof_initialize_preallocated(mp_uint_t n_args, const mp_obj_t *args){
    maybe_init_ctx();
    intptr_t proofptr = get_uint64(args[0]);
    size_t prooflen = get_uint64(args[1]);
    if(prooflen < sizeof(secp256k1_surjectionproof)){
        mp_raise_ValueError("Not enough memory preallocated");
    }
    mp_obj_list_t *in_assets = MP_OBJ_TO_PTR(args[2]);
    mp_buffer_info_t asset;
    mp_get_buffer_raise(args[3], &asset, MP_BUFFER_READ);
    mp_buffer_info_t seed;
    mp_get_buffer_raise(args[4], &seed, MP_BUFFER_READ);
    if(asset.len != sizeof(secp256k1_fixed_asset_tag) || seed.len != 32){
        mp_raise_ValueError("Invalid argument length");
    }

    size_t iterations = 100;
    size_t n_inputs = in_assets->len;
    // min(3, len(in_assets))
    size_t n_tags_to_use = 3;
    if(n_inputs < n_tags_to_use){
        n_tags_to_use = n_inputs;
    }

    size_t input_index = 0;

    mp_buffer_info_t buf;
    for(int i=0; i<n_inputs; i++){
        mp_get_buffer_raise(in_assets->items[i], &buf, MP_BUFFER_READ);
        if(buf.len != 32){
            mp_raise_ValueError("Invalid argument length");
        }
    }
    secp256k1_fixed_asset_tag * in_assets_buf = (secp256k1_fixed_asset_tag *)malloc(sizeof(secp256k1_fixed_asset_tag)*n_inputs);
    for(int i=0; i<n_inputs; i++){
        mp_get_buffer(in_assets->items[i], &buf, MP_BUFFER_READ);
        memcpy(in_assets_buf+(i*sizeof(secp256k1_fixed_asset_tag)), buf.buf, sizeof(secp256k1_fixed_asset_tag));
    }
    int res = secp256k1_surjectionproof_initialize(ctx, (secp256k1_surjectionproof*)proofptr, &input_index, in_assets_buf, n_inputs, n_tags_to_use, (secp256k1_fixed_asset_tag *)asset.buf, iterations, seed.buf);
    free(in_assets_buf);
    if(!res){
        mp_raise_ValueError("Failed to initialize surj proof");
    }
    mp_obj_t items[2];
    items[0] = mp_obj_new_int_from_ull(sizeof(secp256k1_surjectionproof));
    items[1] = mp_obj_new_int_from_ull(input_index);
    return mp_obj_new_tuple(2, items);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_VAR(usecp256k1_surjectionproof_initialize_preallocated_obj, 3, usecp256k1_surjectionproof_initialize_preallocated);

// surjectionproof_generate(proof, in_idx, in_tags, out_tag, in_abf, out_abf)
STATIC mp_obj_t usecp256k1_surjectionproof_generate(mp_uint_t n_args, const mp_obj_t *args){
    maybe_init_ctx();
    mp_buffer_info_t proof;
    secp256k1_surjectionproof * ptr = NULL;
    if(mp_get_buffer(args[0], &proof, MP_BUFFER_READ)){
        ptr = (secp256k1_surjectionproof *)proof.buf;
    }else{
        ptr = (secp256k1_surjectionproof *)get_uint64(args[0]);
    }
    size_t in_idx = (size_t)get_uint64(args[1]);
    mp_obj_list_t *in_assets = MP_OBJ_TO_PTR(args[2]);
    mp_buffer_info_t asset;
    mp_get_buffer_raise(args[3], &asset, MP_BUFFER_READ);
    mp_buffer_info_t in_abf;
    mp_get_buffer_raise(args[4], &in_abf, MP_BUFFER_READ);
    mp_buffer_info_t out_abf;
    mp_get_buffer_raise(args[5], &out_abf, MP_BUFFER_READ);
    if(out_abf.len != 32 || asset.len != sizeof(secp256k1_generator) || in_abf.len != 32){
        mp_raise_ValueError("Invalid argument length");
    }

    size_t n_inputs = in_assets->len;

    mp_buffer_info_t buf;
    for(int i=0; i<n_inputs; i++){
        mp_get_buffer_raise(in_assets->items[i], &buf, MP_BUFFER_READ);
        if(buf.len != sizeof(secp256k1_generator)){
            mp_raise_ValueError("Invalid gen argument length");
        }
    }
    secp256k1_generator * in_assets_buf = (secp256k1_generator *)malloc(sizeof(secp256k1_generator)*n_inputs);
    for(int i=0; i<n_inputs; i++){
        mp_get_buffer(in_assets->items[i], &buf, MP_BUFFER_READ);
        memcpy(in_assets_buf+(i*sizeof(secp256k1_generator)), buf.buf, sizeof(secp256k1_generator));
    }
    int res = secp256k1_surjectionproof_generate(ctx, ptr, in_assets_buf, n_inputs, (secp256k1_generator *)asset.buf, in_idx, in_abf.buf, out_abf.buf);
    free(in_assets_buf);
    if(!res){
        mp_raise_ValueError("Failed to generate surj proof");
    }
    return args[0];
}
STATIC MP_DEFINE_CONST_FUN_OBJ_VAR(usecp256k1_surjectionproof_generate_obj, 6, usecp256k1_surjectionproof_generate);

// surjectionproof_serialize(proof) - proof is either a buffer or a pointer
STATIC mp_obj_t usecp256k1_surjectionproof_serialize(const mp_obj_t arg){
    maybe_init_ctx();
    mp_buffer_info_t proof;
    secp256k1_surjectionproof * ptr;
    if(mp_get_buffer(arg, &proof, MP_BUFFER_READ)){
        ptr = (secp256k1_surjectionproof *)proof.buf;
    }else{
        ptr = (secp256k1_surjectionproof *)get_uint64(arg);
    }

    size_t l = secp256k1_surjectionproof_serialized_size(ctx, ptr);
    vstr_t vstr;
    vstr_init_len(&vstr, l);
    size_t l0 = l;

    int res = secp256k1_surjectionproof_serialize(ctx, vstr.buf, &l, ptr);
    if(!res){
        mp_raise_ValueError("Failed to serialize surj proof");
    }
    if(l < l0){
        vstr_cut_tail_bytes(&vstr, l0-l);
    }
    return mp_obj_new_str_from_vstr(&mp_type_bytes, &vstr);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_1(usecp256k1_surjectionproof_serialize_obj, usecp256k1_surjectionproof_serialize);

// rangeproof_sign(nonce, value, value_commitment, vbf, message, extra, gen, min_value=1, exp=0, min_bits=52)
STATIC mp_obj_t usecp256k1_rangeproof_sign(mp_uint_t n_args, const mp_obj_t *args){
    maybe_init_ctx();
    if(n_args < 7){
        mp_raise_ValueError("Function requires at least 7 arguments");
        return mp_const_none;
    }
    mp_buffer_info_t nonce;
    mp_get_buffer_raise(args[0], &nonce, MP_BUFFER_READ);
    if(nonce.len != 32){
        mp_raise_ValueError("Nonce should be 32 bytes long");
        return mp_const_none;
    }

    uint64_t value = get_uint64(args[1]);

    mp_buffer_info_t commitbuf;
    mp_get_buffer_raise(args[2], &commitbuf, MP_BUFFER_READ);
    if(commitbuf.len != 64){
        mp_raise_ValueError("Commitment should be 64 bytes long");
        return mp_const_none;
    }
    secp256k1_pedersen_commitment commit;
    memcpy(commit.data, commitbuf.buf, 64);

    mp_buffer_info_t vbf;
    mp_get_buffer_raise(args[3], &vbf, MP_BUFFER_READ);
    if(vbf.len != 32){
        mp_raise_ValueError("Value blinding factor should be 32 bytes long");
        return mp_const_none;
    }

    mp_buffer_info_t msg;
    mp_get_buffer_raise(args[4], &msg, MP_BUFFER_READ);

    mp_buffer_info_t extra;
    mp_get_buffer_raise(args[5], &extra, MP_BUFFER_READ);

    mp_buffer_info_t genbuf;
    mp_get_buffer_raise(args[6], &genbuf, MP_BUFFER_READ);
    if(genbuf.len != 64){
        mp_raise_ValueError("Commitment should be 64 bytes long");
        return mp_const_none;
    }
    secp256k1_generator gen;
    memcpy(gen.data, genbuf.buf, 64);

    uint64_t min_value = 1;
    if(n_args > 7){
        min_value = get_uint64(args[7]);
    }
    int exp = 0;
    if(n_args > 8){
        exp = MP_OBJ_SMALL_INT_VALUE(args[8]);
    }
    int min_bits = 52;
    if(n_args > 9){
        min_value = MP_OBJ_SMALL_INT_VALUE(args[9]);
    }

    vstr_t vstr;
    size_t prooflen = 5200;
    vstr_init_len(&vstr, 5200);
    int res = secp256k1_rangeproof_sign(ctx, vstr.buf, &prooflen,
                min_value, &commit, vbf.buf, nonce.buf,
                exp, min_bits, value, msg.buf, msg.len, extra.buf, extra.len, &gen);
    if(!res){
        mp_raise_ValueError("Failed to create a proof");
        return mp_const_none;
    }
    vstr_cut_tail_bytes(&vstr, 5200-prooflen);
    return mp_obj_new_str_from_vstr(&mp_type_bytes, &vstr);
}

STATIC MP_DEFINE_CONST_FUN_OBJ_VAR(usecp256k1_rangeproof_sign_obj, 7, usecp256k1_rangeproof_sign);

// rangeproof_sign_to(stream, mem_ptr, mem_len,
//                    nonce, value, value_commitment, vbf, message, extra, gen, min_value=1, exp=0, min_bits=52)
STATIC mp_obj_t usecp256k1_rangeproof_sign_to(mp_uint_t n_args, const mp_obj_t *args){
    maybe_init_ctx();
    if(n_args < 10){
        mp_raise_ValueError("Function requires at least 10 arguments");
        return mp_const_none;
    }
    mp_obj_t stream = args[0];
    mp_get_stream_raise(stream, MP_STREAM_OP_WRITE);

    // preallocated memory
    intptr_t memptr = (intptr_t)get_uint64(args[1]);
    intptr_t memlen = (intptr_t)get_uint64(args[2]);

    size_t prooflen = 5200;

    if(memlen < prooflen){
        mp_raise_ValueError("Not enough memory for proof allocation.");
    }

    mp_buffer_info_t nonce;
    mp_get_buffer_raise(args[3], &nonce, MP_BUFFER_READ);
    if(nonce.len != 32){
        mp_raise_ValueError("Nonce should be 32 bytes long");
        return mp_const_none;
    }

    uint64_t value = get_uint64(args[4]);

    mp_buffer_info_t commitbuf;
    mp_get_buffer_raise(args[5], &commitbuf, MP_BUFFER_READ);
    if(commitbuf.len != 64){
        mp_raise_ValueError("Commitment should be 64 bytes long");
        return mp_const_none;
    }
    secp256k1_pedersen_commitment commit;
    memcpy(commit.data, commitbuf.buf, 64);

    mp_buffer_info_t vbf;
    mp_get_buffer_raise(args[6], &vbf, MP_BUFFER_READ);
    if(vbf.len != 32){
        mp_raise_ValueError("Value blinding factor should be 32 bytes long");
        return mp_const_none;
    }

    mp_buffer_info_t msg;
    mp_get_buffer_raise(args[7], &msg, MP_BUFFER_READ);

    mp_buffer_info_t extra;
    mp_get_buffer_raise(args[8], &extra, MP_BUFFER_READ);

    mp_buffer_info_t genbuf;
    mp_get_buffer_raise(args[9], &genbuf, MP_BUFFER_READ);
    if(genbuf.len != 64){
        mp_raise_ValueError("Commitment should be 64 bytes long");
        return mp_const_none;
    }
    secp256k1_generator gen;
    memcpy(gen.data, genbuf.buf, 64);

    uint64_t min_value = 1;
    if(n_args > 10){
        min_value = get_uint64(args[10]);
    }
    int exp = 0;
    if(n_args > 11){
        exp = MP_OBJ_SMALL_INT_VALUE(args[11]);
    }
    int min_bits = 52;
    if(n_args > 12){
        min_value = MP_OBJ_SMALL_INT_VALUE(args[12]);
    }

    int res = secp256k1_rangeproof_sign_preallocated(ctx, (void*)memptr, &prooflen,
                min_value, &commit, vbf.buf, nonce.buf,
                exp, min_bits, value, msg.buf, msg.len, extra.buf, extra.len, &gen,
                (void *)(memptr+prooflen), (memlen-prooflen));
    if(!res){
        mp_raise_ValueError("Failed to create a proof");
        return mp_const_none;
    }

    // write in chunks of 64 bytes
    size_t l = 0;
    while(l+64 < prooflen){
        mp_stream_write(stream, (void *)(memptr + l), 64, MP_STREAM_RW_WRITE);
        l += 64;
    }
    mp_stream_write(stream, (void *)(memptr + l), (prooflen - l), MP_STREAM_RW_WRITE);
    return mp_obj_new_int_from_ull(prooflen);
}

STATIC MP_DEFINE_CONST_FUN_OBJ_VAR(usecp256k1_rangeproof_sign_to_obj, 10, usecp256k1_rangeproof_sign_to);


// rangeproof_rewind(proof, nonce, value_commitment, script_pubkey, generator)
STATIC mp_obj_t usecp256k1_rangeproof_rewind(mp_uint_t n_args, const mp_obj_t *args){
    maybe_init_ctx();
    if(n_args < 5){
        mp_raise_ValueError("Function requires 5 arguments");
        return mp_const_none;
    }
    mp_buffer_info_t proof;
    mp_get_buffer_raise(args[0], &proof, MP_BUFFER_READ);

    mp_buffer_info_t nonce;
    mp_get_buffer_raise(args[1], &nonce, MP_BUFFER_READ);
    if(nonce.len != 32){
        mp_raise_ValueError("Nonce should be 32 bytes long");
        return mp_const_none;
    }

    mp_buffer_info_t value_commitment;
    mp_get_buffer_raise(args[2], &value_commitment, MP_BUFFER_READ);
    if(value_commitment.len != 64){
        mp_raise_ValueError("Value commitment should be 64 bytes long");
        return mp_const_none;
    }

    mp_buffer_info_t script_pubkey;
    mp_get_buffer_raise(args[3], &script_pubkey, MP_BUFFER_READ);

    mp_buffer_info_t generator;
    mp_get_buffer_raise(args[4], &generator, MP_BUFFER_READ);
    if(generator.len != 64){
        mp_raise_ValueError("Generator should be 64 bytes long");
        return mp_const_none;
    }

    vstr_t vbf_out;
    vstr_init_len(&vbf_out, 32);

    size_t msglen = 64;
    if(n_args > 5){
        msglen = get_uint64(args[5]);
    }
    size_t msglenout = msglen;
    vstr_t msg;
    vstr_init_len(&msg, msglen);

    uint64_t value_out;
    uint64_t min_value;
    uint64_t max_value;

    int res = secp256k1_rangeproof_rewind(ctx, vbf_out.buf, &value_out,
                            msg.buf, &msglenout,
                            nonce.buf, &min_value, &max_value,
                            value_commitment.buf, proof.buf, proof.len,
                            script_pubkey.buf, script_pubkey.len,
                            generator.buf);

    if(!res){
        mp_raise_ValueError("Failed to rewind the proof");
        return mp_const_none;
    }

    // value_out, vbf_out, msg, min_value, max_value
    mp_obj_t items[5];
    items[0] = mp_obj_new_int_from_ull(value_out);
    items[1] = mp_obj_new_str_from_vstr(&mp_type_bytes, &vbf_out);
    if(msglen == msglenout){
        items[2] = mp_obj_new_str_from_vstr(&mp_type_bytes, &msg);
    }else{
        vstr_t msgout;
        vstr_init_len(&msgout, msglenout);
        memcpy(msgout.buf, msg.buf, msglenout);
        items[2] = mp_obj_new_str_from_vstr(&mp_type_bytes, &msgout);
    }
    items[3] = mp_obj_new_int_from_ull(min_value);
    items[4] = mp_obj_new_int_from_ull(max_value);
    return mp_obj_new_tuple(5, items);
}

STATIC MP_DEFINE_CONST_FUN_OBJ_VAR(usecp256k1_rangeproof_rewind_obj, 5, usecp256k1_rangeproof_rewind);

// rangeproof_rewind_from(stream, len, memptr, memlen, nonce, value_commitment, script_pubkey, generator)
STATIC mp_obj_t usecp256k1_rangeproof_rewind_from(mp_uint_t n_args, const mp_obj_t *args){
    maybe_init_ctx();
    if(n_args < 8){
        mp_raise_ValueError("Function requires 8 arguments");
        return mp_const_none;
    }
    // stream to read
    mp_obj_t stream = args[0];
    mp_get_stream_raise(stream, MP_STREAM_OP_READ);
    size_t prooflen = (size_t)get_uint64(args[1]);

    // preallocated memory
    intptr_t memptr = (intptr_t)get_uint64(args[2]);
    intptr_t memlen = (intptr_t)get_uint64(args[3]);
    // 32bit alignment
    intptr_t memoff = (prooflen / 4 + 1)*4;

    size_t l = 0;
    if(memlen < memoff){
        mp_raise_ValueError("Not enough memory for proof.");
    }
    int err = 0;
    while(l < (prooflen - 64)){
        mp_stream_read_exactly(stream, (byte*)(memptr+l), 64, &err);
        if(err){
            mp_raise_ValueError("Failed to read from stream");
        }
        l += 64;
    }
    mp_stream_read_exactly(stream, (byte*)(memptr+l), (prooflen-l), &err);
    if(err){
        mp_raise_ValueError("Failed to read from stream");
    }

    // mp_buffer_info_t proof;
    // mp_get_buffer_raise(args[0], &proof, MP_BUFFER_READ);

    mp_buffer_info_t nonce;
    mp_get_buffer_raise(args[4], &nonce, MP_BUFFER_READ);
    if(nonce.len != 32){
        mp_raise_ValueError("Nonce should be 32 bytes long");
        return mp_const_none;
    }

    mp_buffer_info_t value_commitment;
    mp_get_buffer_raise(args[5], &value_commitment, MP_BUFFER_READ);
    if(value_commitment.len != 64){
        mp_raise_ValueError("Value commitment should be 64 bytes long");
        return mp_const_none;
    }

    mp_buffer_info_t script_pubkey;
    mp_get_buffer_raise(args[6], &script_pubkey, MP_BUFFER_READ);

    mp_buffer_info_t generator;
    mp_get_buffer_raise(args[7], &generator, MP_BUFFER_READ);
    if(generator.len != 64){
        mp_raise_ValueError("Generator should be 64 bytes long");
        return mp_const_none;
    }

    vstr_t vbf_out;
    vstr_init_len(&vbf_out, 32);

    size_t msglen = 64;
    if(n_args > 8){
        msglen = get_uint64(args[8]);
    }
    size_t msglenout = msglen;
    vstr_t msg;
    vstr_init_len(&msg, msglen);

    uint64_t value_out;
    uint64_t min_value;
    uint64_t max_value;

    int res = secp256k1_rangeproof_rewind_preallocated(ctx, vbf_out.buf, &value_out,
                            msg.buf, &msglenout,
                            nonce.buf, &min_value, &max_value,
                            value_commitment.buf, (void*)memptr, prooflen,
                            script_pubkey.buf, script_pubkey.len,
                            generator.buf, (void *)(memptr+memoff), (memlen-memoff));

    if(!res){
        mp_raise_ValueError("Failed to rewind the proof");
        return mp_const_none;
    }

    // value_out, vbf_out, msg, min_value, max_value
    mp_obj_t items[5];
    items[0] = mp_obj_new_int_from_ull(value_out);
    items[1] = mp_obj_new_str_from_vstr(&mp_type_bytes, &vbf_out);
    if(msglen == msglenout){
        items[2] = mp_obj_new_str_from_vstr(&mp_type_bytes, &msg);
    }else{
        vstr_t msgout;
        vstr_init_len(&msgout, msglenout);
        memcpy(msgout.buf, msg.buf, msglenout);
        items[2] = mp_obj_new_str_from_vstr(&mp_type_bytes, &msgout);
    }
    items[3] = mp_obj_new_int_from_ull(min_value);
    items[4] = mp_obj_new_int_from_ull(max_value);
    return mp_obj_new_tuple(5, items);
}

STATIC MP_DEFINE_CONST_FUN_OBJ_VAR(usecp256k1_rangeproof_rewind_from_obj, 8, usecp256k1_rangeproof_rewind_from);


/****************************** MODULE ******************************/

STATIC const mp_rom_map_elem_t secp256k1_module_globals_table[] = {
    { MP_ROM_QSTR(MP_QSTR___name__), MP_ROM_QSTR(MP_QSTR_secp256k1) },
    { MP_ROM_QSTR(MP_QSTR_context_randomize), MP_ROM_PTR(&usecp256k1_context_randomize_obj) },
    { MP_ROM_QSTR(MP_QSTR_context_preallocated_size), MP_ROM_PTR(&usecp256k1_context_preallocated_size_obj) },
    { MP_ROM_QSTR(MP_QSTR_ec_pubkey_create), MP_ROM_PTR(&usecp256k1_ec_pubkey_create_obj) },
    { MP_ROM_QSTR(MP_QSTR_ec_pubkey_parse), MP_ROM_PTR(&usecp256k1_ec_pubkey_parse_obj) },
    { MP_ROM_QSTR(MP_QSTR_ec_pubkey_serialize), MP_ROM_PTR(&usecp256k1_ec_pubkey_serialize_obj) },
    { MP_ROM_QSTR(MP_QSTR_ecdsa_signature_parse_compact), MP_ROM_PTR(&usecp256k1_ecdsa_signature_parse_compact_obj) },
    { MP_ROM_QSTR(MP_QSTR_ecdsa_signature_parse_der), MP_ROM_PTR(&usecp256k1_ecdsa_signature_parse_der_obj) },
    { MP_ROM_QSTR(MP_QSTR_ecdsa_signature_serialize_der), MP_ROM_PTR(&usecp256k1_ecdsa_signature_serialize_der_obj) },
    { MP_ROM_QSTR(MP_QSTR_ecdsa_signature_serialize_compact), MP_ROM_PTR(&usecp256k1_ecdsa_signature_serialize_compact_obj) },
    { MP_ROM_QSTR(MP_QSTR_ecdsa_signature_normalize), MP_ROM_PTR(&usecp256k1_ecdsa_signature_normalize_obj) },
    { MP_ROM_QSTR(MP_QSTR_ecdsa_verify), MP_ROM_PTR(&usecp256k1_ecdsa_verify_obj) },
    { MP_ROM_QSTR(MP_QSTR_ecdsa_sign), MP_ROM_PTR(&usecp256k1_ecdsa_sign_obj) },
    // schnorrsig
    { MP_ROM_QSTR(MP_QSTR_xonly_pubkey_from_pubkey), MP_ROM_PTR(&usecp256k1_xonly_pubkey_from_pubkey_obj) },
    { MP_ROM_QSTR(MP_QSTR_schnorrsig_verify), MP_ROM_PTR(&usecp256k1_schnorrsig_verify_obj) },
    { MP_ROM_QSTR(MP_QSTR_keypair_create), MP_ROM_PTR(&usecp256k1_keypair_create_obj) },
    { MP_ROM_QSTR(MP_QSTR_schnorrsig_sign), MP_ROM_PTR(&usecp256k1_schnorrsig_sign_obj) },

    { MP_ROM_QSTR(MP_QSTR_ecdsa_sign_recoverable), MP_ROM_PTR(&usecp256k1_ecdsa_sign_recoverable_obj) },

    { MP_ROM_QSTR(MP_QSTR_nonce_function_default), MP_ROM_PTR(&usecp256k1_nonce_function_default_obj) },
    { MP_ROM_QSTR(MP_QSTR_nonce_function_rfc6979), MP_ROM_PTR(&usecp256k1_nonce_function_default_obj) },

    { MP_ROM_QSTR(MP_QSTR_ec_seckey_verify), MP_ROM_PTR(&usecp256k1_ec_seckey_verify_obj) },
    { MP_ROM_QSTR(MP_QSTR_ec_privkey_negate), MP_ROM_PTR(&usecp256k1_ec_privkey_negate_obj) },
    { MP_ROM_QSTR(MP_QSTR_ec_pubkey_negate), MP_ROM_PTR(&usecp256k1_ec_pubkey_negate_obj) },
    { MP_ROM_QSTR(MP_QSTR_ec_privkey_tweak_add), MP_ROM_PTR(&usecp256k1_ec_privkey_tweak_add_obj) },
    { MP_ROM_QSTR(MP_QSTR_ec_privkey_add), MP_ROM_PTR(&usecp256k1_ec_privkey_add_obj) },
    { MP_ROM_QSTR(MP_QSTR_ec_pubkey_tweak_add), MP_ROM_PTR(&usecp256k1_ec_pubkey_tweak_add_obj) },
    { MP_ROM_QSTR(MP_QSTR_ec_pubkey_add), MP_ROM_PTR(&usecp256k1_ec_pubkey_add_obj) },
    { MP_ROM_QSTR(MP_QSTR_ec_privkey_tweak_mul), MP_ROM_PTR(&usecp256k1_ec_privkey_tweak_mul_obj) },
    { MP_ROM_QSTR(MP_QSTR_ec_pubkey_tweak_mul), MP_ROM_PTR(&usecp256k1_ec_pubkey_tweak_mul_obj) },
    { MP_ROM_QSTR(MP_QSTR_ec_pubkey_combine), MP_ROM_PTR(&usecp256k1_ec_pubkey_combine_obj) },
    { MP_ROM_QSTR(MP_QSTR_EC_COMPRESSED), MP_ROM_INT(SECP256K1_EC_COMPRESSED) },
    { MP_ROM_QSTR(MP_QSTR_EC_UNCOMPRESSED), MP_ROM_INT(SECP256K1_EC_UNCOMPRESSED) },

    { MP_ROM_QSTR(MP_QSTR_generator_generate_blinded), MP_ROM_PTR(&usecp256k1_generator_generate_blinded_obj) },
    { MP_ROM_QSTR(MP_QSTR_generator_serialize), MP_ROM_PTR(&usecp256k1_generator_serialize_obj) },
    { MP_ROM_QSTR(MP_QSTR_generator_parse), MP_ROM_PTR(&usecp256k1_generator_parse_obj) },
    { MP_ROM_QSTR(MP_QSTR_pedersen_commit), MP_ROM_PTR(&usecp256k1_pedersen_commit_obj) },
    { MP_ROM_QSTR(MP_QSTR_pedersen_commitment_serialize), MP_ROM_PTR(&usecp256k1_pedersen_commitment_serialize_obj) },
    { MP_ROM_QSTR(MP_QSTR_pedersen_commitment_parse), MP_ROM_PTR(&usecp256k1_pedersen_commitment_parse_obj) },
    { MP_ROM_QSTR(MP_QSTR_pedersen_blind_generator_blind_sum), MP_ROM_PTR(&usecp256k1_pedersen_blind_generator_blind_sum_obj) },

    { MP_ROM_QSTR(MP_QSTR_rangeproof_sign), MP_ROM_PTR(&usecp256k1_rangeproof_sign_obj) },
    { MP_ROM_QSTR(MP_QSTR_rangeproof_rewind), MP_ROM_PTR(&usecp256k1_rangeproof_rewind_obj) },

    { MP_ROM_QSTR(MP_QSTR_rangeproof_sign_to), MP_ROM_PTR(&usecp256k1_rangeproof_sign_to_obj) },
    { MP_ROM_QSTR(MP_QSTR_rangeproof_rewind_from), MP_ROM_PTR(&usecp256k1_rangeproof_rewind_from_obj) },

    { MP_ROM_QSTR(MP_QSTR_surjectionproof_initialize), MP_ROM_PTR(&usecp256k1_surjectionproof_initialize_obj) },
    { MP_ROM_QSTR(MP_QSTR_surjectionproof_initialize_preallocated), MP_ROM_PTR(&usecp256k1_surjectionproof_initialize_preallocated_obj) },
    { MP_ROM_QSTR(MP_QSTR_surjectionproof_generate), MP_ROM_PTR(&usecp256k1_surjectionproof_generate_obj) },
    { MP_ROM_QSTR(MP_QSTR_surjectionproof_serialize), MP_ROM_PTR(&usecp256k1_surjectionproof_serialize_obj) },

};
STATIC MP_DEFINE_CONST_DICT(secp256k1_module_globals, secp256k1_module_globals_table);

// Define module object.
const mp_obj_module_t secp256k1_user_cmodule = {
    .base = { &mp_type_module },
    .globals = (mp_obj_dict_t*)&secp256k1_module_globals,
};

// Register the module to make it available in Python
MP_REGISTER_MODULE(MP_QSTR_secp256k1, secp256k1_user_cmodule, MODULE_SECP256K1_ENABLED);
