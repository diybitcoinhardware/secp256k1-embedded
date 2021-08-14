#ifndef _SECP256K1_RANGEPROOF_PREALLOCATED_H_
#define _SECP256K1_RANGEPROOF_PREALLOCATED_H_

int secp256k1_rangeproof_sign_preallocated(const secp256k1_context* ctx, unsigned char *proof, size_t *plen, uint64_t min_value,
 const secp256k1_pedersen_commitment *commit, const unsigned char *blind, const unsigned char *nonce, int exp, int min_bits, uint64_t value,
 const unsigned char *message, size_t msg_len, const unsigned char *extra_commit, size_t extra_commit_len, const secp256k1_generator* gen,
 void * preallocated_ptr, uint64_t allocated_len);

int secp256k1_rangeproof_rewind_preallocated(const secp256k1_context* ctx,
 unsigned char *blind_out, uint64_t *value_out, unsigned char *message_out, size_t *outlen, const unsigned char *nonce,
 uint64_t *min_value, uint64_t *max_value,
 const secp256k1_pedersen_commitment *commit, const unsigned char *proof, size_t plen, const unsigned char *extra_commit, size_t extra_commit_len, const secp256k1_generator* gen,
 void * preallocated_ptr, uint64_t allocated_len);

#endif