#ifndef _SECP256K1_RANGEPROOF_PREALLOCATED_IMPL_H_
#define _SECP256K1_RANGEPROOF_PREALLOCATED_IMPL_H_

SECP256K1_INLINE static int secp256k1_rangeproof_sign_preallocated_impl(
 const secp256k1_ecmult_context* ecmult_ctx,
 const secp256k1_ecmult_gen_context* ecmult_gen_ctx,
 unsigned char *proof, size_t *plen, uint64_t min_value,
 const secp256k1_ge *commit, const unsigned char *blind, const unsigned char *nonce, int exp, int min_bits, uint64_t value,
 const unsigned char *message, size_t msg_len, const unsigned char *extra_commit, size_t extra_commit_len, const secp256k1_ge* genp,
 void * preallocated_ptr, intptr_t allocated_len){
    intptr_t ptr = (intptr_t)preallocated_ptr;

    secp256k1_gej* pubs = (secp256k1_gej*)ptr; // [128];     /* Candidate digits for our proof, most inferred. */
    ptr += 128*sizeof(secp256k1_gej);
    secp256k1_scalar* s = (secp256k1_scalar*)ptr; // [128];     /* Signatures in our proof, most forged. */
    ptr += 128*sizeof(secp256k1_scalar);
    secp256k1_scalar* sec = (secp256k1_scalar*)ptr; // [32];    /* Blinding factors for the correct digits. */
    ptr += 32*sizeof(secp256k1_scalar);
    secp256k1_scalar* k = (secp256k1_scalar*)ptr; // [32];      /* Nonces for our non-forged signatures. */
    ptr += 32*sizeof(secp256k1_scalar);
    secp256k1_scalar stmp;
    secp256k1_sha256 sha256_m;

    unsigned char* prep = (unsigned char*)ptr; // [4096];
    ptr += 4096;
    unsigned char* tmp = (unsigned char*)ptr; // [33];
    ptr += 36; // alignment
    unsigned char *signs;          /* Location of sign flags in the proof. */
    uint64_t v;
    uint64_t scale;                /* scale = 10^exp. */
    int mantissa;                  /* Number of bits proven in the blinded value. */
    size_t rings;                     /* How many digits will our proof cover. */
    size_t* rsizes = (size_t *)ptr; // [32];                /* How many possible values there are for each place. */
    ptr += 32*sizeof(size_t);
    size_t* secidx = (size_t *) ptr; // [32];                /* Which digit is the correct one. */
    ptr += 32*sizeof(size_t);
    size_t len;                       /* Number of bytes used so far. */
    size_t i;
    int overflow;
    size_t npub;
    len = 0;

    intptr_t required_preallocated = ptr-(intptr_t)preallocated_ptr;
    if(required_preallocated > allocated_len){
        return 0;
    }

    if (*plen < 65 || min_value > value || min_bits > 64 || min_bits < 0 || exp < -1 || exp > 18) {
        return 0;
    }
    if (!secp256k1_range_proveparams(&v, &rings, rsizes, &npub, secidx, &min_value, &mantissa, &scale, &exp, &min_bits, value)) {
        return 0;
    }
    proof[len] = (rsizes[0] > 1 ? (64 | exp) : 0) | (min_value ? 32 : 0);
    len++;
    if (rsizes[0] > 1) {
        VERIFY_CHECK(mantissa > 0 && mantissa <= 64);
        proof[len] = mantissa - 1;
        len++;
    }
    if (min_value) {
        for (i = 0; i < 8; i++) {
            proof[len + i] = (min_value >> ((7-i) * 8)) & 255;
        }
        len += 8;
    }
    /* Do we have enough room in the proof for the message? Each ring gives us 128 bytes, but the
     * final ring is used to encode the blinding factor and the value, so we can't use that. (Well,
     * technically there are 64 bytes available if we avoided the other data, but this is difficult
     * because it's not always in the same place. */
    if (msg_len > 0 && msg_len > 128 * (rings - 1)) {
        return 0;
    }
    /* Do we have enough room for the proof? */
    if (*plen - len < 32 * (npub + rings - 1) + 32 + ((rings+6) >> 3)) {
        return 0;
    }
    secp256k1_sha256_initialize(&sha256_m);
    secp256k1_rangeproof_serialize_point(tmp, commit);
    secp256k1_sha256_write(&sha256_m, tmp, 33);
    secp256k1_rangeproof_serialize_point(tmp, genp);
    secp256k1_sha256_write(&sha256_m, tmp, 33);
    secp256k1_sha256_write(&sha256_m, proof, len);

    memset(prep, 0, 4096);
    if (message != NULL) {
        memcpy(prep, message, msg_len);
    }
    /* Note, the data corresponding to the blinding factors must be zero. */
    if (rsizes[rings - 1] > 1) {
        size_t idx;
        /* Value encoding sidechannel. */
        idx = rsizes[rings - 1] - 1;
        idx -= secidx[rings - 1] == idx;
        idx = ((rings - 1) * 4 + idx) * 32;
        for (i = 0; i < 8; i++) {
            prep[8 + i + idx] = prep[16 + i + idx] = prep[24 + i + idx] = (v >> (56 - i * 8)) & 255;
            prep[i + idx] = 0;
        }
        prep[idx] = 128;
    }
    if (!secp256k1_rangeproof_genrand(sec, s, prep, rsizes, rings, nonce, commit, proof, len, genp)) {
        return 0;
    }
    memset(prep, 0, 4096);
    for (i = 0; i < rings; i++) {
        /* Sign will overwrite the non-forged signature, move that random value into the nonce. */
        k[i] = s[i * 4 + secidx[i]];
        secp256k1_scalar_clear(&s[i * 4 + secidx[i]]);
    }
    /** Genrand returns the last blinding factor as -sum(rest),
     *   adding in the blinding factor for our commitment, results in the blinding factor for
     *   the commitment to the last digit that the verifier can compute for itself by subtracting
     *   all the digits in the proof from the commitment. This lets the prover skip sending the
     *   blinded value for one digit.
     */
    secp256k1_scalar_set_b32(&stmp, blind, &overflow);
    secp256k1_scalar_add(&sec[rings - 1], &sec[rings - 1], &stmp);
    if (overflow || secp256k1_scalar_is_zero(&sec[rings - 1])) {
        return 0;
    }
    signs = &proof[len];
    /* We need one sign bit for each blinded value we send. */
    for (i = 0; i < (rings + 6) >> 3; i++) {
        signs[i] = 0;
        len++;
    }
    npub = 0;
    for (i = 0; i < rings; i++) {
        /*OPT: Use the precomputed gen2 basis?*/
        secp256k1_pedersen_ecmult(ecmult_gen_ctx, &pubs[npub], &sec[i], ((uint64_t)secidx[i] * scale) << (i*2), genp);
        if (secp256k1_gej_is_infinity(&pubs[npub])) {
            return 0;
        }
        if (i < rings - 1) {
            unsigned char tmpc[33];
            secp256k1_ge c;
            unsigned char quadness;
            /*OPT: split loop and batch invert.*/
            /*OPT: do not compute full pubs[npub] in ge form; we only need x */
            secp256k1_ge_set_gej_var(&c, &pubs[npub]);
            secp256k1_rangeproof_serialize_point(tmpc, &c);
            quadness = tmpc[0];
            secp256k1_sha256_write(&sha256_m, tmpc, 33);
            signs[i>>3] |= quadness << (i&7);
            memcpy(&proof[len], tmpc + 1, 32);
            len += 32;
        }
        npub += rsizes[i];
    }
    secp256k1_rangeproof_pub_expand(pubs, exp, rsizes, rings, genp);
    if (extra_commit != NULL) {
        secp256k1_sha256_write(&sha256_m, extra_commit, extra_commit_len);
    }
    secp256k1_sha256_finalize(&sha256_m, tmp);
    if (!secp256k1_borromean_sign(ecmult_ctx, ecmult_gen_ctx, &proof[len], s, pubs, k, sec, rsizes, secidx, rings, tmp, 32)) {
        return 0;
    }
    len += 32;
    for (i = 0; i < npub; i++) {
        secp256k1_scalar_get_b32(&proof[len],&s[i]);
        len += 32;
    }
    VERIFY_CHECK(len <= *plen);
    *plen = len;
    memset(prep, 0, 4096);
    return (int)required_preallocated;
}

int secp256k1_rangeproof_sign_preallocated(const secp256k1_context* ctx, unsigned char *proof, size_t *plen, uint64_t min_value,
 const secp256k1_pedersen_commitment *commit, const unsigned char *blind, const unsigned char *nonce, int exp, int min_bits, uint64_t value,
 const unsigned char *message, size_t msg_len, const unsigned char *extra_commit, size_t extra_commit_len, const secp256k1_generator* gen,
 void * preallocated_ptr, intptr_t allocated_len){
    secp256k1_ge commitp;
    secp256k1_ge genp;
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(proof != NULL);
    ARG_CHECK(plen != NULL);
    ARG_CHECK(commit != NULL);
    ARG_CHECK(blind != NULL);
    ARG_CHECK(nonce != NULL);
    ARG_CHECK(message != NULL || msg_len == 0);
    ARG_CHECK(extra_commit != NULL || extra_commit_len == 0);
    ARG_CHECK(gen != NULL);
    ARG_CHECK(secp256k1_ecmult_context_is_built(&ctx->ecmult_ctx));
    ARG_CHECK(secp256k1_ecmult_gen_context_is_built(&ctx->ecmult_gen_ctx));
    secp256k1_pedersen_commitment_load(&commitp, commit);
    secp256k1_generator_load(&genp, gen);
    return secp256k1_rangeproof_sign_preallocated_impl(&ctx->ecmult_ctx, &ctx->ecmult_gen_ctx,
     proof, plen, min_value, &commitp, blind, nonce, exp, min_bits, value, message, msg_len, extra_commit, extra_commit_len, &genp,
     preallocated_ptr, allocated_len);
}

SECP256K1_INLINE static int secp256k1_rangeproof_rewind_preallocated_inner(secp256k1_scalar *blind, uint64_t *v,
 unsigned char *m, size_t *mlen, secp256k1_scalar *ev, secp256k1_scalar *s,
 size_t *rsizes, size_t rings, const unsigned char *nonce, const secp256k1_ge *commit, const unsigned char *proof, size_t len, const secp256k1_ge *genp,
 void * preallocated_ptr, intptr_t allocated_len) {
    intptr_t ptr = (intptr_t)preallocated_ptr;
    secp256k1_scalar* s_orig = (secp256k1_scalar*)ptr; // [128];
    ptr += 128*sizeof(secp256k1_scalar);
    secp256k1_scalar* sec = (secp256k1_scalar*)ptr; // [32];
    ptr += 32*sizeof(secp256k1_scalar);
    secp256k1_scalar stmp;
    unsigned char* prep = (unsigned char*)ptr; // [4096];
    ptr += 4096;
    unsigned char* tmp = (unsigned char*)ptr; // [32];
    ptr += 32;

    intptr_t required_preallocated = ptr-(intptr_t)preallocated_ptr;
    if(required_preallocated > allocated_len){
        return 0;
    }

    uint64_t value;
    size_t offset;
    size_t i;
    size_t j;
    int b;
    size_t skip1;
    size_t skip2;
    size_t npub;
    npub = ((rings - 1) << 2) + rsizes[rings-1];
    VERIFY_CHECK(npub <= 128);
    VERIFY_CHECK(npub >= 1);
    memset(prep, 0, 4096);
    /* Reconstruct the provers random values. */
    secp256k1_rangeproof_genrand(sec, s_orig, prep, rsizes, rings, nonce, commit, proof, len, genp);
    *v = UINT64_MAX;
    secp256k1_scalar_clear(blind);
    if (rings == 1 && rsizes[0] == 1) {
        /* With only a single proof, we can only recover the blinding factor. */
        secp256k1_rangeproof_recover_x(blind, &s_orig[0], &ev[0], &s[0]);
        if (v) {
            *v = 0;
        }
        if (mlen) {
            *mlen = 0;
        }
        return 1;
    }
    npub = (rings - 1) << 2;
    for (j = 0; j < 2; j++) {
        size_t idx;
        /* Look for a value encoding in the last ring. */
        idx = npub + rsizes[rings - 1] - 1 - j;
        secp256k1_scalar_get_b32(tmp, &s[idx]);
        secp256k1_rangeproof_ch32xor(tmp, &prep[idx * 32]);
        if ((tmp[0] & 128) && (memcmp(&tmp[16], &tmp[24], 8) == 0) && (memcmp(&tmp[8], &tmp[16], 8) == 0)) {
            value = 0;
            for (i = 0; i < 8; i++) {
                value = (value << 8) + tmp[24 + i];
            }
            if (v) {
                *v = value;
            }
            memcpy(&prep[idx * 32], tmp, 32);
            break;
        }
    }
    if (j > 1) {
        /* Couldn't extract a value. */
        if (mlen) {
            *mlen = 0;
        }
        return 0;
    }
    skip1 = rsizes[rings - 1] - 1 - j;
    skip2 = ((value >> ((rings - 1) << 1)) & 3);
    if (skip1 == skip2) {
        /*Value is in wrong position.*/
        if (mlen) {
            *mlen = 0;
        }
        return 0;
    }
    skip1 += (rings - 1) << 2;
    skip2 += (rings - 1) << 2;
    /* Like in the rsize[] == 1 case, Having figured out which s is the one which was not forged, we can recover the blinding factor. */
    secp256k1_rangeproof_recover_x(&stmp, &s_orig[skip2], &ev[skip2], &s[skip2]);
    secp256k1_scalar_negate(&sec[rings - 1], &sec[rings - 1]);
    secp256k1_scalar_add(blind, &stmp, &sec[rings - 1]);
    if (!m || !mlen || *mlen == 0) {
        if (mlen) {
            *mlen = 0;
        }
        /* FIXME: cleanup in early out/failure cases. */
        return 1;
    }
    offset = 0;
    npub = 0;
    for (i = 0; i < rings; i++) {
        size_t idx;
        idx = (value >> (i << 1)) & 3;
        for (j = 0; j < rsizes[i]; j++) {
            if (npub == skip1 || npub == skip2) {
                npub++;
                continue;
            }
            if (idx == j) {
                /** For the non-forged signatures the signature is calculated instead of random, instead we recover the prover's nonces.
                 *  this could just as well recover the blinding factors and messages could be put there as is done for recovering the
                 *  blinding factor in the last ring, but it takes an inversion to recover x so it's faster to put the message data in k.
                 */
                secp256k1_rangeproof_recover_k(&stmp, &sec[i], &ev[npub], &s[npub]);
            } else {
                stmp = s[npub];
            }
            secp256k1_scalar_get_b32(tmp, &stmp);
            secp256k1_rangeproof_ch32xor(tmp, &prep[npub * 32]);
            for (b = 0; b < 32 && offset < *mlen; b++) {
                m[offset] = tmp[b];
                offset++;
            }
            npub++;
        }
    }
    *mlen = offset;
    memset(prep, 0, 4096);
    for (i = 0; i < 128; i++) {
        secp256k1_scalar_clear(&s_orig[i]);
    }
    for (i = 0; i < 32; i++) {
        secp256k1_scalar_clear(&sec[i]);
    }
    secp256k1_scalar_clear(&stmp);
    return 1;
}

SECP256K1_INLINE static int secp256k1_rangeproof_verify_preallocated_impl(const secp256k1_ecmult_context* ecmult_ctx,
 const secp256k1_ecmult_gen_context* ecmult_gen_ctx,
 unsigned char *blindout, uint64_t *value_out, unsigned char *message_out, size_t *outlen, const unsigned char *nonce,
 uint64_t *min_value, uint64_t *max_value, const secp256k1_ge *commit, const unsigned char *proof, size_t plen, const unsigned char *extra_commit, size_t extra_commit_len, const secp256k1_ge* genp,
 void * preallocated_ptr, intptr_t allocated_len) {
    intptr_t ptr = (intptr_t)preallocated_ptr;

    secp256k1_gej accj;
    secp256k1_gej* pubs = (secp256k1_gej*)ptr; //[128];
    ptr += 128*sizeof(secp256k1_gej);
    secp256k1_ge c;
    secp256k1_scalar* s = (secp256k1_scalar*)ptr; // [128];
    ptr += 128*sizeof(secp256k1_scalar);
    secp256k1_scalar* evalues = (secp256k1_scalar*)ptr; //[128]; /* Challenges, only used during proof rewind. */
    ptr += 128*sizeof(secp256k1_scalar);
    secp256k1_sha256 sha256_m;
    size_t* rsizes = (size_t *)ptr; //[32];
    ptr += 32*sizeof(size_t);

    int ret;
    size_t i;
    int exp;
    int mantissa;
    size_t offset;
    size_t rings;
    int overflow;
    size_t npub;
    int offset_post_header;
    uint64_t scale;
    unsigned char* signs = (unsigned char*)ptr; //[31];
    ptr += 32; // alignment

    unsigned char* m = (unsigned char*)ptr; //[33];
    ptr += 36; // alignment
    const unsigned char *e0;

    intptr_t required_preallocated = ptr-(intptr_t)preallocated_ptr;
    if(required_preallocated > allocated_len){
        return 0;
    }

    offset = 0;
    if (!secp256k1_rangeproof_getheader_impl(&offset, &exp, &mantissa, &scale, min_value, max_value, proof, plen)) {
        return 0;
    }
    offset_post_header = offset;
    rings = 1;
    rsizes[0] = 1;
    npub = 1;
    if (mantissa != 0) {
        rings = (mantissa >> 1);
        for (i = 0; i < rings; i++) {
            rsizes[i] = 4;
        }
        npub = (mantissa >> 1) << 2;
        if (mantissa & 1) {
            rsizes[rings] = 2;
            npub += rsizes[rings];
            rings++;
        }
    }
    VERIFY_CHECK(rings <= 32);
    if (plen - offset < 32 * (npub + rings - 1) + 32 + ((rings+6) >> 3)) {
        return 0;
    }
    secp256k1_sha256_initialize(&sha256_m);
    secp256k1_rangeproof_serialize_point(m, commit);
    secp256k1_sha256_write(&sha256_m, m, 33);
    secp256k1_rangeproof_serialize_point(m, genp);
    secp256k1_sha256_write(&sha256_m, m, 33);
    secp256k1_sha256_write(&sha256_m, proof, offset);
    for(i = 0; i < rings - 1; i++) {
        signs[i] = (proof[offset + ( i>> 3)] & (1 << (i & 7))) != 0;
    }
    offset += (rings + 6) >> 3;
    if ((rings - 1) & 7) {
        /* Number of coded blinded points is not a multiple of 8, force extra sign bits to 0 to reject mutation. */
        if ((proof[offset - 1] >> ((rings - 1) & 7)) != 0) {
            return 0;
        }
    }
    npub = 0;
    secp256k1_gej_set_infinity(&accj);
    if (*min_value) {
        secp256k1_pedersen_ecmult_small(&accj, *min_value, genp);
    }
    for(i = 0; i < rings - 1; i++) {
        secp256k1_fe fe;
        if (!secp256k1_fe_set_b32(&fe, &proof[offset]) ||
            !secp256k1_ge_set_xquad(&c, &fe)) {
            return 0;
        }
        if (signs[i]) {
            secp256k1_ge_neg(&c, &c);
        }
        /* Not using secp256k1_rangeproof_serialize_point as we almost have it
         * serialized form already. */
        secp256k1_sha256_write(&sha256_m, &signs[i], 1);
        secp256k1_sha256_write(&sha256_m, &proof[offset], 32);
        secp256k1_gej_set_ge(&pubs[npub], &c);
        secp256k1_gej_add_ge_var(&accj, &accj, &c, NULL);
        offset += 32;
        npub += rsizes[i];
    }
    secp256k1_gej_neg(&accj, &accj);
    secp256k1_gej_add_ge_var(&pubs[npub], &accj, commit, NULL);
    if (secp256k1_gej_is_infinity(&pubs[npub])) {
        return 0;
    }
    secp256k1_rangeproof_pub_expand(pubs, exp, rsizes, rings, genp);
    npub += rsizes[rings - 1];
    e0 = &proof[offset];
    offset += 32;
    for (i = 0; i < npub; i++) {
        secp256k1_scalar_set_b32(&s[i], &proof[offset], &overflow);
        if (overflow) {
            return 0;
        }
        offset += 32;
    }
    if (offset != plen) {
        /*Extra data found, reject.*/
        return 0;
    }
    if (extra_commit != NULL) {
        secp256k1_sha256_write(&sha256_m, extra_commit, extra_commit_len);
    }
    secp256k1_sha256_finalize(&sha256_m, m);
    ret = secp256k1_borromean_verify(ecmult_ctx, nonce ? evalues : NULL, e0, s, pubs, rsizes, rings, m, 32);
    if (ret && nonce) {
        /* Given the nonce, try rewinding the witness to recover its initial state. */
        secp256k1_scalar blind;
        uint64_t vv;
        if (!ecmult_gen_ctx) {
            return 0;
        }
        if (!secp256k1_rangeproof_rewind_preallocated_inner(&blind, &vv, message_out, outlen, evalues, s, rsizes, rings, nonce, commit, proof, offset_post_header, genp,
                        (void *)ptr, (allocated_len-required_preallocated))) {
            return 0;
        }
        /* Unwind apparently successful, see if the commitment can be reconstructed. */
        /* FIXME: should check vv is in the mantissa's range. */
        vv = (vv * scale) + *min_value;
        secp256k1_pedersen_ecmult(ecmult_gen_ctx, &accj, &blind, vv, genp);
        if (secp256k1_gej_is_infinity(&accj)) {
            return 0;
        }
        secp256k1_gej_neg(&accj, &accj);
        secp256k1_gej_add_ge_var(&accj, &accj, commit, NULL);
        if (!secp256k1_gej_is_infinity(&accj)) {
            return 0;
        }
        if (blindout) {
            secp256k1_scalar_get_b32(blindout, &blind);
        }
        if (value_out) {
            *value_out = vv;
        }
    }
    return ret;
}

int secp256k1_rangeproof_rewind_preallocated(const secp256k1_context* ctx,
 unsigned char *blind_out, uint64_t *value_out, unsigned char *message_out, size_t *outlen, const unsigned char *nonce,
 uint64_t *min_value, uint64_t *max_value,
 const secp256k1_pedersen_commitment *commit, const unsigned char *proof, size_t plen, const unsigned char *extra_commit, size_t extra_commit_len, const secp256k1_generator* gen,
 void * preallocated_ptr, intptr_t allocated_len) {
    secp256k1_ge commitp;
    secp256k1_ge genp;
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(commit != NULL);
    ARG_CHECK(proof != NULL);
    ARG_CHECK(min_value != NULL);
    ARG_CHECK(max_value != NULL);
    ARG_CHECK(message_out != NULL || outlen == NULL);
    ARG_CHECK(nonce != NULL);
    ARG_CHECK(extra_commit != NULL || extra_commit_len == 0);
    ARG_CHECK(gen != NULL);
    ARG_CHECK(secp256k1_ecmult_context_is_built(&ctx->ecmult_ctx));
    ARG_CHECK(secp256k1_ecmult_gen_context_is_built(&ctx->ecmult_gen_ctx));
    secp256k1_pedersen_commitment_load(&commitp, commit);
    secp256k1_generator_load(&genp, gen);
    return secp256k1_rangeproof_verify_preallocated_impl(&ctx->ecmult_ctx, &ctx->ecmult_gen_ctx,
     blind_out, value_out, message_out, outlen, nonce, min_value, max_value, &commitp, proof, plen, extra_commit, extra_commit_len, &genp,
     preallocated_ptr, allocated_len);
}

#endif