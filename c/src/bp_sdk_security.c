#include "bp_sdk_internal.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

extern bp_context_t g_bp_context;

static bp_security_t *find_security(const char *name) {
    if (!name) return NULL;
    for (int i = 0; i < g_bp_context.security.count; i++) {
        if (strcmp(g_bp_context.security.security[i]->security_name, name) == 0) {
            return g_bp_context.security.security[i];
        }
    }
    return NULL;
}

static int validate_security(bp_security_t *sec) {
    return sec && sec->security_name && (sec->encrypt || sec->decrypt || sec->sign || sec->verify);
}

int bp_security_register(bp_security_t *security) {
    if (!validate_security(security) || !g_bp_context.initialized) 
        return !g_bp_context.initialized ? BP_ERROR_NOT_INITIALIZED : BP_ERROR_INVALID_ARGS;

    pthread_mutex_lock(&g_bp_context.mutex);
    
    if (find_security(security->security_name)) {
        pthread_mutex_unlock(&g_bp_context.mutex);
        return BP_ERROR_DUPLICATE;
    }

    int result = ensure_capacity((void***)&g_bp_context.security.security, 
                               &g_bp_context.security.capacity, 
                               g_bp_context.security.count, 
                               sizeof(bp_security_t*));
    
    if (result == BP_SUCCESS) {
        g_bp_context.security.security[g_bp_context.security.count++] = security;
    }
    
    pthread_mutex_unlock(&g_bp_context.mutex);
    return result;
}

int bp_security_unregister(const char *security_name) {
    if (!security_name || !g_bp_context.initialized) 
        return !g_bp_context.initialized ? BP_ERROR_NOT_INITIALIZED : BP_ERROR_INVALID_ARGS;

    pthread_mutex_lock(&g_bp_context.mutex);
    
    for (int i = 0; i < g_bp_context.security.count; i++) {
        if (strcmp(g_bp_context.security.security[i]->security_name, security_name) == 0) {
            memmove(&g_bp_context.security.security[i], 
                   &g_bp_context.security.security[i + 1], 
                   (g_bp_context.security.count - i - 1) * sizeof(bp_security_t*));
            g_bp_context.security.count--;
            pthread_mutex_unlock(&g_bp_context.mutex);
            return BP_SUCCESS;
        }
    }
    
    pthread_mutex_unlock(&g_bp_context.mutex);
    return BP_ERROR_NOT_FOUND;
}

int bp_security_encrypt(const void *plain, size_t plain_len, void **cipher, size_t *cipher_len) {
    if (!plain || !cipher || !cipher_len || !g_bp_context.initialized) 
        return !g_bp_context.initialized ? BP_ERROR_NOT_INITIALIZED : BP_ERROR_INVALID_ARGS;

    pthread_mutex_lock(&g_bp_context.mutex);
    
    if (g_bp_context.security.count == 0) {
        pthread_mutex_unlock(&g_bp_context.mutex);
        return BP_ERROR_NOT_FOUND;
    }

    bp_security_t *sec = g_bp_context.security.security[0];
    if (!sec->encrypt) {
        pthread_mutex_unlock(&g_bp_context.mutex);
        return BP_ERROR_PROTOCOL;
    }

    int result = sec->encrypt(plain, plain_len, cipher, cipher_len, sec->context);
    pthread_mutex_unlock(&g_bp_context.mutex);
    
    return (result == 0) ? BP_SUCCESS : BP_ERROR_SECURITY;
}

int bp_security_decrypt(const void *cipher, size_t cipher_len, void **plain, size_t *plain_len) {
    if (!cipher || !plain || !plain_len || !g_bp_context.initialized) 
        return !g_bp_context.initialized ? BP_ERROR_NOT_INITIALIZED : BP_ERROR_INVALID_ARGS;

    pthread_mutex_lock(&g_bp_context.mutex);
    
    if (g_bp_context.security.count == 0) {
        pthread_mutex_unlock(&g_bp_context.mutex);
        return BP_ERROR_NOT_FOUND;
    }

    bp_security_t *sec = g_bp_context.security.security[0];
    if (!sec->decrypt) {
        pthread_mutex_unlock(&g_bp_context.mutex);
        return BP_ERROR_PROTOCOL;
    }

    int result = sec->decrypt(cipher, cipher_len, plain, plain_len, sec->context);
    pthread_mutex_unlock(&g_bp_context.mutex);
    
    return (result == 0) ? BP_SUCCESS : BP_ERROR_SECURITY;
}

int bp_security_sign(const void *data, size_t data_len, void **signature, size_t *sig_len) {
    if (!data || !signature || !sig_len || !g_bp_context.initialized) 
        return !g_bp_context.initialized ? BP_ERROR_NOT_INITIALIZED : BP_ERROR_INVALID_ARGS;

    pthread_mutex_lock(&g_bp_context.mutex);
    
    if (g_bp_context.security.count == 0) {
        pthread_mutex_unlock(&g_bp_context.mutex);
        return BP_ERROR_NOT_FOUND;
    }

    bp_security_t *sec = g_bp_context.security.security[0];
    if (!sec->sign) {
        pthread_mutex_unlock(&g_bp_context.mutex);
        return BP_ERROR_PROTOCOL;
    }

    int result = sec->sign(data, data_len, signature, sig_len, sec->context);
    pthread_mutex_unlock(&g_bp_context.mutex);
    
    return (result == 0) ? BP_SUCCESS : BP_ERROR_SECURITY;
}

int bp_security_verify(const void *data, size_t data_len, const void *signature, size_t sig_len) {
    if (!data || !signature || !g_bp_context.initialized) 
        return !g_bp_context.initialized ? BP_ERROR_NOT_INITIALIZED : BP_ERROR_INVALID_ARGS;

    pthread_mutex_lock(&g_bp_context.mutex);
    
    if (g_bp_context.security.count == 0) {
        pthread_mutex_unlock(&g_bp_context.mutex);
        return BP_ERROR_NOT_FOUND;
    }

    bp_security_t *sec = g_bp_context.security.security[0];
    if (!sec->verify) {
        pthread_mutex_unlock(&g_bp_context.mutex);
        return BP_ERROR_PROTOCOL;
    }

    int result = sec->verify(data, data_len, signature, sig_len, sec->context);
    pthread_mutex_unlock(&g_bp_context.mutex);
    
    return (result == 0) ? BP_SUCCESS : BP_ERROR_SECURITY;
}

static int aes_gcm_encrypt_impl(const void *plain, size_t plain_len, void **cipher, size_t *cipher_len, void *context) {
    (void)context;
    
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    unsigned char key[32] = {0};
    unsigned char iv[12] = {0};
    unsigned char tag[16] = {0};
    
    if (RAND_bytes(iv, sizeof(iv)) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    *cipher_len = plain_len + sizeof(iv) + sizeof(tag);
    *cipher = malloc(*cipher_len);
    if (!*cipher) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    unsigned char *out = (unsigned char *)*cipher;
    memcpy(out, iv, sizeof(iv));
    
    int len;
    if (EVP_EncryptUpdate(ctx, out + sizeof(iv), &len, plain, plain_len) != 1) {
        free(*cipher);
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    if (EVP_EncryptFinal_ex(ctx, out + sizeof(iv) + len, &len) != 1) {
        free(*cipher);
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, sizeof(tag), tag) != 1) {
        free(*cipher);
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    memcpy(out + sizeof(iv) + plain_len, tag, sizeof(tag));
    EVP_CIPHER_CTX_free(ctx);
    return 0;
}

static int hmac_sha256_sign_impl(const void *data, size_t data_len, void **signature, size_t *sig_len, void *context) {
    (void)context;
    
    unsigned char key[32] = {0};
    unsigned int len = 0;
    
    *signature = malloc(EVP_MAX_MD_SIZE);
    if (!*signature) return -1;

    if (!HMAC(EVP_sha256(), key, sizeof(key), data, data_len, *signature, &len)) {
        free(*signature);
        return -1;
    }

    *sig_len = len;
    return 0;
}

static int hmac_sha256_verify_impl(const void *data, size_t data_len, const void *signature, size_t sig_len, void *context) {
    void *computed_sig;
    size_t computed_len;
    
    if (hmac_sha256_sign_impl(data, data_len, &computed_sig, &computed_len, context) != 0) {
        return -1;
    }

    int result = (computed_len == sig_len && memcmp(computed_sig, signature, sig_len) == 0) ? 0 : -1;
    free(computed_sig);
    return result;
}

int bp_security_create_aes_gcm(bp_security_t **security) {
    if (!security) return BP_ERROR_INVALID_ARGS;

    bp_security_t *sec = malloc(sizeof(bp_security_t));
    if (!sec) return BP_ERROR_MEMORY;

    memset(sec, 0, sizeof(bp_security_t));
    sec->security_name = strdup("aes-gcm");
    if (!sec->security_name) {
        free(sec);
        return BP_ERROR_MEMORY;
    }

    sec->encrypt = aes_gcm_encrypt_impl;
    sec->context = NULL;

    *security = sec;
    return BP_SUCCESS;
}

int bp_security_create_hmac_sha256(bp_security_t **security) {
    if (!security) return BP_ERROR_INVALID_ARGS;

    bp_security_t *sec = malloc(sizeof(bp_security_t));
    if (!sec) return BP_ERROR_MEMORY;

    memset(sec, 0, sizeof(bp_security_t));
    sec->security_name = strdup("hmac-sha256");
    if (!sec->security_name) {
        free(sec);
        return BP_ERROR_MEMORY;
    }

    sec->sign = hmac_sha256_sign_impl;
    sec->verify = hmac_sha256_verify_impl;
    sec->context = NULL;

    *security = sec;
    return BP_SUCCESS;
}

int bp_security_destroy(bp_security_t *security) {
    if (!security) return BP_ERROR_INVALID_ARGS;

    free(security->security_name);
    free(security);
    return BP_SUCCESS;
} 