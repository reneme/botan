#include <tss2/tss2_esys.h>
#include <stdio.h>
#include <tss2/tss2_rc.h>
#include <tss2/tss2_tcti.h>
#include <tss2/tss2_tctildr.h>
#include <string.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>

// apt install swtpm-tools + gnutls-bin + tpm2-abrmd

// sudo mkdir /tmp/mytpm2
// sudo chown tss:root /tmp/mytpm2
// sudo swtpm_setup --tpmstate /tmp/mytpm2 --create-ek-cert --create-platform-cert --create-spk --tpm2
// then swtpm socket

int main() {
    TSS2_RC rc;
    ESYS_CONTEXT *ectx;

    // Initialize the ESAPI context
    const char* tcti = "tabrmd:bus_name=net.randombit.botan.tabrmd,bus_type=session";
    TSS2_TCTI_CONTEXT* tcti_ctx;
    Tss2_TctiLdr_Initialize(tcti, &tcti_ctx);

    rc = Esys_Initialize(&ectx, tcti_ctx, NULL);
    if (rc != TSS2_RC_SUCCESS) {
        fprintf(stderr, "Esys_Initialize failed: 0x%x\n", rc);
        return 1;
    }

    // Obtain the spk (storage primary key) with handle 0x81000001
    TPM2B_PUBLIC *spk_public = NULL;
    ESYS_TR public_handle;
    rc = Esys_TR_FromTPMPublic(ectx, 0x81000001, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, &public_handle);
    if (rc != TSS2_RC_SUCCESS) {
        fprintf(stderr, "Esys_TR_FromTPMPublic failed: 0x%s\n", Tss2_RC_Decode(rc));
        goto cleanup;
    }
    rc = Esys_ReadPublic(ectx, public_handle, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, &spk_public, NULL, NULL);
    if (rc != TSS2_RC_SUCCESS) {
        fprintf(stderr, "Esys_ReadPublic failed: 0x%s\n", Tss2_RC_Decode(rc));
        goto cleanup;
    }
    // TODO: Sometimes the above crashes and TPM needs a restart? => something not properly de-allocated?
    printf("Storage Primary Key (SPK):");
    for(int i = 0; i < spk_public->size; i++) {
        printf("%02x", spk_public->publicArea.unique.rsa.buffer[i]);
    }
    printf("\n");
    Esys_Free(spk_public);

    // Start an authorization session
    ESYS_TR session = ESYS_TR_NONE;
    const TPMT_SYM_DEF auth_sym = {
        .algorithm = TPM2_ALG_AES,
        .keyBits = {.aes = 256},
        .mode = {.aes = TPM2_ALG_CFB},
    };
    TPMI_ALG_HASH auth_hash = TPM2_ALG_SHA256;
    rc = Esys_StartAuthSession(ectx, public_handle /*used to encrypt a random salt*/, public_handle /*bind*/, ESYS_TR_NONE,
                               ESYS_TR_NONE, ESYS_TR_NONE, NULL /*NonceCaller generated automatically*/, TPM2_SE_HMAC, &auth_sym, auth_hash, &session);
    if (rc != TSS2_RC_SUCCESS) {
        fprintf(stderr, "Esys_StartAuthSession failed: 0x%s\n", Tss2_RC_Decode(rc));
        goto cleanup;
    }

    TPMA_SESSION sessionAttributes = TPMA_SESSION_CONTINUESESSION | TPMA_SESSION_AUDIT;/* to sign*/;
    rc = Esys_TRSess_SetAttributes(ectx, session, sessionAttributes, 0xFF);
    if (rc != TSS2_RC_SUCCESS) {
        fprintf(stderr, "Esys_TRSess_SetAttributes failed: 0x%x\n", rc);
        goto cleanup;
    }

    // // Create primary key with password 123456
    // const char *authValue = "123456";
    // TPM2B_AUTH auth = {
    //     .size = strlen(authValue),
    //     .buffer = {0}
    // };
    // memcpy(auth.buffer, authValue, auth.size);

//     TPM2B_PUBLIC in_public = {
//         .size = 0,
//         .publicArea = {
//             .type = TPM2_ALG_RSA,
//             .nameAlg = TPM2_ALG_SHA256,
//             .objectAttributes = (TPMA_OBJECT_USERWITHAUTH | TPMA_OBJECT_RESTRICTED |
//                                  TPMA_OBJECT_DECRYPT | TPMA_OBJECT_FIXEDTPM |
//                                  TPMA_OBJECT_FIXEDPARENT | TPMA_OBJECT_SENSITIVEDATAORIGIN),
//             .authPolicy = { .size = 0 },
//             .parameters.rsaDetail = {
//                 .symmetric = {
//                     .algorithm = TPM2_ALG_AES,
//                     .keyBits.aes = 256,
//                     .mode.aes = TPM2_ALG_CFB,
//                 },
//                 .scheme = {
//                     .scheme = TPM2_ALG_NULL,
//                 },
//                 .keyBits = 2048,
//                 .exponent = 0,
//             },
//             .unique.rsa = { .size = 0 },
//         },
//     };

//     TPM2B_SENSITIVE_CREATE in_sensitive = {
//         .size = 0,
//         .sensitive = {
//             .userAuth = auth,
//             .data = { .size = 0, .buffer = {0} }
//         }
//     };

//     TPML_PCR_SELECTION creation_pcr = { .count = 0 };

//     ESYS_TR primary_handle;
//     TPM2B_PUBLIC *out_public = NULL;
//     TPM2B_CREATION_DATA *creation_data = NULL;
//     TPM2B_DIGEST *creation_hash = NULL;
//     TPMT_TK_CREATION *creation_ticket = NULL;

//     rc = Esys_CreatePrimary(ectx, ESYS_TR_RH_OWNER, session, ESYS_TR_NONE, ESYS_TR_NONE,
// &in_sensitive, &in_public, NULL, &creation_pcr,
// &primary_handle, &out_public, &creation_data,
// &creation_hash, &creation_ticket);
//     if (rc != TSS2_RC_SUCCESS) {
//         fprintf(stderr, "Esys_CreatePrimary failed: 0x%s\n", Tss2_RC_Decode(rc));
//         goto cleanup;
//     }

//     printf("Created primary key:");

//     for(int i = 0; i < out_public->size; i++) {
//         printf("%02x", out_public->publicArea.unique.rsa.buffer[i]);
//     }
//     printf("\n");

//     // Make the primary key persistent
//     ESYS_TR persistent_handle_out;
//     TPMI_DH_PERSISTENT persistent_handle_in = TPM2_PERSISTENT_FIRST + 4;

//     rc = Esys_EvictControl(ectx, ESYS_TR_RH_OWNER, primary_handle, session, ESYS_TR_NONE, ESYS_TR_NONE, persistent_handle_in, &persistent_handle_out);
//     if (rc != TSS2_RC_SUCCESS) {
//         fprintf(stderr, "Esys_EvictControl failed: 0x%s\n", Tss2_RC_Decode(rc));
//         goto cleanup;
//     }
//     TPM2_HANDLE tpm_handle;
//     rc = Esys_TR_GetTpmHandle(ectx, persistent_handle_out, &tpm_handle);
//     if (rc != TSS2_RC_SUCCESS) {
//         fprintf(stderr, "Esys_TR_GetTpmHandle failed: 0x%s\n", Tss2_RC_Decode(rc));
//         goto cleanup;
//     }
//     printf("Primary key made persistent with handle: 0x%08x\n", tpm_handle);

    // // Load the primary persistent key with handle 0x81000004
    // TPM2_HANDLE persistent_handle = 0x81000004;
    // ESYS_TR loaded_handle = ESYS_TR_NONE;
    // rc = Esys_TR_FromTPMPublic(ectx, persistent_handle, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, &loaded_handle);
    // if (rc != TSS2_RC_SUCCESS) {
    //     fprintf(stderr, "Esys_Load failed: 0x%s\n", Tss2_RC_Decode(rc));
    //     goto cleanup;
    // }
    // printf("Primary key loaded with handle: 0x%08x\n", loaded_handle);

    // // Set the authorization value for the key
    // rc = Esys_TR_SetAuth(ectx, loaded_handle, &auth);
    // if (rc != TSS2_RC_SUCCESS) {
    //     fprintf(stderr, "Esys_TR_SetAuth failed: 0x%s\n", Tss2_RC_Decode(rc));
    //     goto cleanup;
    // }
    // printf("Authorization value set for key\n");

    // Signing key template
    TPM2B_PUBLIC inPublic = {
        .size = 0,
        .publicArea = {
            .type = TPM2_ALG_RSA,
            .nameAlg = TPM2_ALG_SHA256,
            .objectAttributes = (TPMA_OBJECT_SIGN_ENCRYPT | TPMA_OBJECT_USERWITHAUTH |
                                 TPMA_OBJECT_FIXEDTPM | TPMA_OBJECT_FIXEDPARENT |
                                 TPMA_OBJECT_SENSITIVEDATAORIGIN),
            .authPolicy = {0},
            .parameters.rsaDetail = {
                .symmetric = {
                    .algorithm = TPM2_ALG_NULL,
                    .keyBits = {.aes = 0},
                    .mode = {.aes = 0}
                },
                .scheme = {
                    .scheme = TPM2_ALG_RSASSA,
                    .details = {.rsassa = {.hashAlg = TPM2_ALG_SHA256}}
                },
                .keyBits = 2048,
                .exponent = 0
            },
            .unique.rsa = {
                .size = 0,
                .buffer = {0}
            }
        }
    };

    // Sensitive data for signing key (auth value)
    const char *signingAuthValue = "signingKey123";
    TPM2B_AUTH signingAuth = {
        .size = strlen(signingAuthValue),
        .buffer = {0}
    };
    memcpy(signingAuth.buffer, signingAuthValue, signingAuth.size);

    TPM2B_SENSITIVE_CREATE inSensitive = {
        .size = 0,
        .sensitive = {
            .userAuth = signingAuth,
            .data = {.size = 0, .buffer = {0}}
        }
    };

    TPM2B_DATA outsideInfo = {.size = 0, .buffer = {0}};
    TPML_PCR_SELECTION creationPCR = {.count = 0};

    TPM2B_PRIVATE *outPrivate = NULL;
    TPM2B_PUBLIC *outPublic = NULL;
    TPM2B_CREATION_DATA *creationData = NULL;
    TPM2B_DIGEST *creationHash = NULL;
    TPMT_TK_CREATION *creationTicket = NULL;
    ESYS_TR signingKeyHandle = ESYS_TR_NONE;

    // Create the signing key
    rc = Esys_Create(
        ectx,
        public_handle,
        session,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        &inSensitive,
        &inPublic,
        &outsideInfo,
        &creationPCR,
        &outPrivate,
        &outPublic,
        &creationData,
        &creationHash,
        &creationTicket
    );

    if (rc != TSS2_RC_SUCCESS) {
        printf("Esys_Create Signing failed: 0x%s\n", Tss2_RC_Decode(rc));
        goto cleanup;
    }
    printf("Signing key created successfully.\n");

    // Load the signing key
    rc = Esys_Load(
        ectx,
        public_handle,
        ESYS_TR_PASSWORD,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        outPrivate,
        outPublic,
        &signingKeyHandle
    );

    if (rc != TSS2_RC_SUCCESS) {
        printf("Esys_Load Signing failed: 0x%s\n", Tss2_RC_Decode(rc));
        goto cleanup;
    }
    printf("Signing key loaded successfully.\n");

    // signingAuth.buffer[0] = 0; // Mess it up to test auth

    // Set the authorization value for the signing key
    rc = Esys_TR_SetAuth(ectx, signingKeyHandle, &signingAuth);
    if (rc != TSS2_RC_SUCCESS) {
        printf("Esys_TR_SetAuth failed: 0x%s\n", Tss2_RC_Decode(rc));
    }
    printf("Authorization value set for signing key successfully.\n");

    printf("Evicting Signing key...\n");
    ESYS_TR sign_persistent_handle_out;
    TPMI_DH_PERSISTENT sign_persistent_handle_in = TPM2_PERSISTENT_FIRST + 7;
    rc = Esys_EvictControl(ectx, ESYS_TR_RH_OWNER, signingKeyHandle, session, ESYS_TR_NONE, ESYS_TR_NONE, sign_persistent_handle_in, &sign_persistent_handle_out);
    if (rc != TSS2_RC_SUCCESS) {
        fprintf(stderr, "Esys_EvictControl failed: 0x%s\n", Tss2_RC_Decode(rc));
        goto cleanup;
    }
    TPM2_HANDLE sign_tpm_handle;
    rc = Esys_TR_GetTpmHandle(ectx, sign_persistent_handle_out, &sign_tpm_handle);
    if (rc != TSS2_RC_SUCCESS) {
        fprintf(stderr, "Esys_TR_GetTpmHandle failed: 0x%s\n", Tss2_RC_Decode(rc));
        goto cleanup;
    }
    printf("Signing key made persistent with handle: 0x%08x\n", sign_tpm_handle);

    // Sign some data
    // Define the data to be signed
    const char *dataToSign = "Hello, TPM!";
    TPM2B_DIGEST digest = {
        .size = 32, // SHA-256 produces a 32-byte hash
        .buffer = {0}
    };

    // Compute the SHA-256 hash of the data
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, dataToSign, strlen(dataToSign));
    SHA256_Final(digest.buffer, &sha256);

    // Define the scheme to be used for signing
    TPMT_SIG_SCHEME inScheme = {
        .scheme = TPM2_ALG_RSASSA,
        .details = {
            .rsassa = {
                .hashAlg = TPM2_ALG_SHA256
            }
        }
    };

    // Placeholder for the signature
    TPMT_TK_HASHCHECK validation = {
        .tag = TPM2_ST_HASHCHECK,
        .hierarchy = TPM2_RH_NULL,
        .digest = {.size = 0, .buffer = {0}}
    };

    TPM2B_ATTEST *quoted = NULL;
    TPMT_SIGNATURE *signature = NULL;

    // Sign the data
    rc = Esys_Sign(
        ectx,
        signingKeyHandle,
        session,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        &digest,
        &inScheme,
        &validation,
        &signature
    );

    if (rc != TSS2_RC_SUCCESS) {
        printf("Esys_Sign failed: 0x%s\n", Tss2_RC_Decode(rc));
        goto cleanup;
    }

    // Output the signature
    printf("Signature generated successfully.\n");
    printf("Signature size: %d\n", signature->signature.rsassa.sig.size);
    for (int i = 0; i < signature->signature.rsassa.sig.size; i++) {
        printf("%02X", signature->signature.rsassa.sig.buffer[i]);
    }
    printf("\n");


cleanup:
    // Clean up
    //Esys_TR_Close(ectx, &primary_handle);
    // Esys_Free(out_public);
    // Esys_Free(creation_data);
    // Esys_Free(creation_hash);
    // Esys_Free(creation_ticket);

    Esys_Free(signature);

    Esys_FlushContext(ectx, signingKeyHandle);
    Esys_Free(outPrivate);
    Esys_Free(outPublic);
    Esys_Free(creationData);
    Esys_Free(creationHash);
    Esys_Free(creationTicket);

    // Esys_TR_Close(ectx, &loaded_handle);
    Esys_FlushContext(ectx, session);
    Esys_Finalize(&ectx);

    return rc;
}
