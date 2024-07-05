#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <inttypes.h>
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "mbedtls/aes.h"
#include "mbedtls/md5.h"
#include "mbedtls/sha1.h"

#define C_NRM "\x1B[0m"
#define C_RED "\x1B[31m"
#define C_GRN "\x1B[32m"
#define C_YEL "\x1B[33m"
#define C_BLU "\x1B[34m"
#define C_MAG "\x1B[35m"
#define C_CYN "\x1B[36m"
#define C_WHT "\x1B[37m"

void calculate_sha1(const unsigned char *input, size_t input_len, unsigned char output[20])
{
    mbedtls_sha1_context ctx;
    mbedtls_sha1_init(&ctx);
    mbedtls_sha1_starts(&ctx);
    mbedtls_sha1_update(&ctx, input, input_len);
    mbedtls_sha1_finish(&ctx, output);
    mbedtls_sha1_free(&ctx);
}

void calculate_md5(const unsigned char *input, size_t input_len, unsigned char output[16])
{
    mbedtls_md5_context ctx;
    mbedtls_md5_init(&ctx);
    mbedtls_md5_starts(&ctx);
    mbedtls_md5_update(&ctx, input, input_len);
    mbedtls_md5_finish(&ctx, output);
    mbedtls_md5_free(&ctx);
}

void encrypt_string(const char *input, const char *key, const char *iv, unsigned char **output, size_t *output_len)
{
    unsigned char sha1_key[20];
    calculate_sha1((const unsigned char *)key, strlen(key), sha1_key);
    // ESP_LOG_BUFFER_HEX("SHA1 KEY", sha1_key, 20);

    unsigned char md5_iv[16];
    calculate_md5((const unsigned char *)iv, strlen(iv), md5_iv);
    // ESP_LOG_BUFFER_HEX("MD5 IV", md5_iv, 16);

    size_t input_len = strlen(input);
    size_t padded_input_len = (input_len / 16 + 1) * 16;

    unsigned char *padded_input = (unsigned char *)malloc(padded_input_len);
    if (!padded_input)
    {
        printf("[encrypt_string] Failed to allocate memory\n");
        return;
    }

    memcpy(padded_input, input, input_len);

    // PKCS#5 padding
    uint8_t padding_value = padded_input_len - input_len;
    for (size_t i = input_len; i < padded_input_len; i++)
    {
        padded_input[i] = padding_value;
    }

    *output = (unsigned char *)malloc(padded_input_len);
    if (!(*output))
    {
        printf("[encrypt_string] Failed to allocate memory for output\n");
        free(padded_input);
        return;
    }

    mbedtls_aes_context aes;
    mbedtls_aes_init(&aes);
    mbedtls_aes_setkey_enc(&aes, sha1_key, 256);

    // ECB
    // mbedtls_aes_crypt_ecb(&aes, MBEDTLS_AES_ENCRYPT, (unsigned char *)padded_input, encrypt_output);

    mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_ENCRYPT, padded_input_len, md5_iv, padded_input, *output);
    // ESP_LOG_BUFFER_HEX("cbc_encrypt", *output, padded_input_len);

    *output_len = padded_input_len;

    free(padded_input);
    mbedtls_aes_free(&aes);
}

void decrypt_string(const unsigned char *input, size_t input_len, const char *key, const char *iv, char **output, size_t *output_len)
{
    unsigned char sha1_key[20];
    calculate_sha1((const unsigned char *)key, strlen(key), sha1_key);
    // ESP_LOG_BUFFER_HEX("SHA1 KEY", sha1_key, 20);

    unsigned char md5_iv[16];
    calculate_md5((const unsigned char *)iv, strlen(iv), md5_iv);
    // ESP_LOG_BUFFER_HEX("MD5 IV", md5_iv, 16);

    unsigned char *decrypt_output = (unsigned char *)malloc(input_len);
    if (!decrypt_output)
    {
        printf("[decrypt_string] Failed to allocate memory\n");
        return;
    }

    mbedtls_aes_context aes;
    mbedtls_aes_init(&aes);
    mbedtls_aes_setkey_dec(&aes, sha1_key, 256);
    mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_DECRYPT, input_len, md5_iv, input, decrypt_output);
    // ESP_LOG_BUFFER_HEX("cbc_decrypt", decrypt_output, input_len);

    // Remove PKCS#5 padding
    uint8_t padding_value = decrypt_output[input_len - 1];
    if (padding_value > 16)
    {
        printf("[decrypt_string] Invalid padding value\n");
        free(decrypt_output);
        return;
    }
    *output_len = input_len - padding_value;
    *output = (char *)malloc(*output_len + 1); // +1 for null terminator
    if (!(*output))
    {
        printf("[decrypt_string] Failed to allocate memory for output\n");
        free(decrypt_output);
        return;
    }
    memcpy(*output, decrypt_output, *output_len);
    (*output)[*output_len] = '\0'; // Null-terminate the output string

    free(decrypt_output);
    mbedtls_aes_free(&aes);
}

void app_main(void)
{
    printf(">>> Teste de Criptografia! <<<\n\n");

    int64_t count = 0;
    char msg[] = "Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum.";
    char enc_key[] = "minha senha secreta";
    while (1)
    {
        vTaskDelay(pdMS_TO_TICKS(5000));

        char enc_iv[60] = {0};
        sprintf(enc_iv, "nome do modulo(%lld)", count);
        printf("%s    ***IV: (%s)***\n", C_WHT, enc_iv);

        unsigned char *encrypted_msg = NULL;
        size_t encrypted_len = 0;

        // Encrypt the message
        encrypt_string(msg, enc_key, enc_iv, &encrypted_msg, &encrypted_len);
        // printf("Encrypt message: (%s)\n", encrypted_msg);
        printf("%sEncrypt message: [%d](", count % 2 ? C_MAG : C_CYN, encrypted_len);
        for (int i = 0; i < encrypted_len; i++)
        {
            printf("%02x", encrypted_msg[i]);
        }
        printf(")[%02x]\n\n", encrypted_msg[encrypted_len - 1]);

        // Prepare to decrypt the message
        char *decrypted_msg = NULL;
        size_t decrypted_len = 0;

        // Decrypt the message
        decrypt_string(encrypted_msg, encrypted_len, enc_key, enc_iv, &decrypted_msg, &decrypted_len);
        printf("Decrypted message: [%d](%s)[%c]\n\n\n", decrypted_len, decrypted_msg, decrypted_msg[decrypted_len - 1]);

        // Clean up
        if (encrypted_msg)
        {
            free(encrypted_msg);
        }
        if (decrypted_msg)
        {
            free(decrypted_msg);
        }

        count++;
    }
}
