#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include "jwt.h"
#include <time.h>
#include <openssl/hmac.h>
void base64url_encode(const unsigned char *input,int len,char *output)
{
   int outlen = EVP_EncodeBlock((unsigned char *)output,input,len);

   for(int i = 0;i<outlen;i++)
   {
      if (output[i]=='+')
      {
         output[i]='-';
      }
      else if (output[i]=='/')
      {
         output[i]='_';
      }
   }

   while(outlen>0 && output[outlen-1]=='=')
   {
        outlen -= 1;
   }
   output[outlen]='\0';
}
void create_jwt(const char *username,char *jwt,int jwt_size)
{
   char payload[256];
   unsigned char hash[EVP_MAX_MD_SIZE];
   unsigned int hash_len;
   char header[] = "{\"alg\":\"HS256\",\"typ\":\"JWT\"}";
   char signing_input[512];
   char signature64[256];
   time_t iat = time(NULL);
   time_t exp = iat + 100;
   sprintf(payload,
        "{\"user\":\"%s\",\"iat\":%ld,\"exp\":%ld}",
        username,
        (long)iat,
        (long)exp);

   char header64[256];
   char payload64[256];

   base64url_encode(
      (unsigned char*)header,
      strlen(header),
      header64);

   base64url_encode(
      (unsigned char*)payload,
      strlen(payload),
      payload64);  
   
   snprintf(signing_input,
         sizeof(signing_input),
         "%s.%s",
         header64,
         payload64); 

   HMAC(EVP_sha256(),
        JWT_SECRET,
        strlen(JWT_SECRET),
        (unsigned char*)signing_input,
        strlen(signing_input),
        hash,
        &hash_len);

   base64url_encode(hash,
                 hash_len,
                 signature64);

   snprintf(jwt,
            jwt_size,
            "%s.%s.%s",
            header64,
            payload64,
            signature64);
}
bool split_jwt(const char *jwt,char header[256],char payload[512],char signature[256])
{
   char copy[1024];
   strcpy(copy,jwt);

   char *part = strtok(copy,".");

   if (part == NULL)
   {
      return false;
   }
   strcpy(header,part);

   part = strtok(NULL,".");

   if (part == NULL)
   {
      return false;
   }
   strcpy(payload,part);

   part = strtok(NULL,".");

   if (part == NULL)
   {
      return false;
   }

   strcpy(signature,part);

   return true;
}
void base64url_decode(const char *input,
                      unsigned char *output,
                      int *len)
{
    char temp[512];

    strcpy(temp, input);

    for(int i = 0; temp[i]; i++)
    {
        if(temp[i] == '-')
            temp[i] = '+';

        else if(temp[i] == '_')
            temp[i] = '/';
    }

    while(strlen(temp) % 4 != 0)
        strcat(temp, "=");

    *len = EVP_DecodeBlock(output,
                           (unsigned char *)temp,
                           strlen(temp));
}
bool verify_jwt(
        const char *jwt,
        char *username,
        time_t *expiry)
{
    char header[256];
    char payload[512];
    char signature[256];


    if(!split_jwt(jwt,
                  header,
                  payload,
                  signature))
        return false;

    char signing_input[1024];

    snprintf(signing_input,
             sizeof(signing_input),
             "%s.%s",
             header,
             payload);

    unsigned char hash[EVP_MAX_MD_SIZE];

    unsigned int hash_len;

    HMAC(EVP_sha256(),
         JWT_SECRET,
         strlen(JWT_SECRET),
         (unsigned char *)signing_input,
         strlen(signing_input),
         hash,
         &hash_len);

    char expected[256];

    base64url_encode(hash,
                     hash_len,
                     expected);

    if(strcmp(expected,
              signature) != 0)
        return false;

    unsigned char decoded[512];

    int len;

    base64url_decode(payload,
                     decoded,
                     &len);

    decoded[len] = '\0';
    time_t issued;
    sscanf((char *)decoded,
        "{\"user\":\"%31[^\"]\",\"iat\":%ld,\"exp\":%ld}",
        username,
        (long *)&issued,
        (long *)expiry);
 
    time_t now = time(NULL);
       
    if(now > *expiry)
    {
        printf("JWT expired\n");
        return false;
    }
     return true;
} 