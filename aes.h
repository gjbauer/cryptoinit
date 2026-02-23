#ifndef __AES_H
#define __AES_H

/// Size of a 128-bit AES key, in bytes
#define AES128_KEY_SIZE                  16
/// Size of a 192-bit AES key, in bytes
#define AES192_KEY_SIZE                  24
/// Size of a 256-bit AES key, in bytes
#define AES256_KEY_SIZE                  32

/// Size of a 128-bit AES key schedule, in bytes
#define AES128_KEY_SCHEDULE_SIZE        176
/// Size of a 128-bit AES key schedule, in bytes
#define AES192_KEY_SCHEDULE_SIZE        208
/// Size of a 128-bit AES key schedule, in bytes
#define AES256_KEY_SCHEDULE_SIZE        240

#define FALSE 0
#define TRUE  1

typedef struct aes128_schedule
{
    unsigned char schedule[AES128_KEY_SCHEDULE_SIZE];
    int boolean;
} aes128_schedule;

typedef struct aes192_schedule
{
    unsigned char schedule[AES192_KEY_SCHEDULE_SIZE];
    int boolean;
} aes192_schedule;

typedef struct aes256_schedule
{
    unsigned char schedule[AES256_KEY_SCHEDULE_SIZE];
    int boolean;
} aes256_schedule;

// Determines whether or not data represents valid
// AES key schedules. In reality, this is very efficient code for 
// finding blocks of data that are NOT AES key schedules.
//
// Because we are going to encounter blocks of data that are not
// valid key schedules far more often than not, these functions
// have been optimized to find values that are not key schedules.
//
// Returns TRUE if 'computed' is a valid 128-bit AES key schedule, otherwise FALSE
int valid_aes128_schedule(const unsigned char * in, unsigned char computed[AES128_KEY_SCHEDULE_SIZE]);
int valid_aes192_schedule(const unsigned char * in, unsigned char computed[AES192_KEY_SCHEDULE_SIZE]);
int valid_aes256_schedule(const unsigned char * in, unsigned char computed[AES256_KEY_SCHEDULE_SIZE]);

aes128_schedule* reconstruct_aes128(const unsigned char * in, aes128_schedule* schedule, int bits, int pos);
aes192_schedule* reconstruct_aes192(const unsigned char * in, aes192_schedule* schedule, int bits, int pos);
aes256_schedule* reconstruct_aes256(const unsigned char * in, aes256_schedule* schedule, int bits, int pos);

#endif   // ifndef __AES_H

