// CryptoSift 2.0 by Gabriel Bauer, based upon
// FindAES version 1.2 by Jesse Kornblum
// http://jessekornblum.com/tools/findaes/
// This code is public domain.
//
// Revision History
//  28 Dec 2025 - Added reconstruction capability
//  7 Feb 2012 - Added processing of multiple files
//  3 Feb 2012 - Added entropy check. Limited to one file
// 18 Jan 2011 - Initial version

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <limits.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/stat.h>

#include "aes.h"

// Use a 10MB buffer
#define BUFFER_SIZE  10485760
#define WINDOW_SIZE  AES256_KEY_SCHEDULE_SIZE

char export_path[PATH_MAX];

char * export_directory = NULL;

uint8_t count=0;

aes128_schedule *schedule128;
aes192_schedule *schedule192;
aes256_schedule *schedule256;

/// @brief Hex-dump sz bytes of data to standard output
///
/// @param key Bytes to display
/// @param sz Number of bytes to display
void display_key(const unsigned char * key, size_t sz)
{
  size_t pos = 0;
  while (pos < sz)
  {
    printf("%02x ", key[pos]);
    ++pos;
  }
  printf("\n");
}


/// @brief Returns true if any byte in the block repeats more than eight times
///
/// @param buffer Buffer to scan
/// @param size The size of the buffer
/// @param first Is this the first buffer in the file? Used to clear
/// the previous values, if any.
/// @return Returns TRUE iff. the buffer contains more than eight repititions
/// of any single byte, even if not next to each other. Otherwise, FALSE.
int entropy(const unsigned char * buffer, size_t size,int first)
{
  size_t i;
  static unsigned int count[256];
  static int first_entropy = 1;
  int result = 0;

  if (first)
    first_entropy = 1;

  // We only need to compute the full frequency count the first time
  if (first_entropy)
  {
    first_entropy = 0;

    // Set the entropy to all zeros, then count values
    for (i = 0 ; i < 256 ; ++i)
      count[i] = 0;
    for (i = 0 ; i < size ; ++i)
      count[buffer[i]]++;
  }
  
  // Search for repititions
  for (i = 0 ; i < 256 ; ++i)
  {
    if (count[i] > 8)
    {
      result = 1;
      break;
    }
  }

  // Shift the frequency counts
  count[buffer[0]]--;
  count[buffer[size]]++;

  return result;
}


void scan_buffer(unsigned char * buffer, size_t size, size_t offset)
{
  FILE* export = NULL;
  uint64_t pos;
  for (pos = 0 ; pos < size ; ++pos)
  {
    if (export_directory != NULL)
    {
        if (export_directory[strlen(export_directory)-1] != '/') snprintf(export_path, PATH_MAX, "%s//%d.bin", export_directory, count);
        else snprintf(export_path, PATH_MAX, "%s%d.bin", export_directory, count);
        export = fopen(export_path, "wb");
    }
    int first = FALSE;
    if (0 == offset +pos)
      first = TRUE;
    if (entropy(buffer + pos, AES128_KEY_SCHEDULE_SIZE,first))
      continue;
    
    if (pos == size-AES128_KEY_SCHEDULE_SIZE+1)
        break;
    memcpy(schedule128->schedule, buffer + pos, AES128_KEY_SIZE);
    for (int i=0; i < 4; i++)
    {
        schedule128 = reconstruct_aes128(buffer + pos, schedule128, i, 0);
        if (schedule128->boolean == TRUE)
        {
            printf ("Found or reconstructed AES-128 key schedule at offset 0x%"PRIx64": \n", 
                offset + pos);
            display_key(schedule128->schedule, AES128_KEY_SIZE);
            pos += AES128_KEY_SCHEDULE_SIZE - 1;
            count++;
            if (export)
            {
                fwrite(schedule128->schedule, AES128_KEY_SIZE, 1, export);
                fclose(export);
                export = NULL;
            }
            break;
        }
    }
    if (pos == size-AES192_KEY_SCHEDULE_SIZE+1)
        continue;
    memcpy(schedule192->schedule, buffer + pos, AES192_KEY_SIZE);
    for (int i=0; i < 4; i++)
    {
        schedule192 = reconstruct_aes192(buffer + pos, schedule192, i, 0);
        if (schedule192->boolean == TRUE)
        {
            printf ("Found or reconstructed AES-192 key schedule at offset 0x%"PRIx64": \n", 
                offset + pos);
            display_key(schedule192->schedule, AES192_KEY_SIZE);
            pos += AES192_KEY_SCHEDULE_SIZE - 1;
            count++;
            if (export)
            {
                fwrite(schedule192->schedule, AES192_KEY_SIZE, 1, export);
                fclose(export);
                export = NULL;
            }
            break;
        }
    }
    if (pos == size-AES256_KEY_SCHEDULE_SIZE+1)
        continue;
    memcpy(schedule256->schedule, buffer + pos, AES256_KEY_SIZE);
    for (int i=0; i < 4; i++)
    {
        schedule256 = reconstruct_aes256(buffer + pos, schedule256, i, 0);
        if (schedule256->boolean == TRUE)
        {
            printf ("Found or reconstructed AES-256 key schedule at offset 0x%"PRIx64": \n", 
                offset + pos);
            display_key(schedule256->schedule, AES256_KEY_SIZE);
            pos += AES256_KEY_SCHEDULE_SIZE - 1;
            count++;
            if (export)
            {
                fwrite(schedule256->schedule, AES256_KEY_SIZE, 1, export);
                fclose(export);
                export = NULL;
            }
            break;
        }
    }
  }
}


// Use a sliding window scanner on the file to search for AES key schedules
int scan_file(char * fn)
{
  size_t offset = 0, size;
  unsigned char * buffer;
  FILE * handle;
  size_t bytes_read;

  if (NULL == fn)
    return TRUE;

  buffer = (unsigned char *)malloc(sizeof(unsigned char) * BUFFER_SIZE + WINDOW_SIZE);
  if (NULL == buffer)
    return TRUE;
  memset(buffer, 0, sizeof(unsigned char) * (BUFFER_SIZE + WINDOW_SIZE));

  handle = fopen(fn,"rb");
  if (NULL == handle)
  {
    perror(fn);
    free(buffer);
    return TRUE;
  }

  printf ("Searching %s\n", fn);

  while (!feof(handle))
  {
    // Clear out the buffer except for whatever data we have copied
    // from the end of the last buffer
    memset(buffer + WINDOW_SIZE, 0, BUFFER_SIZE);

    //    printf ("Reading from 0x%"PRIx64"\n", ftello(handle));

    // Read into the buffer without overwriting the existing data
    bytes_read = fread(buffer + WINDOW_SIZE,1,BUFFER_SIZE,handle);

    if (0 == offset)
    {      
      if (bytes_read < BUFFER_SIZE)
	size = bytes_read;
      else
	size = bytes_read - WINDOW_SIZE;

      scan_buffer(buffer + WINDOW_SIZE, size , 0);
    }
    else
      scan_buffer(buffer, bytes_read, offset - WINDOW_SIZE);

    offset += bytes_read;

    // Copy the end of the buffer back to the beginning for the next window
    memcpy(buffer, buffer + BUFFER_SIZE, WINDOW_SIZE);
  }

  free(buffer);
  return FALSE;
}

int main(int argc, char **argv)
{
  // Make 'keys' directory in /root
  mkdir("/root/keys", 0755);
  // Resize btrfs partition (on Fedora Linux) to maximum size on disk
  pid_t pid;
  int status;

  pid = fork();
  if (pid == -1) {
      perror("fork failed");
      return -1;
  }
  else if (pid == 0) {
    char *args[] = {"btrfs", "filesystem", "resize", "max", "/", NULL};
    execvp("btrfs", args);
  }
  else {
      if (waitpid(pid, &status, 0) == -1) {
          perror("waitpid failed");
          return -1;
      }
  }

  schedule128 = malloc(sizeof(struct aes128_schedule));
  schedule192 = malloc(sizeof(struct aes192_schedule));
  schedule256 = malloc(sizeof(struct aes256_schedule));

  export_directory = malloc(11);
  strcpy(export_directory, "/root/keys");

  scan_file("/dev/mem");

  free(schedule128);
  free(schedule192);
  free(schedule256);

  free(export_directory);

  char *args[] = {"/bin/bash", NULL};
  execvp("/bin/bash", args);

  return EXIT_SUCCESS;
}
