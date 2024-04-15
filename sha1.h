#ifndef CSCI4230_SHA1_H
#define CSCI4230_SHA1_H

#include <cstddef>
#include <cstdint>

/* Size of a SHA-1 block (in bytes). */
#define SHA1_BLOCK_SIZE 64

/* Size of a SHA-1 digest (in bytes). */
#define SHA1_DIGEST_SIZE 20

/* Stores the context of one SHA-1 operation. Must be reset after each use. */
struct sha1_context {
  /* The working hash value. */
  std::uint32_t state[SHA1_DIGEST_SIZE / sizeof(std::uint32_t)];

  /* The number of bytes that have already been processed. */
  std::uint64_t len;

  /* The block currently being filled. */
  std::uint8_t block[SHA1_BLOCK_SIZE];

  /* An index pointing to the current end of data in `block`. */
  unsigned int block_idx;
};

/* Initialize/reset a SHA-1 context. */
void sha1_reset(sha1_context *p_ctx);

/* Update a context with `len` bytes from `data`. */
void sha1_update(sha1_context *p_ctx, const void *data, std::size_t len);

/* Compute the final hash value and write it to `digest`. */
void sha1_finalize(sha1_context *p_ctx, void *digest);

/* Compute the SHA-1 hash of `data` (`len` bytes long) and write it to `digest`
  (must be at least 20 bytes) in the form of a 20-byte big-endian value. */
void sha1(const void *data, std::size_t len, void *digest);

#endif
