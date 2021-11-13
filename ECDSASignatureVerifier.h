/*   2log.io
 *   Copyright (C) 2021 - 2log.io | mail@2log.io,  sascha@2log.io
 *
 *   This program is free software: you can redistribute it and/or modify
 *   it under the terms of the GNU Affero General Public License as published by
 *   the Free Software Foundation, either version 3 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU Affero General Public License for more details.
 *
 *   You should have received a copy of the GNU Affero General Public License
 *   along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef ECDSASIGNATUREVERIFIER_H
#define ECDSASIGNATUREVERIFIER_H

#include "SignatureVerifier.h"

extern "C"
{
    #include "mbedtls/ecdsa.h"
}

#define IDFIX_ERR_CRYPTO_WRONG_KEY      -1
#define IDFIX_ERR_CRYPTO_SUCCESS        0

namespace IDFix
{
    namespace Crypto
    {
        /**
         * @brief The ECDSASignatureVerifier class provides an implementation of the SignatureVerifier interface
         *          to verify an ECDSA (Elliptic Curve Digital Signature Algorithm) signature.
         */
        class ECDSASignatureVerifier : public SignatureVerifier
        {
            public:

                virtual         ~ECDSASignatureVerifier();

                /**
                 * @brief Set the public key to use for verification
                 * @param pubKey    the PublicKey to use
                 *
                 * @return          \c IDFIX_ERR_CRYPTO_SUCCESS on success
                 * @return          \c IDFIX_ERR_CRYPTO_WRONG_KEY if key is not an elliptic curve key
                 */
                virtual int     setPublicKey(PublicKey* pubKey) override;

                /**
                 * @brief Verify a message hash against a signature.
                 * @param hash              The message hash that was signed. This must be a readable
                 *                          buffer of length \p hashLength Bytes.
                 * @param hashLength        The size of the hash \p hash.
                 * @param signature         The signature to read and verify. This must be a readable
                 *                          buffer of length \p signatureLength bytes.
                 * @param signatureLength   The size of \p signature in bytes.
                 *
                 * @return          \c 0 on success.
                 * @return          \c MBEDTLS_ERR_ECP_BAD_INPUT_DATA if signature is invalid.
                 * @return          \c MBEDTLS_ERR_ECP_SIG_LEN_MISMATCH if there is a valid
                 *                  signature in \p signature, but its length is less than \p signatureLength.
                 * @return          An \c MBEDTLS_ERR_ECP_XXX or \c MBEDTLS_ERR_MPI_XXX
                 *                  error code on failure for any other reason.
                 */
                virtual int     verify(const unsigned char* hash, size_t hashLength, const unsigned char *signature, size_t signatureLength) override;

            protected:

                mbedtls_ecdsa_context *_ecdsaContext;
        };



    }
}

#endif // ECDSASIGNATUREVERIFIER_H
