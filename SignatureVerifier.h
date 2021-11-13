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

#ifndef SIGNATUREVERIFIER_H
#define SIGNATUREVERIFIER_H

extern "C"
{
    #include <stddef.h>
}

namespace IDFix
{
    namespace Crypto
    {
        class PublicKey;

        /**
         * @brief The SignatureVerifier class defines an interface to verify signatures of different types.
         */
        class SignatureVerifier
        {
            public:

                virtual         ~SignatureVerifier();

                /**
                 * @brief Set the public key to use for verification
                 * @param pubKey    the PublicKey to use
                 *
                 * @return          \c 0 on success; error code otherwise
                 */
                virtual int     setPublicKey(PublicKey* pubKey) = 0;

                /**
                 * @brief Verify a message hash against a signature.
                 * @param hash              The message hash that was signed. This must be a readable
                 *                          buffer of length \p hashLength Bytes.
                 * @param hashLength        The size of the hash \p hash.
                 * @param signature         The signature to read and verify. This must be a readable
                 *                          buffer of length \p signatureLength bytes.
                 * @param signatureLength   The size of \p signature in bytes.
                 *
                 * @return          \c 0 on success; error code otherwise.
                 */
                virtual int     verify(const unsigned char* hash, size_t hashLength, const unsigned char *signature, size_t signatureLength) = 0;
        };
    }
}

#endif // SIGNATUREVERIFIER_H
