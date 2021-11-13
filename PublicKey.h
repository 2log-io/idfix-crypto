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

#ifndef PUBLICKEY_H
#define PUBLICKEY_H

extern "C"
{
    #include "mbedtls/pk.h"
}


namespace IDFix
{
    namespace Crypto
    {
        /**
         * @brief The PublicKey class provides a convienient interface for a public key
         */
        class PublicKey
        {
            public:

                                            PublicKey();
                virtual                     ~PublicKey();

                /**
                * @brief parseKey       Parse a public key in PEM or DER format
                *
                * @param key            Input buffer to parse.
                *                       The buffer must contain the input exactly, with no
                *                       extra trailing material. For PEM, the buffer must
                *                       contain a null-terminated string.
                * @param keylen         Size of \b key in bytes.
                *                       For PEM data, this includes the terminating null byte,
                *                       so \p keylen must be equal to `strlen(key) + 1`.
                *
                * @return               0 if successful, or a specific PK or PEM error code
                */
                int                         parseKey(const unsigned char *key, size_t keylen);

                /**
                 * @brief Get the key type
                 *
                 * \return          Type on success.
                 * \return          \c MBEDTLS_PK_NONE for an unitialized key
                 */
                mbedtls_pk_type_t           getType() const;

                /**
                 * @brief Get the \c mbedtls_pk_context for this key
                 *
                 * @return initialized \c mbedtls_pk_context for this key
                 * @return \c nullptr for an unitialized key
                 */
                const mbedtls_pk_context*   getContext();

            protected:

                mbedtls_pk_context  _publicKeyContext = {};
        };
    }
}

#endif // PUBLICKEY_H
