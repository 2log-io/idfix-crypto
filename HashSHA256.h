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

#ifndef HASHSHA256_H
#define HASHSHA256_H

extern "C"
{
    #include "mbedtls/sha256.h"
}

#include "HashAlgorithm.h"

namespace IDFix
{
    namespace Crypto
    {
        /**
         * @brief The HashSHA256 class implements the HashAlgorithm interface to calculate a SHA-256 hash sum.
         */
        class HashSHA256 : public HashAlgorithm
        {
            public:

                                                HashSHA256();
                virtual                         ~HashSHA256();

                /**
                 * @brief Begin the SHA-256 hash calculation.
                 *
                 * Must be called before feeding any data to the hash calculation.
                 */
                virtual void                    begin() override;

                /**
                 * @brief Feed (partial) data to an ongoing hash calculation.
                 *
                 * This function can be called to continuously feed (partial) data to the
                 * hash calculation.
                 *
                 * @param data      The buffer holding the data. This must be a readable
                 *                  buffer of length \p length bytes.
                 * @param length    The length of the input data in bytes.
                 */
                virtual void                    addData(const unsigned char *data, size_t length) override;

                /**
                 * @brief Finish the hash calculation
                 *
                 * Finish the hash calculation and store the hash sum.
                 *
                 * \return         \c 0 on success.
                 * \return         A negative error code on failure.
                 */
                virtual int                     end() override;

                /**
                 * @brief Get the calculated hash sum
                 *
                 * \note only valid after a call to end().
                 *
                 * @return the calculated hash sum
                 */
                virtual const unsigned char*    getHash() override;

                /**
                 * @brief Get the size of the SHA-256 hash sum in bytes.
                 * @return \c 32 - the size of the SHA-256 hash sum in bytes.
                 */
                virtual size_t                  hashLength() const override;

                /**
                 * @brief Get the type of implemented hashing algorithm
                 * @return  \c Algorithm::SHA256
                 */
                virtual Algorithm               getAlgorithm() const override;

            protected:

                unsigned char           _hash[32];
                mbedtls_sha256_context* _sha256Context = { nullptr };
        };
    }
}

#endif // HASHSHA256_H
