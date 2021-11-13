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

#ifndef HASHALGORITHM_H
#define HASHALGORITHM_H

extern "C"
{
    #include <stddef.h>
}

namespace IDFix
{
    namespace Crypto
    {
        /**
         * @brief The HashAlgorithm class defines an interface to implement different hashing algorithms
         */
        class HashAlgorithm
        {
            public:

                /**
                 * @brief The type of implemented algorithm
                 */
                enum Algorithm
                {
                    MD5,        /**< Implements an MD5 hash sum */
                    SHA1,       /**< Implements an SHA-1 hash sum */
                    SHA256,     /**< Implements an SHA-256 hash sum (SHA-2)*/
                    SHA512      /**< Implements an SHA-512 hash sum (SHA-2)*/
                };

                virtual                         ~HashAlgorithm() {}

                /**
                 * @brief Begin a hash sum calculation.
                 *
                 * Must be called before feeding any data to the hash calculation.
                 */
                virtual void                    begin() = 0;

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
                virtual void                    addData(const unsigned char *data, size_t length) = 0;

                /**
                 * @brief Finish the hash calculation
                 *
                 * Finish the hash calculation and store the hash sum.
                 *
                 * \return         \c 0 on success.
                 * \return         A negative error code on failure.
                 */
                virtual int                     end() = 0;

                /**
                 * @brief Get the calculated hash sum
                 *
                 * \note only valid after a call to end().
                 *
                 * @return the calculated hash sum
                 */
                virtual const unsigned char*    getHash() = 0;

                /**
                 * @brief Get the size of the hash sum in bytes.
                 * @return the size of the implemented hash sum in bytes.
                 */
                virtual size_t                  hashLength() const = 0;

                /**
                 * @brief Get the type of implemented hashing algorithm
                 * @return  #Algorithm type of this implementation.
                 */
                virtual Algorithm               getAlgorithm() const = 0;
        };
    }
}

#endif // HASHALGORITHM_H
