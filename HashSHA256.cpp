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

#include "HashSHA256.h"



namespace IDFix
{
    namespace Crypto
    {
        HashSHA256::HashSHA256()
        {

        }

        HashSHA256::~HashSHA256()
        {
            if ( _sha256Context != nullptr )
            {
                delete _sha256Context;
            }
        }

        void HashSHA256::begin()
        {
            if ( _sha256Context != nullptr )
            {
                delete _sha256Context;
            }

            _sha256Context = new mbedtls_sha256_context;
            mbedtls_sha256_init(_sha256Context);

            mbedtls_sha256_starts_ret(_sha256Context, 0 /* SHA-256, not 224 */ );
        }

        void HashSHA256::addData(const unsigned char *data, size_t length)
        {
            mbedtls_sha256_update_ret(_sha256Context, data, length );
        }

        int HashSHA256::end()
        {
            int result = mbedtls_sha256_finish_ret(_sha256Context, _hash);

            delete _sha256Context;
            _sha256Context = nullptr;

            return result;
        }

        const unsigned char *HashSHA256::getHash()
        {
            return _hash;
        }

        size_t HashSHA256::hashLength() const
        {
            return 32;
        }

        HashAlgorithm::Algorithm HashSHA256::getAlgorithm() const
        {
            return SHA256;
        }
    }
}


