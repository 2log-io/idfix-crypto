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

#include "PublicKey.h"

namespace IDFix
{
    namespace Crypto
    {

        PublicKey::PublicKey()
        {

        }

        PublicKey::~PublicKey()
        {
            mbedtls_pk_free(&_publicKeyContext);
        }

        int PublicKey::parseKey(const unsigned char *key, size_t keylen)
        {
            if ( _publicKeyContext.pk_ctx != nullptr || _publicKeyContext.pk_info != nullptr )
            {
                mbedtls_pk_free(&_publicKeyContext);
            }

            mbedtls_pk_init(&_publicKeyContext);

            return mbedtls_pk_parse_public_key(&_publicKeyContext, key, keylen );
        }

        mbedtls_pk_type_t PublicKey::getType() const
        {
            return mbedtls_pk_get_type( &_publicKeyContext );
        }

        const mbedtls_pk_context *PublicKey::getContext()
        {
            if ( _publicKeyContext.pk_ctx != nullptr || _publicKeyContext.pk_info != nullptr )
            {
                return &_publicKeyContext;
            }

            return nullptr;
        }

    }
}
