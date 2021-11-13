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

#include "ECDSASignatureVerifier.h"

#include "PublicKey.h"

namespace IDFix
{
    namespace Crypto
    {
        ECDSASignatureVerifier::~ECDSASignatureVerifier()
        {

        }

        int ECDSASignatureVerifier::setPublicKey(PublicKey *pubKey)
        {
            if ( pubKey->getType() != MBEDTLS_PK_ECKEY )
            {
                return IDFIX_ERR_CRYPTO_WRONG_KEY;
            }

            _ecdsaContext =  mbedtls_pk_ec( *( pubKey->getContext() ) );

            return IDFIX_ERR_CRYPTO_SUCCESS;
        }

        int ECDSASignatureVerifier::verify(const unsigned char *hash, size_t hashLength, const unsigned char *signature, size_t signatureLength)
        {
            return mbedtls_ecdsa_read_signature(_ecdsaContext, hash, hashLength, signature, signatureLength);
        }
    }
}
