/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * A copy of the License is located at
 *
 *  http://aws.amazon.com/apache2.0
 *
 * or in the "license" file accompanying this file. This file is distributed
 * on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

#include "crypto/s2n_openssl.h"
#include "pq-crypto/s2n_pq.h"
#include "s2n_test.h"

int main()
{
    BEGIN_TEST();
    if (s2n_libcrypto_is_awslc() && s2n_pq_is_enabled()) {
        EXPECT_TRUE(s2n_libcrypto_supports_kyber_512());
    } else {
        EXPECT_FALSE(s2n_libcrypto_supports_kyber_512());
    }
    END_TEST();
}
