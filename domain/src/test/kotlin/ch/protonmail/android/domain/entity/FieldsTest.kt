/*
 * Copyright (c) 2020 Proton Technologies AG
 * 
 * This file is part of ProtonMail.
 * 
 * ProtonMail is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * ProtonMail is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with ProtonMail. If not, see https://www.gnu.org/licenses/.
 */
package ch.protonmail.android.domain.entity

import assert4k.*
import kotlin.test.Test

/**
 * Test suite for [EmailAddress]
 * @author Davide Farella
 */
internal class FieldsTest {

    @Test
    fun `verify happy paths`() {
        listOf(
            "somebody@protonmail.com",
            "mail@4cafe.diostu",
            "davide@proton.me",
            "hello@email.it"
        ).map { EmailAddress(it) }
    }

    @Test
    fun `verify failing paths`() {
        assert that fails<ValidationException> {
            EmailAddress("@hello.com")
        }
        assert that fails<ValidationException> {
            EmailAddress("hello.com")
        }
        assert that fails<ValidationException> {
            EmailAddress("hello@com")
        }
        assert that fails<ValidationException> {
            EmailAddress("hello@.com")
        }
        assert that fails<ValidationException> {
            EmailAddress("hello@-.com")
        }
    }
}
