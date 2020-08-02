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
package ch.protonmail.android.prefs

import android.annotation.SuppressLint
import android.content.Context
import android.content.SharedPreferences
import android.content.res.Configuration
import android.os.Build
import android.preference.PreferenceManager
import android.provider.Settings
import android.security.KeyPairGeneratorSpec
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.text.TextUtils
import android.util.Base64
import ch.protonmail.android.utils.AppUtil
import ch.protonmail.android.utils.Logger
import java.math.BigInteger
import java.security.*
import java.util.*
import javax.crypto.Cipher
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec
import javax.security.auth.x500.X500Principal

// region constants
private const val UTF8 = "UTF-8"
private const val ALGORITHM_AES = "AES"
const val PREF_SYMMETRIC_KEY = "SEKRIT"
// endregion

class SecureSharedPreferences
/**
 * Constructor
 *
 * @param context
 * @param delegate - SharedPreferences object from the system
 */
private constructor(var context: Context, private val delegate: SharedPreferences) : SharedPreferences {

    private val keyPair: KeyPair
    private val keyStoreName = "AndroidKeyStore"
    private val asymmetricKeyAlias = "ProtonMailKey"
    private val saltKeyAlias = "ProtonMailSalt"
    private val KeyProtectedKey = "KeyProtectedKey"

    private var keyStore: KeyStore
    private val secureRandom = SecureRandom()
    private var symmetricSalt32Bytes = ByteArray(32)

    private val defaultSharedPreferences: SharedPreferences = PreferenceManager.getDefaultSharedPreferences(context)

    private var isPassPhraseProtected: Boolean = defaultSharedPreferences.getBoolean(KeyProtectedKey, false)
        get() =
            defaultSharedPreferences.getBoolean(KeyProtectedKey, false)
        set(value) {
            field = value
            defaultSharedPreferences.edit().putBoolean(KeyProtectedKey, value).commit()
        }

    private val SEKRIT: MutableList<ByteArray> by lazy {
        var keyPair = retrieveAsymmetricKeyPair(asymmetricKeyAlias)
        if (keyPair == null) {
            keyPair = generateKeyPair(context, asymmetricKeyAlias)
        }

        var symmetricKey = if (isPassPhraseProtected) {
            decryptAsymmetric(decryptWithPassPhraseString(
                    defaultSharedPreferences.getString(PREF_SYMMETRIC_KEY, ""), "123456"),
                    keyPair.private)
        } else {
            decryptAsymmetric(defaultSharedPreferences.getString(PREF_SYMMETRIC_KEY, "")!!, keyPair.private)
        }

        when (symmetricKey) {
            null -> { // error decrypting, we lost the key
                symmetricKey = UUID.randomUUID().toString()
                defaultSharedPreferences.edit().putString(PREF_SYMMETRIC_KEY,
                        encryptWithPassPhraseString(encryptAsymmetric(symmetricKey, keyPair.public), "123456")
                ).apply()
                isPassPhraseProtected = true
                AppUtil.deletePrefs() // force re-login
                // don't call ProtonMailApplication#notifyLoggedOut because UserManager is needed for that
                // and it can't be properly instantiated because of this error here
            }
            "" -> { // no previous key stored
                symmetricKey = UUID.randomUUID().toString()
                defaultSharedPreferences.edit().putString(PREF_SYMMETRIC_KEY,
                        encryptWithPassPhraseString(encryptAsymmetric(symmetricKey, keyPair.public), "123456")
                ).apply()
                isPassPhraseProtected = true
                migrateToKeyStore(symmetricKey.toByteArray())
            }

            // else successfuly decrypted secret key
        }


        return@lazy mutableListOf(symmetricKey!!.toByteArray())
    }

    init {
        keyStore = KeyStore.getInstance(keyStoreName)
        keyStore.load(null)

        val keyPairOptional = retrieveAsymmetricKeyPair(asymmetricKeyAlias)
        keyPair = keyPairOptional ?: generateKeyPair(context, asymmetricKeyAlias)

        initSymmetricSalt()

        migrateSEKRITPassPhrase("123456")

        println(">>>> isCorrect " + verifyPassPhraseCorrect("223456"))

    }

    fun verifyPassPhraseCorrect(passPhrase: String): Boolean {
        try {
            decryptWithPassPhraseString(
                    defaultSharedPreferences.getString(PREF_SYMMETRIC_KEY, ""), passPhrase)
        } catch (e: Exception) {
            return false
        }
        return true
    }

    fun migrateSEKRITPassPhrase(passPhrase: String) {
        if (isPassPhraseProtected) {
            return
        }
        defaultSharedPreferences.edit().putString(PREF_SYMMETRIC_KEY,
                encryptWithPassPhraseString(encryptAsymmetric(String(SEKRIT[0]), keyPair.public), passPhrase)
        ).apply()
        println(">>>> migrate done")
        isPassPhraseProtected = true
    }

    fun encryptWithPassPhraseString(plainText: String, passPhrase: String): String {
        val cipherBytes = encryptWithPassPhrase(plainText.toByteArray(), passPhrase)
        return Base64.encodeToString(cipherBytes, Base64.NO_WRAP)
    }

    fun decryptWithPassPhraseString(cipherTextB64: String, passPhrase: String): String {
        val cipherBytes = Base64.decode(cipherTextB64, Base64.NO_WRAP)
        val plainBytes = decryptWithPassPhrase(cipherBytes, passPhrase)
        return String(plainBytes)
    }

    fun encryptWithPassPhrase(plainBytes: ByteArray, passPhrase: String): ByteArray {

        val passPhraseKey = digestPassPhrase(passPhrase)

        val spec = SecretKeySpec(passPhraseKey, "AES")
        val pbeCipher = Cipher.getInstance(ALGORITHM_AES)
        pbeCipher.init(Cipher.ENCRYPT_MODE, spec)
        return pbeCipher.doFinal(plainBytes)
    }

    fun decryptWithPassPhrase(cipherBytes: ByteArray, passPhrase: String): ByteArray {
        val passPhraseKey = digestPassPhrase(passPhrase)

        val spec = SecretKeySpec(passPhraseKey, "AES")
        val pbeCipher = Cipher.getInstance(ALGORITHM_AES)
        pbeCipher.init(Cipher.DECRYPT_MODE, spec)
        return pbeCipher.doFinal(cipherBytes)
    }

    private fun initSymmetricSalt() {
        val byte32 = ByteArray(32)


        val rsaDecCipherDecrypt = Cipher.getInstance("RSA/ECB/PKCS1Padding").apply {
            init(Cipher.DECRYPT_MODE, keyPair.private)
        }

        if (defaultSharedPreferences.contains(saltKeyAlias)) {
            val salt = defaultSharedPreferences.getString(saltKeyAlias, "")
            val saltBytes = Base64.decode(salt, Base64.NO_PADDING)

            symmetricSalt32Bytes = rsaDecCipherDecrypt.doFinal(saltBytes)
            if (symmetricSalt32Bytes.size == 32) {
                return
            }
        }
        defaultSharedPreferences.edit().remove(saltKeyAlias).apply()

        secureRandom.nextBytes(byte32)

        val rsaEncCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding").apply {
            init(Cipher.ENCRYPT_MODE, keyPair.public)
        }

        symmetricSalt32Bytes = byte32

        val saltEncoded = Base64.encodeToString(rsaEncCipher.doFinal(symmetricSalt32Bytes), Base64.NO_PADDING)
        defaultSharedPreferences.edit().putString(saltKeyAlias, saltEncoded).apply()

    }

    private fun digestPassPhrase(passPhrase: String): ByteArray {
        val secretKeyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1")
        val spec = PBEKeySpec(passPhrase.toCharArray(), symmetricSalt32Bytes, 40000, 256)
        val secret = secretKeyFactory.generateSecret(spec)
        return secret.encoded
    }

    private fun migrateToKeyStore(newSEKRIT: ByteArray) {

        // old code for getting encryption key
        var secretKey: String? =
                Settings.Secure.getString(context.contentResolver, Settings.Secure.ANDROID_ID)
        if (TextUtils.isEmpty(secretKey)) {
            secretKey = delegate.getString("AUIDSP", null)
            if (TextUtils.isEmpty(secretKey)) {
                secretKey = UUID.randomUUID().toString()
                delegate.edit().putString("AUIDSP", secretKey).apply()
            }
            SEKRIT.removeAt(0)
            SEKRIT.add(secretKey!!.toByteArray())
        } else {
            SEKRIT.removeAt(0)
            SEKRIT.add(secretKey!!.toByteArray())
        }

        val oldPreferences = mutableMapOf<String, String>()
        val oldPreferencesKeysToRemove = mutableListOf<String>()

        // decrypt old preferences
        delegate.all.forEach {
            val key = decrypt(it.key)
            val value = decrypt(it.value as String)
            if (key != null && value != null) {
                oldPreferences[key] = value
                oldPreferencesKeysToRemove.add(it.key)
            }
        }

        // change current key to new one
        SEKRIT.removeAt(0)
        SEKRIT.add(newSEKRIT)

        // encrypt old preferences with new key
        val newPreferencesEditor = edit()
        oldPreferences.forEach { newPreferencesEditor.putString(it.key, it.value) }
        oldPreferencesKeysToRemove.forEach { newPreferencesEditor.remove(it) }
        newPreferencesEditor.apply()

    }

    override fun edit(): Editor {
        return Editor()
    }

    override fun getAll(): Map<String, *> {
        throw UnsupportedOperationException()
    }

    @Synchronized
    override fun getBoolean(key: String, defValue: Boolean): Boolean {
        //if these weren't encrypted, then it won't be a string
        val v: String?
        try {
            v = delegate.getString(encryptProxyKey(key), null)
        } catch (e: ClassCastException) {
            return delegate.getBoolean(key, defValue)
        }

        return if (v != null) java.lang.Boolean.parseBoolean(decrypt(v)) else defValue
    }

    @Synchronized
    override fun getFloat(key: String, defValue: Float): Float {
        val v: String?
        try {
            v = delegate.getString(encryptProxyKey(key), null)
        } catch (e: ClassCastException) {
            return delegate.getFloat(key, defValue)
        }

        try {
            return java.lang.Float.parseFloat(decrypt(v)!!)
        } catch (e: NumberFormatException) {
            //FIXME::could not decrypt the number.  Maybe we are using the wrong key?
            decryptionErrorFlag = true
            Logger.doLogException(this.javaClass.name, "Warning, could not decrypt the value.", e)
        }

        return defValue
    }

    @Synchronized
    override fun getInt(key: String, defValue: Int): Int {
        val v: String?
        try {
            v = delegate.getString(encryptProxyKey(key), null)
        } catch (e: ClassCastException) {
            return delegate.getInt(key, defValue)
        }

        try {
            return if (v == null) defValue else Integer.parseInt(decrypt(v)!!)
        } catch (e: NumberFormatException) {
            //could not decrypt the number.  Maybe we are using the wrong key?
            decryptionErrorFlag = true
            Logger.doLogException(this.javaClass.name, "Warning, could not decrypt the value.", e)
        }

        return defValue
    }

    @Synchronized
    override fun getLong(key: String, defValue: Long): Long {
        val v: String?
        try {
            v = delegate.getString(encryptProxyKey(key), null)
        } catch (e: ClassCastException) {
            return delegate.getLong(key, defValue)
        }

        try {
            return if (v == null) defValue else java.lang.Long.parseLong(decrypt(v)!!)
        } catch (e: NumberFormatException) {
            //FIXME::could not decrypt the number.  Maybe we are using the wrong key?
            decryptionErrorFlag = true
            Logger.doLogException(this.javaClass.name, "Warning, could not decrypt the value.", e)
        }

        return defValue
    }

    @Synchronized
    override fun getString(key: String, defValue: String?): String? {
        val v = delegate.getString(encryptProxyKey(key), null)
        return if (v != null) decrypt(v) else defValue
    }

    override fun contains(key: String): Boolean {
        return delegate.contains(encryptProxyKey(key))
    }

    override fun registerOnSharedPreferenceChangeListener(onSharedPreferenceChangeListener: SharedPreferences.OnSharedPreferenceChangeListener) {
        delegate.registerOnSharedPreferenceChangeListener(onSharedPreferenceChangeListener)
    }

    override fun unregisterOnSharedPreferenceChangeListener(onSharedPreferenceChangeListener: SharedPreferences.OnSharedPreferenceChangeListener) {
        delegate.unregisterOnSharedPreferenceChangeListener(onSharedPreferenceChangeListener)
    }

    override fun getStringSet(key: String, defValues: Set<String>?): Set<String>? {
        throw RuntimeException("This class does not work with String Sets.")
    }

    /**
     * Helper method needed for migration, decrypts data from this SecureSharedPreferences instance
     * and puts it encrypted in target one.
     */
    fun copyAllEntriesTo(sharedPreferences: SharedPreferences) {
        val target = sharedPreferences.edit()
        delegate.all.forEach {
            val key = decrypt(it.key)
            val value = decrypt(it.value as String)
            if (key != null && value != null) {
                target.putString(key, value)
            }
        }
        target.apply()
    }

    /**
     * Helper method for removing all empty keys from a list.
     */
    fun deleteAllEmptyEntries() {
        val listOfEmptyKeys = mutableListOf<String>()
        delegate.all.forEach {
            val key = decrypt(it.key)
            val value = decrypt(it.value as String)
            if (key != null && value != null && value.isNotEmpty()) {
                listOfEmptyKeys.add(key)
            }
        }
        val editor = delegate.edit()
        listOfEmptyKeys.forEach {
            editor.remove(it).apply()
        }
    }

    fun encrypt(value: String?): String {
        try {
            // String out = OpenPgp.createInstance().encryptMailboxPwd(value, SEKRIT);
            //return out;
            val bytes = value?.toByteArray(charset(UTF8)) ?: ByteArray(0)
            val digester = MessageDigest.getInstance("SHA-256")
            digester.update(SEKRIT.first())
            val key = digester.digest()
            val spec = SecretKeySpec(key, "AES")
            val pbeCipher = Cipher.getInstance(ALGORITHM_AES)
            pbeCipher.init(Cipher.ENCRYPT_MODE, spec)
            return String(Base64.encode(pbeCipher.doFinal(bytes), Base64.NO_WRAP), charset(UTF8))
        } catch (e: Exception) {
            throw RuntimeException(e)
        }
    }

    private fun decrypt(value: String?): String? {
        try {
            // String out = OpenPgp.createInstance().decryptMailboxPwd(value, SEKRIT);
            // return out;
            val bytes = if (value != null) Base64.decode(value, Base64.NO_WRAP) else ByteArray(0)
            val digester = MessageDigest.getInstance("SHA-256")
            digester.update(SEKRIT.first())
            val key = digester.digest()
            val spec = SecretKeySpec(key, "AES")
            val pbeCipher = Cipher.getInstance(ALGORITHM_AES)
            pbeCipher.init(Cipher.DECRYPT_MODE, spec)
            return String(pbeCipher.doFinal(bytes), charset(UTF8))
        } catch (e: Exception) {
            Logger.doLogException(this.javaClass.name, "Warning, could not decrypt the value.", e)
            return value
        }
    }

    private fun generateKeyPair(context: Context, alias: String): KeyPair {

        // workaround for BouncyCastle crashing when parsing Date in RTL languages
        // we set locale temporarily to US and then go back
        val defaultLocale = Locale.getDefault()
        setLocale(Locale.US)

        val start = GregorianCalendar()
        val end = GregorianCalendar()
        end.add(Calendar.YEAR, 5)

        val keyPairGenerator = KeyPairGenerator.getInstance("RSA", keyStoreName)

        // The KeyPairGeneratorSpec object is how parameters for your key pair are passed
        // to the KeyPairGenerator.
        val algorithmParameterSpec = if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M) {
            KeyPairGeneratorSpec.Builder(context)
                    .setAlias(alias)
                    .setSubject(X500Principal("CN=ProtonMail, O=Android Authority"))
                    .setSerialNumber(BigInteger.ONE)
                    .setStartDate(start.time)
                    .setEndDate(end.time)
                    .build()
        } else {
            KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                    .setCertificateSubject(X500Principal("CN=ProtonMail, O=Android Authority"))
                    .setBlockModes(KeyProperties.BLOCK_MODE_ECB)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_PKCS1)
                    .setCertificateSerialNumber(BigInteger.ONE)
                    .setCertificateNotBefore(start.time)
                    .setCertificateNotAfter(end.time)
                    .build()
        }

        keyPairGenerator.initialize(algorithmParameterSpec)
        val keyPair = keyPairGenerator.generateKeyPair()

        setLocale(defaultLocale)

        return keyPair
    }

    private fun setLocale(locale: Locale) {
        Locale.setDefault(locale)
        val resources = context.resources
        val configuration = Configuration(resources.configuration)
        configuration.setLocale(locale)
        context.createConfigurationContext(configuration)
    }

    private fun retrieveAsymmetricKeyPair(alias: String): KeyPair? {
        val privateKey = try {
            keyStore.getKey(alias, null) as PrivateKey?
        } catch (e: UnrecoverableKeyException) {
            null
        }
        val publicKey = keyStore.getCertificate(alias)?.publicKey

        return if (privateKey != null && publicKey != null) {
            KeyPair(publicKey, privateKey)
        } else {
            null
        }
    }

    private fun encryptAsymmetric(plainText: String, key: Key): String {
        val asymmetricCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding")
        asymmetricCipher.init(Cipher.ENCRYPT_MODE, key)
        val bytes = asymmetricCipher.doFinal(plainText.toByteArray())
        return Base64.encodeToString(bytes, Base64.NO_WRAP)
    }

    /**
     * @return null when decryption key couldn't decrypt value
     */
    private fun decryptAsymmetric(cipherText: String, key: Key): String? {
        if (cipherText.isBlank()) {
            return ""
        }
        val asymmetricCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding")
        asymmetricCipher.init(Cipher.DECRYPT_MODE, key)
        val encryptedData = Base64.decode(cipherText, Base64.NO_WRAP)
        return try {
            String(asymmetricCipher.doFinal(encryptedData))
        } catch (e: Exception) {
            null
        }
    }

    ///// helper
    fun encryptProxyKey(value: String): String {
        return encrypt(value)
    }

    inner class Editor internal constructor() : SharedPreferences.Editor {
        private var delegate: SharedPreferences.Editor =
                this@SecureSharedPreferences.delegate.edit()

        @Synchronized
        override fun putBoolean(key: String, value: Boolean): Editor {
            delegate.putString(encryptProxyKey(key), encrypt(java.lang.Boolean.toString(value)))
            return this
        }

        @Synchronized
        override fun putFloat(key: String, value: Float): Editor {
            delegate.putString(encryptProxyKey(key), encrypt(java.lang.Float.toString(value)))
            return this
        }

        @Synchronized
        override fun putInt(key: String, value: Int): Editor {
            delegate.putString(encryptProxyKey(key), encrypt(Integer.toString(value)))
            return this
        }

        @Synchronized
        override fun putLong(key: String, value: Long): Editor {
            delegate.putString(encryptProxyKey(key), encrypt(java.lang.Long.toString(value)))
            return this
        }

        @Synchronized
        override fun putString(key: String, value: String?): Editor {
            delegate.putString(encryptProxyKey(key), encrypt(value))
            return this
        }

        @Synchronized
        override fun apply() {
            //to maintain compatibility with android level 7
            delegate.commit()
        }

        @Synchronized
        override fun clear(): Editor {
            delegate.clear()
            return this
        }

        @Synchronized
        override fun commit(): Boolean {
            return delegate.commit()
        }

        @Synchronized
        override fun remove(s: String): Editor {
            delegate.remove(encryptProxyKey(s))
            return this
        }

        override fun putStringSet(key: String, values: Set<String>?): android.content.SharedPreferences.Editor {
            throw RuntimeException("This class does not work with String Sets.")
        }
    }

    fun buildLongSharedPrefsListener(watchForKey: String, onKeyUpdated: Function1<Long, Unit>) =
            object : LongOnSharedPreferenceChangeListener(watchForKey) {
                override fun onKeyUpdated(newValue: Long) {
                    onKeyUpdated.invoke(newValue)
                }
            }

    abstract inner class LongOnSharedPreferenceChangeListener(private val mWatchForKey: String) :
            SharedPreferences.OnSharedPreferenceChangeListener {
        abstract fun onKeyUpdated(newValue: Long)
        override fun onSharedPreferenceChanged(sharedPreferences: SharedPreferences, key: String) {
            if (key == encryptProxyKey(mWatchForKey)) {
                onKeyUpdated(getLong(mWatchForKey, 0L))
            }
        }
    }

    companion object {
        private var decryptionErrorFlag = false

        @SuppressLint("StaticFieldLeak")
        private var prefs: SecureSharedPreferences? = null
        private val userSSPs = mutableMapOf<String, SecureSharedPreferences>()

        /**
         * Accessor to grab the preferences in a singleton.  This stores the reference in a singleton so it can be accessed repeatedly with
         * no performance penalty
         *
         * @param context     - the context used to access the preferences.
         * @param appName     - domain the shared preferences should be stored under
         * @param contextMode - Typically Context.MODE_PRIVATE
         * @return
         */
        @Synchronized
        fun getPrefs(context: Context, appName: String, contextMode: Int): SecureSharedPreferences {
            if (prefs == null) {
                prefs =
                        SecureSharedPreferences(context.applicationContext, context.applicationContext.getSharedPreferences(appName, contextMode))
            }
            return prefs!!
        }

        @Synchronized
        fun getPrefsForUser(context: Context, username: String): SecureSharedPreferences {
            return userSSPs.getOrPut(username) {
                SecureSharedPreferences(context.applicationContext, context.applicationContext.getSharedPreferences("${Base64.encodeToString(username.toByteArray(), Base64.NO_WRAP)}-SSP", Context.MODE_PRIVATE))
            }
        }
    }
}
