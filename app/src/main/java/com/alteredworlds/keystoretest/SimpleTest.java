package com.alteredworlds.keystoretest;

import android.annotation.TargetApi;
import android.content.Context;
import android.os.Build;
import android.security.KeyPairGeneratorSpec;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;

import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.PublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Calendar;
import java.util.Date;

import javax.security.auth.x500.X500Principal;

import timber.log.Timber;

/**
 * Created by twcgilbert on 23/01/2018.
 */

public class SimpleTest {

    private static final String X500PRINCIPAL = "CN=Toms Stupid Android App,O=AlteredWorlds,C=UK";
    private static final String ANDROID_KEY_STORE = "AndroidKeyStore";
    private static final String KEY_PAIR_GENERATOR_ALGORITHM = "RSA";
    private static final String KEY_ALIAS = "whatup_dude";

    private SimpleTest() {
    }

    public static synchronized void saveKey(Context context) throws GeneralSecurityException, IOException {
        KeyStore keyStore = KeyStore.getInstance(ANDROID_KEY_STORE);
        keyStore.load(null);

        PublicKey publicKey = getPublicKey(context, keyStore, KEY_ALIAS);
        Timber.d("Retrieved public key, no probs");
    }

    private static synchronized PublicKey getPublicKey(Context context, final KeyStore keyStore, final String alias) throws
            GeneralSecurityException, IOException {
        final PublicKey retVal;
        if (doesKeyPairExist(keyStore, alias)) {
            KeyStore.PrivateKeyEntry privateKeyEntry = readKeyPair(keyStore, alias);
            retVal = privateKeyEntry.getCertificate().getPublicKey();
        } else {
            KeyPair keyPair = generateKeyPair(context, alias);
            retVal = keyPair.getPublic();
        }
        return retVal;
    }

    private static synchronized KeyPair generateKeyPair(
            final Context context,
            final String alias)
            throws GeneralSecurityException, IOException {
        Timber.d("Generate KeyPair from AndroidKeyStore");
        final Calendar start = Calendar.getInstance();
        final Calendar end = Calendar.getInstance();
        final int certValidYears = 100;
        end.add(Calendar.YEAR, certValidYears);

        // self signed cert stored in AndroidKeyStore
        final KeyPairGenerator generator = KeyPairGenerator.getInstance(
                KEY_PAIR_GENERATOR_ALGORITHM,
                ANDROID_KEY_STORE);
        generator.initialize(
                getKeyPairGeneratorSpec(
                        context,
                        alias,
                        start.getTime(),
                        end.getTime()));
        try {
            return generator.generateKeyPair();
        } catch (final IllegalStateException exception) {
            // There is an issue with AndroidKeyStore when attempting to generate keypair
            // if user doesn't have pin/passphrase setup for their lock screen.
            // Issue 177459 : AndroidKeyStore KeyPairGenerator fails to generate
            // KeyPair after toggling lock type, even without setting the encryptionRequired
            // flag on the KeyPairGeneratorSpec.
            // https://code.google.com/p/android/issues/detail?id=177459
            // The thrown exception in this case is:
            // java.lang.IllegalStateException: could not generate key in keystore
            // To avoid app crashing, re-throw as checked exception
            throw new KeyStoreException(exception);
        }
    }

    @TargetApi(Build.VERSION_CODES.M)
    private static synchronized AlgorithmParameterSpec getKeyPairGeneratorSpec(
            Context context,
            final String alias,
            Date startDate,
            Date endDate) {
        final AlgorithmParameterSpec retVal;
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            retVal = new KeyGenParameterSpec.Builder(
                    alias,
                    KeyProperties.PURPOSE_DECRYPT | KeyProperties.PURPOSE_ENCRYPT)
                    .setCertificateSubject(new X500Principal(X500PRINCIPAL))
                    .setCertificateNotBefore(startDate)
                    .setCertificateNotAfter(endDate)
                    .setCertificateSerialNumber(BigInteger.ONE)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_PKCS1)
                    .build();
        } else {
            retVal = new KeyPairGeneratorSpec.Builder(context)
                    .setAlias(alias)
                    .setSubject(new X500Principal(X500PRINCIPAL))
                    .setSerialNumber(BigInteger.ONE)
                    .setStartDate(startDate)
                    .setEndDate(endDate)
                    .build();
        }
        return retVal;
    }

    /**
     * Read KeyPair from AndroidKeyStore.
     */
    private static synchronized KeyStore.PrivateKeyEntry readKeyPair(
            final KeyStore keyStore,
            final String alias) throws GeneralSecurityException, IOException {
        Timber.v("Reading Key entry");
        final KeyStore.PrivateKeyEntry retVal;
        try {
            retVal = (KeyStore.PrivateKeyEntry) keyStore.getEntry(alias, null);
        } catch (final RuntimeException e) {
            // There is an issue in android keystore that resets keystore
            // Issue 61989:  AndroidKeyStore deleted after changing screen lock type
            // https://code.google.com/p/android/issues/detail?id=61989
            // in this case getEntry throws
            // java.lang.RuntimeException: error:0D07207B:asn1 encoding routines:ASN1_get_object:header too long
            // handle it as regular KeyStoreException...
            try {
                keyStore.deleteEntry(alias); // but first, make sure alias removed
            } catch (Exception ex) {
                Timber.e(ex, "Failed to delete Keystore entry...");
            }
            throw new KeyStoreException(e);
        }

        return retVal;
    }

    /**
     * Check if KeyPair exists on AndroidKeyStore.
     */
    private static synchronized boolean doesKeyPairExist(
            final KeyStore keyStore,
            final String alias) throws GeneralSecurityException, IOException {
        final boolean retVal;
        try {
            retVal = keyStore.containsAlias(alias);
        } catch (final NullPointerException exception) {
            // There is an issue with Android Keystore when remote service attempts
            // to access Keystore.
            // Changeset found for google source to address the related issue with
            // remote service accessing keystore :
            // https://android.googlesource.com/platform/external/sepolicy/+/0e30164b17af20f680635c7c6c522e670ecc3df3
            // The thrown exception in this case is:
            // java.lang.NullPointerException: Attempt to invoke interface method
            // 'int android.security.IKeystoreService.exist(java.lang.String, int)' on a null object reference
            // To avoid app from crashing, re-throw as checked exception
            throw new KeyStoreException(exception);
        }
        return retVal;
    }
}
