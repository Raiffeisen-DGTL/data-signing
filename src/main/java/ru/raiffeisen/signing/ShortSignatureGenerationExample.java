package ru.raiffeisen.signing;

import org.apache.commons.codec.digest.DigestUtils;
import ru.CryptoPro.CAdES.CAdESSignature;
import ru.CryptoPro.CAdES.CAdESType;
import ru.CryptoPro.JCP.JCP;
import ru.CryptoPro.JCSP.JCSP;
import ru.CryptoPro.reprov.RevCheck;

import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.List;


public class ShortSignatureGenerationExample {
    static {
        // Включение онлайн-валидации сертификата
        // Для отключения валидации необходимо использовать опции CAdESSignature
        // cadesSignature.setOptions(new Options().disableCertificateValidation());
        System.setProperty("com.sun.security.enableCRLDP", "true");
        System.setProperty("com.ibm.security.enableCRLDP", "true");
        System.setProperty("ocsp.enable", "true");
        // Java-реализация алгоритмов Крипто ПРО
        Security.addProvider(new JCSP());
        Security.addProvider(new RevCheck());
    }

    public static void main(String[] args) throws Exception {
        if (args.length != 4) {
            System.err.println("Usage: ./bin/data-signing <key-file-path> <key-alias> <key-password> <data>");
            System.exit(1);
        }

        // входные данные
        var privateKeyPath = args[0];
        var keyAlias = args[1];
        var password = args[2];
        String inputData = args[3];

        KeyStore keyStore;
        try (InputStream in = new FileInputStream(privateKeyPath)) {
            keyStore = KeyStore.getInstance(JCSP.PFX_STORE_NAME, JCSP.PROVIDER_NAME);
            keyStore.load(in, password.toCharArray());
        }

        var privateKey = (PrivateKey) keyStore.getKey(keyAlias, password.toCharArray());

        // Получаем только первый сертификат из цепочки для получения короткой подписи
        var singleCertificateList = List.of((X509Certificate) keyStore.getCertificateChain(keyAlias)[0]);

        // Считаем дайджест от подписываемого json
        byte[] digest = DigestUtils.sha256(inputData);

        var signature = sign(privateKey, singleCertificateList, digest);

        System.out.println("Content-Digest: " + Base64.getEncoder().encodeToString(digest));
        System.out.println("Signature: " + signature);
    }

    private static String sign(
            PrivateKey privateKey,
            List<X509Certificate> certificateChain,
            byte[] digest
    ) throws Exception {
        // true = detached-подпись (не включает в себя подписанные данные)
        var cadesSignature = new CAdESSignature(true);
        // Отключение проверки статуса сертификата (для работы в offline-режиме)
//        cadesSignature.setOptions(new Options().disableCertificateValidation());
        cadesSignature.addSigner(
                JCSP.PROVIDER_NAME,
                JCP.GOST_DIGEST_2012_256_OID,
                JCP.GOST_PARAMS_SIG_2012_256_KEY_OID,
                privateKey,
                certificateChain,
                CAdESType.CAdES_BES,
                null,
                false
        );

        var signatureStream = new ByteArrayOutputStream();
        cadesSignature.open(signatureStream);
        cadesSignature.update(digest);
        cadesSignature.close();
        signatureStream.close();

        byte[] result = signatureStream.toByteArray();
        return Base64.getEncoder().encodeToString(result);
    }
}
