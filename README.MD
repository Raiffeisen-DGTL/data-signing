# Наложение подписи с помощью КриптоПро на языке Java

Данная инструкция рассказывает о том, как создать HTTP-заголовки, содержащие дайджест и подпись запроса в сервис RaifPay.
Подписываемыми данными выступает JSON-объект запроса, в котором отсутствует какое-либо форматирование,
а все поля отсортированы в алфавитном порядке.

## Подготовительные действия

### Java

Для работы требуется JDK 11+ и установленная environment переменная `JAVA_HOME`.

Для проверки требуется выполнить в терминале следующие команды:

* `java -version`
* `echo $JAVA_HOME`

### Сертификаты

Уже существующие в RBO сертификаты подойдут если только они были созданы с этого же компьютера. 
Если компьютер неизвестен или недоступен, то необходимо запросить новый сертификат и все последующие действия выполнять только на нем.

1. Необходимо выпустить сертификат в [настройках личного кабинета RBO](https://www.rbo.raiffeisen.ru/certificates) и затем скачать его на компьютер с установленным [КриптоПро CSP](https://www.cryptopro.ru/products/csp).
2. Импортировать скачанный сертификат в [КриптоПро CSP](https://www.cryptopro.ru/products/csp).
3. Получить публичный сертификат `AO Raiffeisenbank RootCA` (например, экспортировать из браузера с открытой страницей Райффайзен Банка).
4. Проверить, что файл имеет расширение `pem`,`der` или `cer` и переменовать его в `raif-ca-root.cer`.
5. Сделать импорт этого сертификата в JDK, который будет запускать сервис, накладывающий подпись:

```
keytool -importcert -trustcacerts -keystore $JAVA_HOME/lib/security/cacerts -storepass changeit -noprompt -alias raif-root-ca -file raif-ca-root.cer
```

### Необходимые библиотеки

1. Необходимо получить лицензию и скачать [КриптоПро CSP 5.0](https://cryptopro.ru/products/csp/downloads)
2. Скачать библиотеки [сертифицированной версии КриптоПро Java CSP и JTLS (5.0.45549-A для Java 11 и выше)](https://cryptopro.ru/products/csp/downloads#latest_csp50r3_jcsp):
   * [AdES-core.jar](https://cryptopro.ru/products/csp/downloads#latest_csp50r3_jcsp)
   * [ASN1P.jar](https://cryptopro.ru/products/csp/downloads#latest_csp50r3_jcsp)
   * [asn1rt.jar](https://cryptopro.ru/products/csp/downloads#latest_csp50r3_jcsp)
   * [CAdES.jar](https://cryptopro.ru/products/csp/downloads#latest_csp50r3_jcsp)
   * [JCP.jar](https://cryptopro.ru/products/csp/downloads#latest_csp50r3_jcsp)
   * [JCPRevCheck.jar](https://cryptopro.ru/products/csp/downloads#latest_csp50r3_jcsp)
   * [JCPRevTools.jar](https://cryptopro.ru/products/csp/downloads#latest_csp50r3_jcsp)
   * [JCSP.jar](https://cryptopro.ru/products/csp/downloads#latest_csp50r3_jcsp)
3. Скачать библиотеки криптографии `BouncyCastle` версии 1.60 для jdk15:
   * [bcpkix-jdk15on-1.60.jar](https://repo1.maven.org/maven2/org/bouncycastle/bcpkix-jdk15on/1.60/bcpkix-jdk15on-1.60.jar)
   * [bcprov-jdk15on-1.60.jar](https://repo1.maven.org/maven2/org/bouncycastle/bcprov-jdk15on/1.60/bcprov-jdk15on-1.60.jar)
4. Скачать библитеку Apache Codec последней версии:
   * [commons-codec-1.15.jar](https://repo1.maven.org/maven2/commons-codec/commons-codec/1.15/commons-codec-1.15.jar)
5. Добавить скачанные jar-файлы в classpath сервиса, который будет накладывать подпись.

Набор библиотек `КриптоПро Java CSP и JTLS` предоставляет доступ к криптографическим функциям,
расположеннным в приложении `КриптоПро CSP 5.0`, 
поэтому для наложения подписи требуются одновременно эти два комплекта ПО.

### Приватный ключ

Необходимо экспортировать приватный ключ вместе с цепочкой сертификатов в формате `PFX` из [КриптоПро CSP](https://www.cryptopro.ru/products/csp) (доступно при включении расширенного режима).
При экспорте необходимо задать пароль, защищающий файл.

Будет создан файл-контейнер приватного ключа с расширением `pfx`: `key.pfx` (имя может отличаться).

## Наложение подписи

Необходимо создать объект хранилища приватного ключа `KeyStore`:

```java
String password = "пароль заданный при экспорте";
InputStream privateKeyInputStream = new FileInputStream("key.pfx");
KeyStore keyStore = KeyStore.getInstance(JCSP.PFX_STORE_NAME, JCSP.PROVIDER_NAME);
keyStore.load(privateKeyInputStream, password.toCharArray());
```

После этого необходимо узнать поле `CN` сертификата приватного ключа, который лежит в `key.pfx`. Это можно сделать,
проверив доступный список имен в `KeyStore` и выбрать нужное (чаще всего оно совпадает с именем учетной записи RBO):

```java
keyStore.aliases() // вернет Enumeration всех доступных имен, выберем оттуда нужное
```
```java
String keyAlias = "Поле CN сертификата приватного ключа";
```

Далее, извлекаем приватный ключ и цепочку сертификатов (реализация метода `getCertificateChain` находится [здесь](src/main/java/ru/raiffeisen/signing/App.java#L99)):

```java
PrivateKey privateKey = (PrivateKey) keyStore.getKey(keyAlias, password.toCharArray());
List<X509Certificate> certificateChain = getCertificateChain(keyStore, keyAlias);
```

Считаем [дайджест](https://ru.wikipedia.org/wiki/%D0%A5%D1%8D%D1%88-%D1%81%D1%83%D0%BC%D0%BC%D0%B0) входных данных, на который будет наложена подпись:

```java
byte[] digest = DigestUtils.sha256(inputData);
```

Далее, вычисляем подпись (реализация метода `sign` находится [здесь](src/main/java/ru/raiffeisen/signing/App.java#L68))

```java
String signature = sign(privateKey, certificateChain, digest);
```

Формируем http-заголовки, которые необходимо добавлять к запросу на создание платежа:

```java
String digestHeader = "Content-Digest: " + Base64.getEncoder().encodeToString(digest);
String signatureHeader = "Signature: " + signature);
```

## Пример приложения

Данный проект включает в себя два простых приложения, демонстрирующих наложение подписи. Перед сборкой необходимо
убедиться, что на компьютере установлен JDK 11+, все требуемые библиотеки скачаны и находятся в папке lib.

FullSignatureGenerationExample.java - приложение, в котором генерируется подпись с полной цепочкой сертификатов
ShortSignatureGenerationExample.java - приложение, в котором генерируется, короткая подпись без включения всей цепочки

После этого необходимо собрать проект из командной строки командой: 

`./gradlew build`

Если какая-то из требуемых библиотек отсутствует, сборщик Gradle сообщит об этом. После успешной сборки
будет доступен дистрибутив приложения в директории:

`build/distributions/data-signing-1.0.0.zip`

Выполнив в командной строке команду:

`unzip build/distributions/data-signing-1.0.0.zip`

Мы распакуем архив в корневую директорию проекта в папку [data-signing-1.0.0](data-signing-1.0.0).
После этого можно запустить приложение:

`./data-signing-1.0.0/bin/data-signing <key-file-path> <key-alias> <key-password> <data>`

Где:
* key-file-path - путь к файлу с приватным ключом
* key-alias - поле CN в сертификате приватного ключа
* key-password - пароль указанный при экспорте приватного ключа
* data - подписываемые данные