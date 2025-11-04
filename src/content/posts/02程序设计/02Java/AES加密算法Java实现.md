---
date: 2001-01-01
tags:
  - Others
categories:
  - Others
title: "AES加密算法Java实现"
---

创建加解密对象
生成密钥
生成CBC模式初始化向量IV
加解密初始化
加解密



```java
import org.apache.commons.codec.binary.Base64;  
  
import java.nio.charset.Charset;  
import java.security.*;
import java.util.Scanner;  
  
import javax.crypto.*;  

  
public class Aes {  
  
  
    static final String TRANSFORMATION = "AES/CBC/PKCS5Padding";    // 指定加密算法  
    static final String ALGORITHM = "AES";  // 指定加密规则  
  
    // 生成密钥  
    public static SecretKey generateKey() throws NoSuchAlgorithmException {  
        KeyGenerator secretGenerator = KeyGenerator.getInstance(ALGORITHM);  
        SecureRandom secureRandom = new SecureRandom();  
        secretGenerator.init(256, secureRandom);  
        SecretKey secretKey = secretGenerator.generateKey();  
//        System.out.println(Base64.encodeBase64String(secretKey.getEncoded()));  
        return secretKey;  
    }  
  
    // 生成CBC模式初始化向量IV  
    public static byte[] genIV() throws NoSuchAlgorithmException {  
        SecureRandom secureRandom = new SecureRandom();  
        byte[] iv = new byte[16];  
        secureRandom.nextBytes(iv);  
//        System.out.println(Base64.encodeBase64String(iv));  
        return iv;  
    }  
  
    static Charset charset = Charset.forName("UTF-8");  
  
    // 加密  
    public static byte[] encrypt(String content, SecretKey secretKey, byte[] iv) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException { // 加密  
        return aes(content.getBytes(charset), Cipher.ENCRYPT_MODE, secretKey, iv);  
    }  
  
    // 解密  
    public static String decrypt(byte[] contentArray, SecretKey secretKey, byte[] iv) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException { // 解密  
        byte[] result = aes(contentArray, Cipher.DECRYPT_MODE, secretKey, iv);  
        return new String(result, charset);  
    }  
  
    private static byte[] aes(byte[] contentArray, int mode, SecretKey secretKey, byte[] iv)  
            throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {  
        Cipher cipher = Cipher.getInstance(TRANSFORMATION); // 创建加密对象  
        IvParameterSpec IVParamSpec = new IvParameterSpec(iv);  // 创建IV向量  
        cipher.init(mode, secretKey, IVParamSpec);  // 初始化加解密  
        byte[] result = cipher.doFinal(contentArray);   // 进行加解密  
        return result;  
    }  
  
    public static void main(String[] args) {  
        // 输入加密文本  
        Scanner s = new Scanner(System.in);  
        String content = s.next();  
  
  
        try {  
            SecretKey secretKey = generateKey();  
            byte[] iv = genIV();  
            byte[] encryptResult = encrypt(content, secretKey, iv);  
            System.out.println("encryption:" + Base64.encodeBase64String(encryptResult));  
            String decryptResult = decrypt(encryptResult, secretKey, iv);  
            System.out.println("decryption:" + decryptResult);  
        } catch (NoSuchAlgorithmException | InvalidKeyException | NoSuchPaddingException | IllegalBlockSizeException | BadPaddingException | InvalidAlgorithmParameterException e) {  
            e.printStackTrace();  
        }  
    }  
}
```

> 参考文章
> https://wmathor.com/index.php/archives/1142/
> https://bcllemon.github.io/2020-09-04/2020/java-aes-key/
> https://www.zifangsky.cn/1312.html
> 教程学习
> https://blog.csdn.net/hancoder/article/details/111464250
> https://www.bilibili.com/video/BV1tz4y197hm/?p=18&share_source=copy_web&vd_source=d1fcb62c082f9710827e86fedf96d9f0