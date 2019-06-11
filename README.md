# 加密与解密的实现

## 前言
最近在考虑数据传输过程中的安全问题，大体了解了几种加密方式的原理，在这里使用`Java`来实现。

## 对称加密
使用方式：加密和解密使用相同的秘钥

特点：速度快

常用加密方式：AES(Advanced Encryption Standard)

具体实现可见[AESSample](./src/com/mycroft/AESSample.java)

## 非对称加密
使用方式：加密和解密使用不同的两个秘钥，把加密的秘钥公开，称为公钥，另一把用于解密，称为私钥。

特点：相对于对称加密更安全，速度相对对称加密慢

常用加密方式：RSA(三个人的姓氏首字母)

具体实现可见[RSASample](./src/com/mycroft/RSASample.java)

## 数字签名
用于发送的数据没有被篡改过

使用方式：将数据进行规则排列，使用`hash`计算生成一个不可逆的字符串，用于数据完整性的验证

特点：不可逆，速度极快

常用加密方式：MD5, SHA1

具体实现可见[MD5Sample](./src/com/mycroft/MD5Sample.java), [SHA1Sample](./src/com/mycroft/SHA1Sample.java)

## 数字证书(Certificate Authority)

是认证机构证明是真实的服务器发送的数据

已经使用另外的Demo实现了自签名的证书，后面会发布

## 参考
[对称加密和非对称加密、数字签名、数字证书的区别](https://blog.csdn.net/wenxingchen/article/details/81319905)

[MD5、对称加密、非对称加密的比较区别（干货](https://blog.csdn.net/wangpeng322/article/details/84106548)

[对称加密与非对称加密](https://zhuanlan.zhihu.com/p/34288371)
