(ns namkei.funcs
  (:require [clojure.string :as string]
            [buddy.core.hash :as hash]
            [buddy.core.codecs :refer :all]
            [buddy.core.codecs.base64 :as base64]
            [buddy.core.crypto :as crypto]
            [buddy.core.nonce :as nonce]
            [buddy.core.keys :as keys]
            [clj-pgp.core :as pgp]
            [clj-pgp.generate :as pgp-gen]
            [clj-pgp.message :as pgp-msg]
            [clj-pgp.keyring :as keyring]
            [clj-pgp.signature :as pgp-sig]
            )
  (:import (org.bouncycastle.openpgp.operator.bc BcPGPDigestCalculatorProvider
                                                 BcPBESecretKeyEncryptorBuilder
                                                 BcKeyFingerprintCalculator )
           (org.bouncycastle.bcpg HashAlgorithmTags
                                  SymmetricKeyAlgorithmTags)
           (org.bouncycastle.openpgp PGPKeyPair
                                     PGPObjectFactory
                                     PGPPrivateKey
                                     PGPPublicKey
                                     PGPPublicKeyRing
                                     PGPSecretKey
                                     PGPSecretKeyRing
                                     PGPSignature
                                     PGPSignatureList
                                     PGPUtil)
           )
  (:use [clojure.java.io :only [output-stream input-stream]])
  )

(defn- salt [text]
  (-> (string/join "," [text (str (count text))]) hash/ripemd160 bytes->hex)
  )

(defn- hex-sha256 [text]
  (-> text hash/sha256 bytes->hex)
  )

(defn kasnahu [cmene namcu]
  (let [text (string/join " " [cmene namcu])]
    (-> (string/join "," [(hex-sha256 text) (salt text)]) hash/md5 bytes->hex)
    )
  )

(defn pgp-lock-key [keyPair  ^String passphrase]
  (PGPSecretKey. (pgp/private-key keyPair)
                 (pgp/public-key keyPair)
                 (.get  (BcPGPDigestCalculatorProvider.) HashAlgorithmTags/SHA1)
                 true
                 (.build  (BcPBESecretKeyEncryptorBuilder. SymmetricKeyAlgorithmTags/AES_256)
                          (.toCharArray passphrase)))
  )

(defn gen-sec-keyring [key-gen-fn passphrase]
  (let [seckey (pgp-lock-key (key-gen-fn) passphrase)]
    (PGPSecretKeyRing. (.getEncoded seckey) (BcKeyFingerprintCalculator.))
    )
  )


(defn gen-ec-pair [opt]
  (let [ec (pgp-gen/ec-keypair-generator "secp256k1")]
    (pgp-gen/generate-keypair ec opt ))
  )

(defn gen-ec-enc-pair []
  (gen-ec-pair :ec)
  )

(defn gen-ec-dsa-pair []
  (gen-ec-pair :ecdsa)
  )

(defn gen-enc-key [passphrase]
  (-> (gen-sec-keyring gen-ec-enc-pair passphrase)
      .getEncoded base64/encode String.)
  )

(defn gen-dsa-key [passphrase]
  (-> (gen-sec-keyring gen-ec-dsa-pair passphrase)
      .getEncoded base64/encode String.)
  )


(defn get-pub-key-text [keyring]
  (-> keyring pgp/decode first keyring/list-public-keys first
      pgp/encode
      base64/encode
      String.)
  )

(defn encrypt-text [text pubkey]
  (let [pk (pgp/decode-public-key pubkey)]
    (-> 
     (pgp-msg/encrypt text pk
                      :format :utf8  :cipher :aes-256
                      :compress :zip  :armor false)
     base64/encode
     String.
     ))
  )

(defn extract-private-key [keyring passphrase]
  (let [seckey (-> keyring pgp/decode first keyring/list-secret-keys first)]
    (pgp/unlock-key seckey passphrase)
    )
  )

(defn decrypt-text [text keyring passphrase]
  (let [privkey (extract-private-key keyring passphrase)]
    (pgp-msg/decrypt (base64/decode text) privkey)
    )
  )

(defn sig-text [text keyring passphrase]
  (let [privkey (extract-private-key keyring passphrase)]
    (-> (pgp-sig/sign text privkey)
        pgp/encode base64/encode
        String.)
    )
  )

(defn verify-signature [text sig-text pubkey-text]
  (let [sig (-> sig-text base64/decode pgp/decode first first)
        pubkey (pgp/decode-public-key pubkey-text)]
    (pgp-sig/verify text sig pubkey)
    )
  )

(defn selmifra [^String fe ^String fi]
  "decrypt fe with fi, fi is json string for key param, hex encoded"
  (let [key (:key fi)
        iv (:iv fi)]
    (-> (crypto/decrypt (base64/decode fe) (hex->bytes  key) (hex->bytes iv)
                        {:algorithm :aes256-gcm})
        String.
        )
    )
  )

(defn mifra [^String fa ^String fe ^String fi]
  
  (if (empty? fa)
    (let [key (:key fi)
          iv (:iv fi)]
      (-> 
       (crypto/encrypt (str->bytes fe) (hex->bytes key) (hex->bytes iv)
                       {:algorithm :aes256-gcm})
       base64/encode
       bytes->str ))
    ;;else
    (selmifra fa fi)
    ))

(defn- save-secret-key [name seckey]
  (with-open [o (output-stream name)]
    (let [kring (PGPSecretKeyRing. (.getEncoded seckey) (BcKeyFingerprintCalculator.))]
      (.encode kring o))
    ))

(defn- load-secret-key [name]
  (with-open [i (input-stream name)]
    (first  (pgp/decode i))
    ))

