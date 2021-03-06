(ns namkei.routes.services
  (:require [ring.util.http-response :refer :all]
            [compojure.api.sweet :refer :all]
            [namkei.funcs :as func]
            [clojure.tools.logging :as log]
            [schema.core :as s]))

(s/defschema Key {:key s/Str,
                   :iv s/Str
                  })

(defn call-func [fn & args]
  (log/debug (str fn ":") args)
  (try
    (ok  (apply fn args))
    (catch Exception e
      (log/info (.getMessage e))
      (bad-request (str  (.getMessage e)))
      ))
  )


(defapi service-routes
  {:swagger {:ui "/api-ui"
             :spec "/enigma.json"
             :data {:info {:version "1.0.0"
                           :title "ENIGMA API"
                           :description "ENIGMA Services"}}}}
  
  (context "/api/v1.0.0" []
           :tags ["lenamkei"]

           (POST "/gen-enc-key" []
                :return       String
                :body-params [termifckiku :- String]
                :description "param termifckiku: is the pass-phrases to protect generated key pair."
                :summary      "generate key pair for encryption"
                (call-func func/gen-enc-key termifckiku))

           (POST "/gen-dsa-key" []
                 :return       String
                 :body-params [termifckiku :- String]
                 :description "param termifckiku: is the pass-phrases to protect generated key pair."
                 :summary      "generate key pair for signature"
                 (call-func func/gen-dsa-key termifckiku))

           (GET "/public-key" []
                 :return       String
                 :query-params [ckiku :- String]
                 :description "param ckiku: is the generated key pair."
                 :summary      "get public key of input key pair"
                 (call-func  func/get-pub-key-text ckiku ))

           (POST "/public-key" []
                :return       String
                :query-params [ckiku :- String]
                :description "param ckiku: is the generated key pair."
                :summary      "get public key of input key pair"
                (call-func  func/get-pub-key-text ckiku ))

           (POST "/export-pgp-public-key" []
                 :return       String
                 :query-params [dsa-pub :- String, enc-pub :- String]
                 :summary      "get public key of input key pair"
                 (call-func func/export-pgp-public-key dsa-pub enc-pub))

           (POST "/encrypt-text" []
                :return       String
                :body-params [ckiku :- String, selmifra :- String]
                :description "param [ckiku]: is the generated key pair, [selmifra]: text will be encrypted"
                :summary      "encrypt text in  public key of receiver"
                (call-func func/encrypt-text selmifra ckiku))

           (POST "/decrypt-text" []
                 :return       String
                 :body-params [ckiku :- String, mifra :- String, termifckiku :- String]
                 :description "param [ckiku]: is the generated key pair, [mifra]: encryped text, [termifckiku] is ckiku's pass-phrases"
                 :summary      "decrypt text by self private key"
                 (call-func func/decrypt-text mifra ckiku termifckiku))
           
           (POST "/signature" []
                 :return       String
                 :body-params [ckiku :- String, mifra :- String, termifckiku :- String]
                 :summary      "sign mifra by ckiku"
                 (call-func func/sig-text mifra ckiku termifckiku))

           (POST "/verify" []
                 :return       String
                 :body-params [sinxa :- String, selmifra :- String, pubkey :- String]
                 :summary     "verify signature according to  public key"
                 (call-func func/verify-signature selmifra sinxa pubkey))

           (POST "/mifra" []
                 :return       String
                 :body-params [{fa :- String ""} , {fe :- String ""}  fi :- Key  ]
                 :summary     "block ciper, encrypt: fe fi decrypt: fa fi"
                 (call-func func/mifra fa fe fi))

           (POST "/encrypt" []
                 :description "AES CBC ENCRYPTOR"
                 :return       String
                 :body-params [fa :- String  ,   fe :- Key  ]
                 :summary     "aes ciper, encrypt"
                 (call-func func/encrypt-aes-cbc fa (:key fe) (:iv  fe)))

           (POST "/decrypt" []
                 :description "AES CBC DECRYPTOR"
                 :return       String
                 :body-params [fa :- String ,   fe :- Key  ]
                 :summary     "aes ciper, decrypt"
                 (call-func func/decrypt-aes-cbc fa (:key  fe) (:iv fe)))

           (GET "/kasnahu" []
                :return       String
                :query-params [cmene :- String, namcu :- String]
                :summary      "hash value for object"
                (call-func func/kasnahu cmene namcu))
           
           (POST "/kasnahu" []
                 :return      String
                 :body-params [cmene :- String, namcu :- String]
                 :summary     "hash value for object"
                 (call-func func/kasnahu cmene namcu))
           
           (GET "/kasnahu/:namcu/:cmene" []
                :return      String
                :path-params [cmene :- String, namcu :- String]
                :summary     "hash value for object"
                (call-func func/kasnahu cmene namcu))
           
           (POST "/kasnahupamoi" []
                 :return      String
                 :form-params [cmene :- String, namcu :- String]
                 :summary     "hash value for object"
                 (call-func func/kasnahu cmene namcu))
           
           ))
