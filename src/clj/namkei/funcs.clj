(ns namkei.funcs
  (:require [clojure.string :as string]
            [buddy.core.hash :as hash]
            [buddy.core.codecs :refer :all])
  (:gen-class))

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


