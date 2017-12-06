(ns user
  (:require 
            [mount.core :as mount]
            namkei.core))

(defn start []
  (mount/start-without #'namkei.core/repl-server))

(defn stop []
  (mount/stop-except #'namkei.core/repl-server))

(defn restart []
  (stop)
  (start))


