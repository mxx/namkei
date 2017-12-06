(ns namkei.env
  (:require [clojure.tools.logging :as log]))

(def defaults
  {:init
   (fn []
     (log/info "\n-=[namkei started successfully]=-"))
   :stop
   (fn []
     (log/info "\n-=[namkei has shut down successfully]=-"))
   :middleware identity})
