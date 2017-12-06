(ns namkei.env
  (:require [selmer.parser :as parser]
            [clojure.tools.logging :as log]
            [namkei.dev-middleware :refer [wrap-dev]]))

(def defaults
  {:init
   (fn []
     (parser/cache-off!)
     (log/info "\n-=[namkei started successfully using the development profile]=-"))
   :stop
   (fn []
     (log/info "\n-=[namkei has shut down successfully]=-"))
   :middleware wrap-dev})
