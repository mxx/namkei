(ns namkei.handler
  (:require [compojure.core :refer [routes wrap-routes]]
            [namkei.routes.services :refer [service-routes]]
            [compojure.route :as route]
            [namkei.env :refer [defaults]]
            [mount.core :as mount]
            [namkei.middleware :as middleware]))

(mount/defstate init-app
                :start ((or (:init defaults) identity))
                :stop  ((or (:stop defaults) identity)))

(def app-routes
  (routes
    #'service-routes
    (route/not-found
      "page not found")))


(defn app [] (middleware/wrap-base #'app-routes))
