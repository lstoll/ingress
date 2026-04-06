# TODO

* make reconciling better. we often drop changes, when things change we should reflect that
  * probably means diving in to the proxy stuff more, make a route be able to handle a conn
  * for http, rather than a one off listener maybe have a listener that takes conns on a channel, then can just drop it on
    * maybe this just works in general, start with the SNI listener as the exposed part. the route just gets called with a conn
  * don't match all on SNI route. actually make sure we have a handler for it
