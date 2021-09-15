CHANGELOG
=========

The format is based on `Keep a Changelog <https://keepachangelog.com/en/1.0.0/>`_,
and this project adheres to `Semantic Versioning <https://semver.org/spec/v2.0.0.html>`_.


[0.3.0]
-------

Changed
^^^^^^^

* ``AccessToken.bearer`` from ``Result<Bearer, NoneError>`` to
  ``Option<Bearer>``

Removed
^^^^^^^

* ``try_trait``. Crate is stable now.


[0.2.1]
-------

Changed
^^^^^^^

* refreshing access token now after 90% of expiration time, not after
  98%


[0.2.0]
-------

Changed
^^^^^^^

* ``periodically_refresh`` method now private and not ``async``


[0.1.1]
-------

Added
^^^^^

* ``TokenRequest.send``, ``TokenRequest.send_with_client`` methods
