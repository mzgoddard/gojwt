=====
GoJWT
=====

:Author: Michael "Z" Goddard
:Contact: mzgoddard@gmail.com
:Date: Friday, September 9th, 2011
:License: MIT

JSON Web Tokens for Go
 
Install
=======

``goinstall github.com/mzgoddard/gojwt``

Example
=======

.. code:: go
  func queryJwt(w http.ResponseWriter, r *http.Request) {
    fmt.Fprint(w, string(jwt.Encode(
      map[string]interface{}{
        "iss": 12345,
        "request": map[string]interface{}{
          "name": "pie",
          "description": "triangular shaped piece of baked good",
          "delicious": true,
        },
      },
      []byte("super top secret"),
      "HS256",
    )))
  }
  
