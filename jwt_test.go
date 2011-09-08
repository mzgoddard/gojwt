// jwt_test.go
// jwt unit tests

package jwt

import (
  "testing"
  "bytes"
)

func TestEncode(t *testing.T) {
  encoded, err := Encode(
    map[string]interface{}{
      "iss":"joe",
      "exp":1300819380,
      "http://example.com/is_root":true,
    },
    string([]byte{3, 35, 53, 75, 43, 15, 165, 188, 131, 126, 6, 101, 119, 123, 166, 143, 90, 179, 40, 230, 240, 84, 201, 40, 169, 15, 132, 178, 210, 80, 46, 191, 211, 251, 90, 146, 210, 6, 71, 239, 150, 138, 180, 195, 119, 98, 61, 34, 61, 46, 33, 114, 5, 46, 79, 8, 192, 205, 154, 245, 103, 208, 128, 163}),
    "HS256",
  )
  var specExample []byte = []byte("eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk")
  if err != nil || bytes.Compare(encoded, specExample) != 0 {
    t.Errorf("Encoded JWT did not match spec example:\n%s\n%s", string(encoded), string(specExample))
  }
}
