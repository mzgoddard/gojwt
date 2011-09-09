// jwt_test.go
// jwt unit tests

package jwt

import (
  "testing"
  "bytes"
)

func TestEncodeDecode(t *testing.T) {
  if bytes.Compare(separator, []byte{'.'}) != 0 {
    t.Fatal("Segment separator initialized should be '.'", separator)
  }
  
  claims := map[string]interface{}{
    "iss":"joe",
    "exp":1300819380.0,
    "http://example.com":true,
  }
  key := []byte{3, 35, 53, 75, 43, 15, 165, 188, 131, 126, 6, 101, 119, 123, 166, 143, 90, 179, 40, 230, 240, 84, 201, 40, 169, 15, 132, 178, 210, 80, 46, 191, 211, 251, 90, 146, 210, 6, 71, 239, 150, 138, 180, 195, 119, 98, 61, 34, 61, 46, 33, 114, 5, 46, 79, 8, 192, 205, 154, 245, 103, 208, 128, 163}
  encoded, encodeErr := Encode(
    claims,
    key,
    "HS256",
  )
  
  if encodeErr != nil {
    t.Fatal("Failed to encode: ", encodeErr)
  }
  
  var claimsDecoded map[string]interface{} = make(map[string]interface{})
  decodeErr := Decode(encoded, &claimsDecoded, key)
  if decodeErr != nil {
    t.Fatalf("Failed to decode: %s (%s)", decodeErr, encoded)
  }
  for k, v := range claims {
    if claimsDecoded[k] != v {
      t.Errorf("Claim entry '%s' failed: %s != %s", k, claimsDecoded[k], v)
    }
  }
}

func TestSecretError(t *testing.T) {
  claims := map[string]interface{}{
    "hello": "world",
  }
  wrongKey := []byte("wrong!")
  key := []byte("secret!")
  encoded, _ := Encode(claims, wrongKey, "HS256")
  
  var claimsDecoded map[string]interface{}
  decodeErr := Decode(encoded, &claimsDecoded, key)
  if _, ok := decodeErr.(*SecretError); !ok {
    t.Errorf("Did not return SecretError. Got '%s' instead.", decodeErr)
  }
}
