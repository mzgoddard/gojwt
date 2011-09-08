// jwt.go
// JSON Web Tokens for Go

package jwt

import (
  "os"
  "bytes"
  "json"
  "encoding/base64"
  
  "hash"
  "crypto/hmac"
  "crypto/sha256"
  "crypto/sha512"
)

type Error struct {
  message string
}

func (e *Error) String() string {
  return e.message
}

func base64url_encode(b []byte) []byte {
  return bytes.Trim([]byte(base64.URLEncoding.EncodeToString(b)), "=")
}

func getHash(algorithm string) (func () hash.Hash, os.Error) {
  switch algorithm {
  case "HS256":
    return sha256.New, nil
  case "HS384":
    return sha512.New384, nil
  case "HS512":
    return sha512.New, nil
  }
  return nil, &Error{"Algorithm not supported."}
}

func Encode(jwt interface{}, key string, algorithm string) ([]byte, os.Error) {
  shaFunc, err := getHash(algorithm)
  if err != nil {
    return []byte{}, err
  }
  sha := hmac.New(shaFunc, []byte(key))
  
  segments := [3][]byte{}
  
  header, _ := json.Marshal(
    map[string]interface{}{
      "typ": "JWT",
      "alg": algorithm,
    })
  segments[0] = base64url_encode(header)
  
  claims, _ := json.Marshal(jwt)
  segments[1] = base64url_encode(claims)
  
  sha.Write(bytes.Join(segments[:2], []byte{'.'}))
  segments[2] = base64url_encode(sha.Sum())
  
  return bytes.Join(segments[:], []byte{'.'}), nil
}
