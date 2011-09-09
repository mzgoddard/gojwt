/* jwt.go
   JSON Web Tokens for Go
*/
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

var separator []byte = []byte{'.'}

type Error struct {
  message string
}

func (e *Error) String() string {
  return e.message
}

type SecretError Error

func (e *SecretError) String() string {
  return e.message
}

func base64url_encode(b []byte) []byte {
  encoded := []byte(base64.URLEncoding.EncodeToString(b))
  var equalIndex = bytes.Index(encoded, []byte{'='})
  if (equalIndex > -1) {
    encoded = encoded[:equalIndex]
  }
  return encoded
}

func base64url_decode(b []byte) ([]byte, os.Error) {
  if len(b) % 4 != 0 {
    b = append(b, bytes.Repeat([]byte{'='}, 4 - (len(b) % 4))...)
  }
  decoded, err := base64.URLEncoding.DecodeString(string(b))
  if err != nil { return nil, err }
  return decoded, nil
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
  return nil, &Error{"Algorithm not supported"}
}

func Encode(claims interface{}, key []byte, algorithm string) ([]byte, os.Error) {
  shaFunc, err := getHash(algorithm)
  if err != nil {
    return []byte{}, err
  }
  sha := hmac.New(shaFunc, key)
  
  segments := [3][]byte{}
  
  header, err := json.Marshal(
    map[string]interface{}{
      "typ": "JWT",
      "alg": algorithm,
    })
  if err != nil {
    return nil, err
  }
  segments[0] = base64url_encode(header)
  
  claimsJSON, err := json.Marshal(claims)
  if err != nil {
    return nil, err
  }
  segments[1] = base64url_encode(claimsJSON)
  
  sha.Write(bytes.Join(segments[:2], separator))
  segments[2] = base64url_encode(sha.Sum())
  
  return bytes.Join(segments[:], separator), nil
}

func Decode(encoded []byte, claims interface{}, key []byte) os.Error {
  segments := bytes.Split(encoded, separator, -1)
  
  // segments is currently slices make copies so functions like 
  // base64url_decode will not overwrite later portions
  for k, v := range segments {
    newBytes := make([]byte, len(v))
    copy(newBytes, v)
    segments[k] = newBytes
  }
  
  if len(segments) != 3 {
    return &Error{"Incorrect segment count"}
  }
  
  var header map[string]interface{} = make(map[string]interface{})
  headerBase64, err := base64url_decode(segments[0])
  if err != nil {
    return err
  }
  err = json.Unmarshal(headerBase64, &header)
  if err != nil {
    return err
  }
  
  algorithm, ok := header["alg"].(string)
  var sha hash.Hash
  if ok {
    shaFunc, err := getHash(algorithm)
    if err != nil {
      return err
    }
    sha = hmac.New(shaFunc, key)
  } else {
    return &Error{"Algorithm not supported"}
  }
  
  claimsBase64, err := base64url_decode(segments[1])
  if err != nil {
    return err
  }
  err = json.Unmarshal(claimsBase64, claims)
  if err != nil {
    return err
  }
  
  sha.Write(bytes.Join(segments[:2], separator))
  signature := base64url_encode(sha.Sum())
  if bytes.Compare(signature, segments[2]) != 0 {
    return &SecretError{"Signature verification failed"}
  }
  return nil
}
